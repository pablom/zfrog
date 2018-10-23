// cf_worker.c

#include <sys/param.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>

#ifndef CF_NO_TLS
    #include <openssl/rand.h>
#endif

#include "zfrog.h"

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

#ifdef CF_REDIS
    #include "cf_redis.h"
#endif

#ifdef CF_PGSQL
    #include "cf_pgsql.h"
#endif

#ifdef CF_ORACLE
    #include "cf_oci.h"
#endif

#ifdef CF_TASKS
    #include "cf_tasks.h"
#endif

#ifdef CF_PYTHON
    #include "cf_python.h"
#endif

#ifdef CF_LUA
    #include "cf_lua.h"
#endif

#ifdef CF_WORKER_DEBUG
    #define worker_debug(fmt, ...)		printf(fmt, ##__VA_ARGS__)
#else
    #define worker_debug(fmt, ...)
#endif

#if !defined(WAIT_ANY)
    #define WAIT_ANY		(-1)
#endif

#ifndef CF_NO_TLS
    #define WORKER_SOLO_COUNT	2
#else
    #define WORKER_SOLO_COUNT	1
#endif

#define WORKER_LOCK_TIMEOUT     500

#define WORKER(id)						\
    (struct cf_worker *)((uint8_t *)workers +	\
        (sizeof(struct cf_worker) * id))

struct wlock
{
    volatile int lock;
    pid_t        current;
};

/* Forward static function declaration */
static void worker_spawn(uint16_t, uint16_t);
static void worker_entry(struct cf_worker*);
static int	worker_trylock(void);
static void	worker_unlock(void);
static inline int worker_acceptlock_obtain(uint64_t);
static inline int worker_acceptlock_release(uint64_t);

#ifndef CF_NO_TLS
    static void worker_entropy_recv(struct cf_msg*, const void*);
    static void worker_certificate_recv(struct cf_msg*, const void*);
#endif

static uint64_t          next_lock;
static struct cf_worker* workers;       /* Array with all allocated workers structure */
static int               worker_no_lock;
static int               shm_accept_key;
static struct wlock*     accept_lock;

extern volatile sig_atomic_t sig_recv;

/****************************************************************
 *  Init workers helper function
 ****************************************************************/
void cf_worker_init(void)
{
    size_t len;
    uint16_t i = 0;
    uint16_t cpu = 0;

    /* Init no lock workers */
    worker_no_lock = 0;

    if( server.worker_count == 0 )
        server.worker_count = 1;

#ifndef CF_NO_TLS
    /* account for the key manager */
    server.worker_count += 1;
#endif

    len = sizeof(*accept_lock) + (sizeof(struct cf_worker) * server.worker_count);

	shm_accept_key = shmget(IPC_PRIVATE, len, IPC_CREAT | IPC_EXCL | 0700);

    if( shm_accept_key == -1 )
        cf_fatal("cf_worker_init(): shmget() %s", errno_s);

    if( (accept_lock = shmat(shm_accept_key, NULL, 0)) == (void *)-1 ) {
        cf_fatal("cf_worker_init(): shmat() %s", errno_s);
    }

	accept_lock->lock = 0;
	accept_lock->current = 0;

    workers = (struct cf_worker *)((uint8_t *)accept_lock + sizeof(*accept_lock));
    memset(workers, 0, sizeof(struct cf_worker) * server.worker_count);

    log_debug("cf_worker_init(): system has %d cpu's", server.cpu_count);
    log_debug("cf_worker_init(): starting %d workers", server.worker_count);

    if( server.worker_count > server.cpu_count ) {
        log_debug("cf_worker_init(): more workers than cpu's");
	}

    for( i = 0; i < server.worker_count; i++ )
    {
        worker_spawn(i, cpu++);
        if( cpu == server.cpu_count )
			cpu = 0;
	}
}
/****************************************************************
 *  Fork new one worker
 ****************************************************************/
static void worker_spawn( uint16_t id, uint16_t cpu )
{
    struct cf_worker *kw = NULL;

	kw = WORKER(id);
	kw->id = id;
	kw->cpu = cpu;
	kw->has_lock = 0;
	kw->active_hdlr = NULL;

    if( socketpair(AF_UNIX, SOCK_STREAM, 0, kw->pipe) == -1 )
		cf_fatal("socketpair(): %s", errno_s);

    if( !cf_socket_nonblock(kw->pipe[0], 0) ||
        !cf_socket_nonblock(kw->pipe[1], 0))
		cf_fatal("could not set pipe fds to nonblocking: %s", errno_s);

    /* Create a child process */
	kw->pid = fork();

    if( kw->pid == -1 )
		cf_fatal("could not spawn worker child: %s", errno_s);

    if( kw->pid == 0 ) /* Child process started */
    {
		kw->pid = getpid();
        worker_entry(kw);
		/* NOTREACHED */
	}
}
/****************************************************************
 *  Get worker pointer from array
 ****************************************************************/
struct cf_worker* cf_worker_data( uint8_t id )
{
    if( id >= server.worker_count )
		cf_fatal("id %u too large for worker count", id);

    return WORKER(id);
}
/****************************************************************
 *  Shutdown workers
 ****************************************************************/
void cf_worker_shutdown( void )
{
    struct cf_worker* kw = NULL;
    uint16_t id, done;

    cf_log(LOG_NOTICE, "waiting for workers to drain and shutdown");
    for(;;)
    {
		done = 0;
        for( id = 0; id < server.worker_count; id++ )
        {
			kw = WORKER(id);
            if( kw->pid != 0 )
                cf_worker_wait(1);
			else
				done++;
		}

        if( done == server.worker_count )
			break;
	}

    if( shmctl(shm_accept_key, IPC_RMID, NULL) == -1 ) {
        cf_log(LOG_NOTICE, "failed to deleted shm segment: %s", errno_s);
	}
}
/****************************************************************
 *  Dispatch signal to all workers
 ****************************************************************/
void cf_worker_dispatch_signal( int sig )
{
    uint16_t id;
    struct cf_worker *kw = NULL;

    for( id = 0; id < server.worker_count; id++ )
    {
		kw = WORKER(id);
        if( kill(kw->pid, sig) == -1 ) {
            log_debug("kill(%d, %d): %s", kw->pid, sig, errno_s);
		}
	}
}
/****************************************************************
 *  Worker drop priv helper function
 ****************************************************************/
void cf_worker_privdrop( const char *runas, const char *root_path )
{
    rlim_t fd;
    struct rlimit rl;
    struct passwd *pw = NULL;

    /* Must happen before chroot */
    if( server.skip_runas == 0 )
    {
        if( runas == NULL )
            cf_fatalx("no runas user given and -r not specified");

        if( (pw = getpwnam(runas)) == NULL )
        {
            cf_fatalx("cannot getpwnam(\"%s\") runas user: %s", runas, errno_s);
		}
	}

    if( server.skip_chroot == 0 )
    {
        if( root_path == NULL )
            cf_fatalx("no root directory for cf_worker_privdrop");

        if( chroot(root_path) == -1 )
            cf_fatalx("cannot chroot(\"%s\"): %s", root_path, errno_s);

        if( chdir("/") == -1 )
            cf_fatalx("cannot chdir(\"/\"): %s", errno_s);
    }
    else if( root_path )
    {
        if( chdir(root_path) == -1 )
            cf_fatalx("cannot chdir(\"%s\"): %s", root_path, errno_s);
    }

    if( getrlimit(RLIMIT_NOFILE, &rl) == -1 ) {
        cf_log(LOG_WARNING, "getrlimit(RLIMIT_NOFILE): %s", errno_s);
    }
    else
    {
        for( fd = 0; fd < rl.rlim_cur; fd++ )
        {
            if( fcntl(fd, F_GETFD, NULL) != -1 )
                server.worker_rlimit_nofiles++;
		}
	}

    rl.rlim_cur = server.worker_rlimit_nofiles;
    rl.rlim_max = server.worker_rlimit_nofiles;

    if( setrlimit(RLIMIT_NOFILE, &rl) == -1 )
    {
        cf_log(LOG_ERR, "setrlimit(RLIMIT_NOFILE, %d): %s", server.worker_rlimit_nofiles, errno_s);
	}

    if( server.skip_runas == 0 )
    {
        if( setgroups(1, &pw->pw_gid) ||
#if defined(__MACH__) || defined(NetBSD) || defined(__sun)
		    setgid(pw->pw_gid) || setegid(pw->pw_gid) ||
		    setuid(pw->pw_uid) || seteuid(pw->pw_uid))
#else
		    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
		    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
#endif
            cf_fatalx("cannot drop privileges");
	}

#if defined(__OpenBSD__)
    cf_platform_pledge();
#endif

}
/****************************************************************
 *  Worker main entry function
 ****************************************************************/
static void worker_entry( struct cf_worker *kw )
{
    char buf[16];
    int quit = 0;
    int had_lock = 0;
    int r;
    uint64_t now = 0;
    uint64_t netwait = 0;
    uint64_t timerwait = 0;
    uint64_t next_prune = 0;
    struct cf_runtime_call* rcall = NULL;

#ifndef CF_NO_TLS
    uint64_t last_seed = 0;
#endif
    /* Set worker pointer */
    server.worker = kw;

    snprintf(buf, sizeof(buf), "zfrog [wrk %d]", kw->id);

#ifndef CF_NO_TLS
    if( kw->id == CF_WORKER_KEYMGR )
        snprintf(buf, sizeof(buf), "zfrog [keymgr]");
#endif
    /* Set application title */
    cf_platform_proctitle( buf );

    if( server.worker_set_affinity == 1 )
        cf_platform_worker_setcpu( kw );

    /* Set signals catch function */
    cf_signal_setup();

#ifndef CF_NO_TLS
    if( kw->id == CF_WORKER_KEYMGR )
    {
        cf_keymgr_run();
		exit(0);
	}
#endif

    next_lock = 0;

    /* Network initialisation */
    net_init();
    cf_connection_init();
    cf_platform_event_init();
    cf_msg_worker_init();

    /* Drop privileges */
    cf_worker_privdrop( server.runas_user, server.root_path );

#ifndef CF_NO_HTTP
	http_init();
    cf_filemap_resolve_paths();
    cf_accesslog_worker_init();
#endif

    cf_timer_init();
    cf_fileref_init();

#ifndef CF_NO_TLS
    cf_domain_load_crl();
    cf_domain_keymgr_init();
#endif

#ifdef CF_PGSQL
    cf_pgsql_sys_init();
#endif

#ifdef CF_ORACLE
    cf_oci_sys_init();
#endif

#ifdef CF_TASKS
    cf_task_init();
#endif

#ifndef CF_NO_TLS
    cf_msg_register(CF_MSG_ENTROPY_RESP, worker_entropy_recv);
    cf_msg_register(CF_MSG_CERTIFICATE, worker_certificate_recv);
#endif 

#ifdef CF_REDIS
     cf_redis_sys_init();
#endif

    if( server.nlisteners == 0 )
        worker_no_lock = 1;

    cf_log(LOG_NOTICE, "worker %d (%d) started (cpu#%d)", kw->id, kw->pid, kw->cpu );

    /* Try to call */
    if( (rcall = cf_runtime_getcall("cf_worker_configure")) != NULL )
    {
        cf_runtime_execute(rcall);
        mem_free(rcall);
    }

    cf_module_onload();

    for(;;)
    {
        if (sig_recv != 0)
        {
            switch( sig_recv )
            {
			case SIGHUP:
                cf_module_reload(1);
				break;
			case SIGQUIT:
			case SIGINT:
			case SIGTERM:
				quit = 1;
				break;
			default:
				break;
			}

			sig_recv = 0;
		}

        netwait = 100;
        /* Get current time in milliseconds */
		now = cf_time_ms();

#ifndef CF_NO_TLS
        if( (now - last_seed) > CF_RESEED_TIME )
        {
            cf_msg_send(CF_WORKER_KEYMGR, CF_MSG_ENTROPY_REQ, NULL, 0);
            last_seed = now;
        }
#endif

        if( !server.worker->has_lock && next_lock <= now )
        {
            if( worker_acceptlock_obtain(now) )
            {
                if( had_lock == 0 )
                {
                    /* Enable accept new connection for listeners */
                    cf_platform_enable_accept();
                    had_lock = 1;
                }
            }
            else
                next_lock = now + WORKER_LOCK_TIMEOUT / 2;
        }

        if( !server.worker->has_lock )
        {
            if (server.worker_active_connections > 0)
            {
                if (next_lock > now)
                    netwait = next_lock - now;
            }
            else
                netwait = 10;
        }

        timerwait = cf_timer_run(now);
        if( timerwait < netwait )
            netwait = timerwait;

        r = cf_platform_event_wait(netwait);

        if( server.worker->has_lock && r > 0 )
        {
            if( netwait > 10 )
                now = cf_time_ms();

            if( worker_acceptlock_release(now) )
                next_lock = now + WORKER_LOCK_TIMEOUT;
        }

        if( !server.worker->has_lock )
        {
            if( had_lock == 1 )
            {
                had_lock = 0;
                cf_platform_disable_accept();
            }
        }

#ifndef CF_NO_HTTP
		http_process();
#endif

#ifdef CF_PYTHON
        cf_python_coro_run();
#endif
        if( next_prune <= now )
        {
            cf_connection_check_timeout(now);
            cf_connection_prune(CF_CONNECTION_PRUNE_DISCONNECT);
            next_prune = now + 500;
        }

        if( quit )
			break;
	}

    /* Clean up resources */
    cf_platform_event_cleanup();
    cf_connection_cleanup();
    cf_domain_cleanup();
    cf_module_cleanup();

#ifndef CF_NO_HTTP
	http_cleanup();
#endif
	net_cleanup();

#ifdef CF_PGSQL
    cf_pgsql_sys_cleanup();
#endif

#ifdef CF_PYTHON
    cf_python_cleanup();
#endif

#ifdef CF_LUA
    cf_lua_cleanup();
#endif

#ifdef CF_REDIS
    cf_redis_sys_cleanup();
#endif

    log_debug("worker %d shutting down", kw->id);

    /* Cleanup memory pools */
    mem_cleanup();
    exit( 0 );
}
/****************************************************************
 *  Helper function to wait worker end
 ****************************************************************/
void cf_worker_wait( int final )
{
    uint16_t  id;
    pid_t     pid;

    struct cf_worker *kw = NULL;
    int status;

    if( final )
		pid = waitpid(WAIT_ANY, &status, 0);
	else
		pid = waitpid(WAIT_ANY, &status, WNOHANG);

    if( pid == -1 ) {
        log_debug("waitpid(): %s", errno_s);
		return;
	}

    if( pid == 0 )
		return;

    for( id = 0; id < server.worker_count; id++ )
    {
		kw = WORKER(id);
        if( kw->pid != pid )
			continue;

        if( WIFEXITED(status) ) {
            cf_log(LOG_NOTICE, "worker %d (%d)-> exited: %d, status: [%d]", kw->id, pid, WEXITSTATUS(status), status);
        } else if (WIFSIGNALED(status)) {
            cf_log(LOG_NOTICE, "worker %d (%d)-> killed by signal: %d, status: [%d]", kw->id, pid, WTERMSIG(status), status);
        } else if (WIFSTOPPED(status)) {
            cf_log(LOG_NOTICE, "worker %d (%d)-> stopped by signal: %d, status: [%d]", kw->id, pid, WSTOPSIG(status), status);
        } else if (WIFCONTINUED(status)) {
            cf_log(LOG_NOTICE, "worker %d (%d)-> continued, status: [%d]", kw->id, pid, status);
        }

        if( final )
        {
			kw->pid = 0;
			break;
		}

        if( WEXITSTATUS(status) || WTERMSIG(status) || WCOREDUMP(status) )
        {
            cf_log(LOG_NOTICE, "worker %d (pid: %d) (hdlr: %s) gone", kw->id, kw->pid, (kw->active_hdlr != NULL) ? kw->active_hdlr->func :"none");

#ifndef CF_NO_TLS
            if( id == CF_WORKER_KEYMGR )
            {
                cf_log(LOG_CRIT, "keymgr gone, stopping");
				kw->pid = 0;

                if( raise(SIGTERM) != 0 ) {
                    cf_log(LOG_WARNING, "failed to raise SIGTERM signal");
				}
				break;
			}
#endif

            if( kw->pid == accept_lock->current && worker_no_lock == 0 )
				worker_unlock();

#ifndef CF_NO_HTTP
            if( kw->active_hdlr != NULL )
            {
				kw->active_hdlr->errors++;
                cf_log(LOG_NOTICE, "hdlr %s has caused %d error(s)", kw->active_hdlr->func, kw->active_hdlr->errors);
			}
#endif
            cf_log(LOG_NOTICE, "restarting worker %d", kw->id);
            cf_msg_parent_remove(kw);
            worker_spawn(kw->id, kw->cpu);
            cf_msg_parent_add(kw);
        }
        else {
            cf_log(LOG_NOTICE, "worker %d (pid: %d) signaled us (%d)", kw->id, kw->pid, status);
		}

		break;
	}
}
/****************************************************************************
 *  Calling this from your page handler will cause your current worker
 *  to give up the acceptlock (if it holds it).
 *
 *  This is particularly useful if you are about to run code that may block
 *  a bit longer then you are comfortable with. Calling this will cause
 *  the acceptlock to shuffle to another free worker which in turn makes
 *  sure your application can keep accepting requests.
 ****************************************************************************/
void cf_worker_make_busy(void)
{
    if( server.worker_count == WORKER_SOLO_COUNT || worker_no_lock == 1 )
        return;

    if( server.worker->has_lock )
    {
        worker_unlock();
        server.worker->has_lock = 0;
        next_lock = cf_time_ms() + WORKER_LOCK_TIMEOUT;
    }
}
/****************************************************************
 *  Helper function
 ****************************************************************/
static inline int worker_acceptlock_release( uint64_t now )
{
    if( server.worker_count == WORKER_SOLO_COUNT || worker_no_lock == 1 )
        return 0;

    if( server.worker->has_lock != 1 )
        return 0;

    if( server.worker_active_connections < server.worker_max_connections )
    {
#ifndef CF_NO_HTTP
        if( server.http_request_count < server.http_request_limit)
            return 0;
#else
        return 0;
#endif
    }

    worker_debug(LOG_DEBUG, "worker busy, releasing lock");
    worker_debug(LOG_DEBUG, "had lock for %lu ms", now - worker->time_locked);

	worker_unlock();
    server.worker->has_lock = 0;

    return 1;
}
/****************************************************************
 *  Helper function
 ****************************************************************/
static inline int worker_acceptlock_obtain( uint64_t now )
{
    int	rc = 0;

    if( server.worker->has_lock == 1 )
        return 1;

    if( server.worker_count == WORKER_SOLO_COUNT || worker_no_lock == 1 )
    {
        server.worker->has_lock = 1;
        return 1;
	}

    if( server.worker_active_connections >= server.worker_max_connections )
        return 0;

#ifndef CF_NO_HTTP
    if( server.http_request_count >= server.http_request_limit )
        return 0;
#endif

    if( worker_trylock() )
    {
        rc = 1;
        server.worker->has_lock = 1;
        server.worker->time_locked = now;
	}

    return rc;
}
/****************************************************************
 *  Helper function to lock
 ****************************************************************/
static int worker_trylock(void)
{
    if( !__sync_bool_compare_and_swap(&(accept_lock->lock), 0, 1) )
        return 0;

    worker_debug("wrk#%d grabbed lock (%d/%d)\n", server.worker->id, server.worker_active_connections, server.worker_max_connections);
    accept_lock->current = server.worker->pid;
    return 1;
}
/****************************************************************
 *  Helper function to unlock
 ****************************************************************/
static void worker_unlock(void)
{
	accept_lock->current = 0;

    if( !__sync_bool_compare_and_swap(&(accept_lock->lock), 1, 0) )
        cf_log(LOG_NOTICE, "worker_unlock(): wasnt locked");
}

#ifndef CF_NO_TLS
static void worker_entropy_recv( struct cf_msg *msg, const void *data )
{
    if( msg->length != 1024 ) {
        cf_log(LOG_WARNING, "short entropy response (got:%zu - wanted:1024)", msg->length);
    }

    RAND_poll();
    RAND_seed(data, msg->length);
}

static void worker_certificate_recv( struct cf_msg* msg, const void* data )
{
    struct cf_domain* dom = NULL;
    const struct cf_x509_msg* req = NULL;

    if( msg->length < sizeof(*req) )
    {
        cf_log(LOG_WARNING, "short CF_MSG_CERTIFICATE message (%zu)", msg->length);
        return;
    }

    req = (const struct cf_x509_msg*)data;
    if( msg->length != (sizeof(*req) + req->data_len) )
    {
        cf_log(LOG_WARNING, "invalid CF_MSG_CERTIFICATE payload (%zu)", msg->length);
        return;
    }

    if( req->domain_len > CF_DOMAINNAME_LEN )
    {
        cf_log(LOG_WARNING, "invalid CF_MSG_CERTIFICATE domain (%u)", req->domain_len);
        return;
    }

    dom = NULL;
    TAILQ_FOREACH(dom, &server.domains, list)
    {
        if( !strncmp(dom->domain, req->domain, req->domain_len) )
            break;
    }

    if( dom == NULL )
    {
        cf_log(LOG_WARNING,"got CF_MSG_CERTIFICATE for domain that does not exist");
        return;
    }

    /* reinitialize the domain TLS context. */
    cf_domain_tls_init(dom, req->data, req->data_len);
}

#endif

