// cf_main.c

#include <sys/types.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <sys/resource.h>

#include <stdio.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>

#include "zfrog.h"

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

#ifdef CF_PYTHON
    #include "cf_python.h"
#endif

#ifdef CF_LUA
    #include "cf_lua.h"
#endif

#include "cf_redis.h"

volatile sig_atomic_t sig_recv;

struct listener_head listeners;
uint8_t nlisteners;
pid_t cf_pid = -1;
uint16_t cpu_count = 1;
int	foreground = 0;
int	log_debug = 0;
uint8_t worker_count = 0;
int	skip_chroot = 0;
char *chroot_path = NULL;
int	skip_runas = 0;
char *runas_user = NULL;
uint32_t  cf_socket_backlog = 5000;
char *cf_pidfile = CF_PIDFILE_DEFAULT;
char *cf_tls_cipher_list = CF_DEFAULT_CIPHER_LIST;

#ifdef __sun
    const char	*__progname = "zfrog";
#else
    extern char	*__progname;
#endif


static void	cf_server_start(void);
static void	cf_write_pid(void);
static void	cf_server_sslstart(void);

/****************************************************************
 *  Helper function return usage information
 ****************************************************************/
static void usage( void )
{
#if !defined(CF_SINGLE_BINARY)
    fprintf(stderr, "Usage: zfrog [options]\n");
#else
	fprintf(stderr, "Usage: %s [options]\n", __progname);
#endif
	fprintf(stderr, "\n");
	fprintf(stderr, "Available options:\n");

#if !defined(CF_SINGLE_BINARY)
	fprintf(stderr, "\t-c\tconfiguration to use\n");
#endif

#ifdef CF_DEBUG
    fprintf(stderr, "\t-d\trun with debug on\n");
#endif

	fprintf(stderr, "\t-f\tstart in foreground\n");
	fprintf(stderr, "\t-h\tthis help text\n");
	fprintf(stderr, "\t-n\tdo not chroot\n");
	fprintf(stderr, "\t-r\tdo not drop privileges\n");
    fprintf(stderr, "\t-v\tdisplay zfrog build information\n");

	exit(1);
}
/****************************************************************
 *  Helper function return version number
 ****************************************************************/
static void version( void )
{
    printf("%d.%d.%d-%s ", CF_VERSION_MAJOR, CF_VERSION_MINOR, CF_VERSION_PATCH, CF_VERSION_STATE);

#ifndef CF_NO_TLS
    printf("tls ");
#endif

#ifndef CF_NO_HTTP
    printf("http ");
#endif

#ifdef CF_PGSQL
	printf("pgsql ");
#endif

#ifdef CF_TASKS
	printf("tasks ");
#endif

#ifdef CF_MYSQL
    printf("mysql ");
#endif

#ifdef CF_DEBUG
	printf("debug ");
#endif

#ifdef CF_SINGLE_BINARY
	printf("single ");
#endif

#ifdef CF_PYTHON
    printf("python ");
#endif

#ifdef CF_LUA
    printf("lua ");
#endif

#ifdef CF_REDIS
    printf("redis ");
#endif

	printf("\n");
	exit(0);
}

#ifndef CF_NO_TLS
int cf_tls_sni_cb( SSL *ssl, int *ad, void *arg )
{
    struct cf_domain *dom = NULL;
    const char *sname = NULL;

	sname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    log_debug("cf_tls_sni_cb(): received host %s", sname);

    if( sname != NULL && (dom = cf_domain_lookup(sname)) != NULL )
    {
        log_debug("cf_tls_sni_cb(): Using %s CTX", sname);
		SSL_set_SSL_CTX(ssl, dom->ssl_ctx);

        if( dom->cafile != NULL )
        {
			SSL_set_verify(ssl, SSL_VERIFY_PEER |SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        }
        else
        {
			SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
		}

        return SSL_TLSEXT_ERR_OK;
	}

    return SSL_TLSEXT_ERR_NOACK;
}

void cf_tls_info_callback( const SSL *ssl, int flags, int ret )
{
    struct connection *c = NULL;

    if( flags & SSL_CB_HANDSHAKE_START )
    {
        if( (c = SSL_get_app_data(ssl)) == NULL )
            cf_fatal("no SSL_get_app_data");
		c->tls_reneg++;
	}
}
#endif
/****************************************************************
 *  Bind server listener socket to specific address
 ****************************************************************/
int cf_server_bind( const char *ip, const char *port, const char *ccb )
{
    struct listener	*l = NULL;
    int on = 1;
    int	rc;
    struct addrinfo	hints, *results;

    log_debug("cf_server_bind(%s, %s)", ip, port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0;

    if( (rc = getaddrinfo(ip, port, &hints, &results)) != 0 ) {
        cf_fatal("getaddrinfo(%s): %s", ip, gai_strerror(rc));
    }

	l = mem_malloc(sizeof(struct listener));
    l->type = CF_TYPE_LISTENER;
	l->addrtype = results->ai_family;

    if( l->addrtype != AF_INET && l->addrtype != AF_INET6 )
        cf_fatal("getaddrinfo(): unknown address family %d", l->addrtype);

    if( (l->fd = socket(results->ai_family, SOCK_STREAM, 0)) == -1 )
    {
		mem_free(l);
        freeaddrinfo( results );
        cf_log(LOG_ERR, "socket(): %s", errno_s);
        return CF_RESULT_ERROR;
	}

    if( !cf_socket_nonblock(l->fd, 1) )
    {
		mem_free(l);
        freeaddrinfo( results );
        cf_log(LOG_ERR, "cf_socket_nonblock(): %s", errno_s);
        return CF_RESULT_ERROR;
	}

    if( setsockopt( l->fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on)) == -1 )
    {
        close( l->fd );
		mem_free(l);
        freeaddrinfo( results );
        cf_log(LOG_ERR, "setsockopt(SO_REUSEADDR): %s", errno_s);
        return CF_RESULT_ERROR;
	}

#ifdef SO_REUSEPORT
    if( setsockopt( l->fd, SOL_SOCKET, SO_REUSEPORT, (const char *)&on, sizeof(on)) == -1 )
    {
        close( l->fd );
        mem_free(l);
        freeaddrinfo( results );
        cf_log(LOG_ERR, "setsockopt(SO_REUSEPORT): %s", errno_s);
        return CF_RESULT_ERROR;
    }
#endif

    if( bind(l->fd, results->ai_addr, results->ai_addrlen) == -1 )
    {
		close(l->fd);
		mem_free(l);
        freeaddrinfo( results );
        cf_log(LOG_ERR, "bind(): %s to %s port %s", errno_s, ip, port);
        return CF_RESULT_ERROR;
	}

	freeaddrinfo(results);

    if( listen(l->fd, cf_socket_backlog) == -1 )
    {
		close(l->fd);
        mem_free( l );
        cf_log(LOG_ERR, "listen(): %s", errno_s);
        return CF_RESULT_ERROR;
	}

    if( ccb != NULL )
    {
        if( (l->connect = cf_runtime_getcall(ccb)) == NULL )
        {
            cf_log(LOG_ERR, "no such callback: '%s'", ccb);
			close(l->fd);
			mem_free(l);
            return CF_RESULT_ERROR;
		}
    }
    else {
		l->connect = NULL;
	}

	nlisteners++;
	LIST_INSERT_HEAD(&listeners, l, list);

    if( foreground )
    {
#ifndef CF_NO_TLS
    #ifndef CF_NO_HTTP
        cf_log(LOG_NOTICE, "running on https://%s:%s", ip, port);
    #else
        cf_log(LOG_NOTICE, "running on tls %s:%s", ip, port);
    #endif
#else
    #ifndef CF_NO_HTTP
        cf_log(LOG_NOTICE, "running on http://%s:%s", ip, port);
    #else
        cf_log(LOG_NOTICE, "running on %s:%s", ip, port);
    #endif
#endif
	}

    return CF_RESULT_OK;
}
/****************************************************************
 *  Helper function to close all listener objects
 ****************************************************************/
void cf_listener_cleanup( void )
{
    struct listener	*l = NULL;

    while( !LIST_EMPTY(&listeners) )
    {
		l = LIST_FIRST(&listeners);
		LIST_REMOVE(l, list);
		close(l->fd);
		mem_free(l);
	}
}
/****************************************************************
 *  Helper function to catch system signals
 ****************************************************************/
void cf_signal( int sig )
{
	sig_recv = sig;
}
/****************************************************************
 *  Helper function to init SSL library
 ****************************************************************/
static void cf_server_sslstart( void )
{
#ifndef CF_NO_TLS
    log_debug("cf_server_sslstart()");

	SSL_library_init();
	SSL_load_error_strings();
#endif
}
/****************************************************************
 *  Helper function server start
 ****************************************************************/
static void cf_server_start( void )
{
    uint32_t tmp;
    int	quit;
    struct cf_runtime_call *rcall = NULL;

#ifdef __sun

#else
    if( foreground == 0 && daemon(1, 1) == -1 )
        cf_fatal("cannot daemon(): %s", errno_s);
#endif

    cf_pid = getpid();

    if( !foreground )
        cf_write_pid();

    cf_log(LOG_NOTICE, "%s is starting up (%d)", __progname, cf_pid);

#ifdef CF_PGSQL
    cf_log(LOG_NOTICE, "pgsql built-in enabled");
#endif

#ifdef CF_MYSQL
    cf_log(LOG_NOTICE, "mysql built-in enabled");
#endif

#ifdef CF_TASKS
    cf_log(LOG_NOTICE, "tasks built-in enabled");
#endif

#ifdef CF_JSONRPC
    cf_log(LOG_NOTICE, "jsonrpc built-in enabled");
#endif

#ifdef CF_PYTHON
    cf_log(LOG_NOTICE, "python built-in enabled");
#endif

#ifdef CF_LUA
    cf_log(LOG_NOTICE, "lua built-in enabled");
#endif

#ifdef CF_REDIS
    cf_log(LOG_NOTICE, "redis built-in enabled");
#endif

#ifndef CF_SINGLE_BINARY
    if( (rcall = cf_runtime_getcall("cf_parent_configure")) != NULL )
    {
        cf_runtime_execute( rcall );
        mem_free( rcall );
    }
#endif

    cf_platform_proctitle("zfrog [parent]");
    cf_msg_init();
    cf_worker_init();

    /* Set worker_max_connections for connection_init() */
	tmp = worker_max_connections;
	worker_max_connections = worker_count;

	net_init();
    connection_init();
    cf_platform_event_init();
    cf_msg_parent_init();

	quit = 0;
	worker_max_connections = tmp;

    while( quit != 1 )
    {
        if( sig_recv != 0 )
        {
            switch( sig_recv )
            {
			case SIGHUP:
                cf_worker_dispatch_signal(sig_recv);
                cf_module_reload(0);
				break;
			case SIGINT:
			case SIGQUIT:
			case SIGTERM:
				quit = 1;
                cf_worker_dispatch_signal(sig_recv);
				continue;
			default:
                cf_log(LOG_NOTICE, "no action taken for signal %d", sig_recv);
				break;
			}

			sig_recv = 0;
		}

        cf_worker_wait(0);
        cf_platform_event_wait(100);
        cf_connection_prune(CF_CONNECTION_PRUNE_DISCONNECT);
	}

    cf_platform_event_cleanup();
    connection_cleanup();
    cf_domain_cleanup();
	net_cleanup();
}
/************************************************************************
 *  Helper function to write proccess pid to file
 ************************************************************************/
static void cf_write_pid( void )
{
    int fd;
    FILE *fp = NULL;
    struct flock lock;
    struct stat sb;

    if( stat(cf_pidfile, &sb) == 0 )
    {
        /* file exists, perhaps previously kepts by SIGKILL */
        if( unlink(cf_pidfile) == -1 ) {
            cf_fatal("Couldn't remove old pid file '%s' (%s)", cf_pidfile, errno_s);
        }
    }

    if( (fd = open(cf_pidfile, O_WRONLY | O_CREAT | O_CLOEXEC, 0444)) < 0 ) {
         cf_fatal("Couldn't create pid file '%s' (%s)", cf_pidfile, errno_s);
    }

    /* create a write exclusive lock for the entire file */
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

     if( fcntl(fd, F_SETLK, &lock) < 0 )
     {
         close( fd );
         cf_fatal("Couldn't set the lock for the pid file '%s' (%s)", cf_pidfile, errno_s);
     }

    if( (fp = fdopen(fd, "w+")) == NULL )
    {
        close( fd );
        cf_fatal("Couldn't write pid to %s (%s)", cf_pidfile, errno_s);
    }

    /* Write pid to file */
    fprintf(fp, "%d\n", (int)cf_pid);
    /* Close file descriptor */
    fclose( fp );
}
/************************************************************************
 *  Main entry point
 ************************************************************************/
int main( int argc, char *argv[] )
{
    int	ch;
    int flags = 0;

#if !defined(CF_SINGLE_BINARY)
    while( (ch = getopt(argc, argv, "c:dfhnrv")) != -1 )
    {
#else
    while ((ch = getopt(argc, argv, "dfhnrv")) != -1) {
#endif
        flags++;
        switch( ch )
        {
#if !defined(CF_SINGLE_BINARY)
        case 'c':
            config_file = optarg;
            break;
#endif

#ifdef CF_DEBUG
        case 'd':
            log_debug = 1;
            break;
#endif
        case 'f':
            foreground = 1;
            break;
        case 'h':
            usage();
            break;
        case 'n':
            skip_chroot = 1;
            break;
        case 'r':
            skip_runas = 1;
            break;
        case 'v':
            version();
            break;
        default:
            usage();
        }
    }

    argc -= optind;
    argv += optind;

    mem_init();

    if( argc > 0 )
        cf_fatal("did you mean to run `zfrog_cli instead?");

    cf_pid = getpid();
    nlisteners = 0;
    LIST_INIT(&listeners);

    cf_log_init();

#ifdef CF_PYTHON
     cf_python_init();
#endif

#ifdef CF_LUA
     cf_lua_init();
#endif

#ifndef CF_NO_HTTP
    cf_auth_init();
    cf_validator_init();
#endif    

    cf_domain_init();
    cf_module_init();
    /* Start SSL server */
    cf_server_sslstart();

#ifndef CF_SINGLE_BINARY
    if( config_file == NULL )
        usage();
#else
    cf_module_load( NULL, NULL, CF_MODULE_NATIVE );
#endif

    /* Read configuration file */
    cf_parse_config();
    /* Platform initialisation */
    cf_platform_init();

#ifndef CF_NO_HTTP
    cf_accesslog_init();

    if( http_body_disk_offload > 0 )
    {
        if( mkdir(http_body_disk_path, 0700) == -1 && errno != EEXIST )
        {
            printf("can't create http_body_disk_path '%s': %s\n", http_body_disk_path, errno_s);
            return CF_RESULT_ERROR;
        }
    }
#endif

    sig_recv = 0;
    signal( SIGHUP, cf_signal );
    signal( SIGQUIT, cf_signal );
    signal( SIGTERM, cf_signal );

    if( foreground )
        signal(SIGINT, cf_signal);
    else
        signal(SIGINT, SIG_IGN);

    /* Start server */
    cf_server_start();

    cf_log(LOG_NOTICE, "server shutting down");
    cf_worker_shutdown();

    if( !foreground )
        unlink(cf_pidfile);

    cf_listener_cleanup();
    cf_log(LOG_NOTICE, "goodbye cruel world");

    return 0;
}
