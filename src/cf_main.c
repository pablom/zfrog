// cf_main.c

#include <stdio.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/utsname.h>

#include "zfrog.h"

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

#ifdef CF_TASKS
    #include "cf_tasks.h"
#endif

#ifdef CF_PGSQL
    #include "cf_pgsql.h"
#endif

#ifdef CF_MYSQL
    #include "cf_mysql.h"
#endif

#ifdef CF_PYTHON
    #include "cf_python.h"
#endif

#ifdef CF_LUA
    #include "cf_lua.h"
#endif

#ifdef CF_REDIS
    #include "cf_redis.h"
#endif

volatile sig_atomic_t sig_recv;

#ifdef __sun
    const char	*__progname = "zfrog";
#else
    extern char	*__progname;
#endif

/* Global vars */
struct zfrogServer  server; /* Server global state */

/* Local static function declaration */
static void init_server_config(void);
static void	server_start(int, char *[]);
static void	server_sslstart(void);
static void	write_pid(void);


#include <stdio.h>
#include <sys/types.h>
#include <inttypes.h>

#define MAX_OF(type) \
    (((type)(~0LLU) > (type)((1LLU<<((sizeof(type)<<3)-1))-1LLU)) ? (long long unsigned int)(type)(~0LLU) : (long long unsigned int)(type)((1LLU<<((sizeof(type)<<3)-1))-1LLU))
#define MIN_OF(type) \
    (((type)(1LLU<<((sizeof(type)<<3)-1)) < (type)1) ? (long long int)((~0LLU)-((1LLU<<((sizeof(type)<<3)-1))-1LLU)) : 0LL)

static void print_min_max( void )
{
    printf("uint32_t = %lld..%llu\n", MIN_OF(uint32_t), MAX_OF(uint32_t));
    printf("int32_t = %lld..%llu\n", MIN_OF(int32_t), MAX_OF(int32_t));
    printf("uint64_t = %lld..%llu\n", MIN_OF(uint64_t), MAX_OF(uint64_t));
    printf("int64_t = %lld..%llu\n", MIN_OF(int64_t), MAX_OF(int64_t));
    printf("size_t = %lld..%llu\n", MIN_OF(size_t), MAX_OF(size_t));
    printf("ssize_t = %lld..%llu\n", MIN_OF(ssize_t), MAX_OF(ssize_t));
    printf("pid_t = %lld..%llu\n", MIN_OF(pid_t), MAX_OF(pid_t));
    printf("time_t = %lld..%llu\n", MIN_OF(time_t), MAX_OF(time_t));
    printf("intptr_t = %lld..%llu\n", MIN_OF(intptr_t), MAX_OF(intptr_t));
    printf("unsigned char = %lld..%llu\n", MIN_OF(unsigned char), MAX_OF(unsigned char));
    printf("char = %lld..%llu\n", MIN_OF(char), MAX_OF(char));
    printf("uint8_t = %lld..%llu\n", MIN_OF(uint8_t), MAX_OF(uint8_t));
    printf("int8_t = %lld..%llu\n", MIN_OF(int8_t), MAX_OF(int8_t));
    printf("uint16_t = %lld..%llu\n", MIN_OF(uint16_t), MAX_OF(uint16_t));
    printf("int16_t = %lld..%llu\n", MIN_OF(int16_t), MAX_OF(int16_t));
    printf("int = %lld..%llu\n", MIN_OF(int), MAX_OF(int));
    printf("long int = %lld..%llu\n", MIN_OF(long int), MAX_OF(long int));
    printf("long long int = %lld..%llu\n", MIN_OF(long long int), MAX_OF(long long int));
    printf("off_t = %lld..%llu\n", MIN_OF(off_t), MAX_OF(off_t));
}
/****************************************************************
 *  Print out builtin information
 ****************************************************************/
static void builtin_report( void )
{
    char tmp[256];
    int len = 0;

    /* Init buffer */
    memset(tmp, 0, sizeof(tmp));

#ifdef CF_PGSQL
    strcat(tmp, "pgsql, ");
#endif
#ifdef CF_MYSQL
    strcat(tmp, "mysql, ");
#endif
#ifdef CF_TASKS
    strcat(tmp, "tasks, ");
#endif
#ifdef CF_JSONRPC
    strcat(tmp, "jsonrpc, ");
#endif
#ifdef CF_PYTHON
    strcat(tmp, "python, ");
#endif
#ifdef CF_LUA
    strcat(tmp, "lua, ");
#endif
#ifdef CF_REDIS
    strcat(tmp, "redis, ");
#endif

    if( (len = strlen(tmp)) )
    {
        tmp[len - 2] = 0;
        cf_log(LOG_NOTICE, "%s built-in enabled", tmp);
    }
}
/****************************************************************
 *  Helper function return usage information
 ****************************************************************/
static void usage( void )
{
#ifndef CF_SINGLE_BINARY
    fprintf(stderr, "Usage: zfrog [options]\n");
#else
	fprintf(stderr, "Usage: %s [options]\n", __progname);
#endif
	fprintf(stderr, "\n");
	fprintf(stderr, "Available options:\n");

#ifndef CF_SINGLE_BINARY
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

    print_min_max();

	exit(1);
}
/****************************************************************
 *  Helper function return version number
 ****************************************************************/
static void version( void )
{
    struct utsname os_name;

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

    /* Get current OS name & information */
    uname( &os_name );

    printf("\n\nSystem information:");
    printf("\nos:\t\t%s %s %s", os_name.sysname, os_name.release, os_name.machine);
    printf("\narch_bits:\t%d", (sizeof(long) == 8) ? 64 : 32);
    printf("\ngcc_version:\t%d.%d.%d",
#ifdef __GNUC__
           __GNUC__,__GNUC_MINOR__,__GNUC_PATCHLEVEL__);
#else
            0,0,0);
#endif

    printf("\n\n");
	exit(0);
}
/****************************************************************
 *  Init server default options
 ****************************************************************/
static void init_server_config( void )
{
#ifndef CF_SINGLE_BINARY
    server.config_file = NULL;
#endif

    server.worker_count = 0;
    server.worker_rlimit_nofiles = 768;
    server.worker_set_affinity = 1;
    server.worker_max_connections = 512;
    server.worker_active_connections = 0;
    server.worker_accept_threshold = 16;

    server.socket_backlog = 5000;

    server.cpu_count = 1;
    server.nlisteners = 0;

    /* Set server main PID */
    server.pid = getpid();
    server.debug_log = 0;
    server.foreground = 0;
    server.skip_chroot = 0;
    server.root_path = NULL;    /* zFrog root path */
    server.skip_runas = 0;
    server.runas_user = NULL;

    /* Set default pid file path */
    server.pidfile = CF_PIDFILE_DEFAULT;

#ifndef CF_NO_TLS
    server.tls_cipher_list = CF_DEFAULT_CIPHER_LIST;
    server.tls_version = CF_TLS_VERSION_1_2;
    server.keymgr_root_path = NULL;
    server.keymgr_runas_user = NULL;
#endif

#ifndef CF_NO_HTTP
    server.http_body_max = HTTP_BODY_MAX_LEN;
    server.http_keepalive_time = HTTP_KEEPALIVE_TIME;
    server.http_header_max = HTTP_HEADER_MAX_LEN;
    server.http_request_limit = HTTP_REQUEST_LIMIT;
    server.http_request_ms = HTTP_REQUEST_MS;
    server.http_body_disk_offload = HTTP_BODY_DISK_OFFLOAD;
    server.http_hsts_enable = HTTP_HSTS_ENABLE;
    server.http_body_disk_path = HTTP_BODY_DISK_PATH;
    server.http_request_count = 0;
    /* Web sockets settings */
    server.websocket_timeout = 120000;
    server.websocket_maxframe = 16384;
    /* File map settings */
    server.filemap_index = NULL;
    server.filemap_ext = NULL;
#endif

#ifdef CF_TASKS
    server.task_threads = CF_MAX_TASK_THREADS;
#endif

#ifdef CF_PGSQL
    server.pgsql_conn_max = CF_PGSQL_CONN_MAX;
    server.pgsql_queue_limit = CF_PGSQL_QUEUE_LIMIT;
#endif

#ifdef CF_MYSQL
    server.mysql_conn_max = MYSQL_CONN_MAX;
#endif

#ifdef CF_REDIS
    server.redis_serv_conn_max = REDIS_CONN_MAX;
#endif

    server.worker = NULL;
    server.primary_dom = NULL;
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
        if( dom->ssl_ctx == NULL )
        {
            cf_log(LOG_NOTICE, "TLS configuration for %s not complete", dom->domain);
            return SSL_TLSEXT_ERR_NOACK;
        }

        log_debug("cf_tls_sni_cb(): Using %s CTX", sname);
		SSL_set_SSL_CTX(ssl, dom->ssl_ctx);

        if( dom->cafile != NULL ) {
			SSL_set_verify(ssl, SSL_VERIFY_PEER |SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
        }
        else {
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

        if( SSL_version(ssl) != TLS1_3_VERSION )
            c->tls_reneg++;
	}
}
#endif
/****************************************************************
 *  Helper function to accept new one connection
 ****************************************************************/
static void listener_accept(void *arg, int error)
{
    struct connection* c = NULL;
    struct listener*   l = arg;
    uint32_t		accepted = 0;

    if( error )
        cf_fatal("error on listening socket");

    if( !(l->evt.flags & CF_EVENT_READ) )
        return;

    while( server.worker_active_connections < server.worker_max_connections )
    {
        if( server.worker_accept_threshold != 0 && accepted >= server.worker_accept_threshold )
        {
            cf_worker_make_busy();
            break;
        }

        if( !cf_connection_accept(l, &c) )
            break;

        if( c == NULL )
            break;

        accepted++;
        cf_platform_event_all(c->fd, c);
    }
 }
/****************************************************************
 *  Helper function to cleanup listener structure
 ****************************************************************/
static void listener_free( struct listener *l )
{
    LIST_REMOVE(l, list);

    if( l->fd != -1 )
        close( l->fd );

    mem_free(l);
}
/****************************************************************
 *  Helper function to create listener structure
 ****************************************************************/
static struct listener* listener_alloc( int family, const char *ccb )
{
    struct listener* l = NULL;

    switch( family )
    {
    case AF_INET:
    case AF_INET6:
    case AF_UNIX:
        break;
    default:
        cf_fatal("unknown address family %d", family);
    }

    l = mem_calloc(1, sizeof(struct listener));

    server.nlisteners++;
    LIST_INSERT_HEAD(&server.listeners, l, list);

    l->fd = -1;
    l->family = family;
    l->evt.type = CF_TYPE_LISTENER;
    l->evt.handle = listener_accept;

    /* Create socket */
    if( (l->fd = socket(family, SOCK_STREAM, 0)) == -1 )
    {
        listener_free(l);
        cf_log(LOG_ERR, "socket(): %s", errno_s);
        return NULL;
    }

    if( !cf_socket_nonblock(l->fd, family != AF_UNIX) )
    {
        listener_free(l);
        cf_log(LOG_ERR, "kore_connection_nonblock(): %s", errno_s);
        return NULL;
    }

#ifdef SO_REUSEPORT
    if( !cf_socket_opt(l->fd, SOL_SOCKET, SO_REUSEADDR) )
    {
        listener_free(l);
        return NULL;
    }
#endif

    if( ccb != NULL )
    {
        if( (l->connect = cf_runtime_getcall(ccb)) == NULL )
        {
            cf_log(LOG_ERR, "no such callback: '%s'", ccb);
            listener_free(l);
            return NULL;
        }
    }
    else
        l->connect = NULL;

    return l;
}
/****************************************************************
 *  Bind server listener socket to specific address
 ****************************************************************/
int cf_server_bind( const char *ip, const char *port, const char *ccb )
{
    int	rc;
    struct listener	*l = NULL;
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

    /* Create listener structure */
    if( (l = listener_alloc(results->ai_family, ccb)) == NULL )
    {
        freeaddrinfo( results );
        return CF_RESULT_ERROR;
    }

    if( bind(l->fd, results->ai_addr, results->ai_addrlen) == -1 )
    {
        listener_free(l);
        freeaddrinfo( results );
        cf_log(LOG_ERR, "bind(): %s", errno_s);
        return CF_RESULT_ERROR;
	}

	freeaddrinfo(results);

    if( listen(l->fd, server.socket_backlog) == -1 )
    {
        listener_free( l );
        cf_log(LOG_ERR, "listen(): %s", errno_s);
        return CF_RESULT_ERROR;
	}

    if( server.foreground )
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
 *  Bind server listener socket to UNIX local socket address
 ****************************************************************/
int cf_server_bind_unix( const char *path, const char *ccb )
{
    struct listener		*l = NULL;
    struct sockaddr_un	sun;
    socklen_t socklen;
    int len = 0;

    memset(&sun, 0, sizeof(sun));
    sun.sun_family = AF_UNIX;

    len = snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", path);
    if( len == -1 || (size_t)len >= sizeof(sun.sun_path) )
    {
        cf_log(LOG_ERR, "unix socket path '%s' too long", path);
        return CF_RESULT_ERROR;
    }

#if defined(__linux__)
    if( sun.sun_path[0] == '@' )
        sun.sun_path[0] = '\0';
#endif

    socklen = sizeof(sun.sun_family) + len;

    if( (l = listener_alloc(AF_UNIX, ccb)) == NULL )
        return CF_RESULT_ERROR;

    if( bind(l->fd, (struct sockaddr *)&sun, socklen) == -1 )
    {
        cf_log(LOG_ERR, "bind: %s", errno_s);
        listener_free(l);
        return CF_RESULT_ERROR;
    }

    if( listen(l->fd, server.socket_backlog) == -1 )
    {
        cf_log(LOG_ERR, "listen(): %s", errno_s);
        listener_free(l);
        return CF_RESULT_ERROR;
    }

    if( server.foreground )
        cf_log(LOG_NOTICE, "running on %s", path);

    return CF_RESULT_OK;
}
/****************************************************************
 *  Helper function to close all listener objects
 ****************************************************************/
void cf_listener_cleanup( void )
{
    struct listener	*l = NULL;

    while( !LIST_EMPTY(&server.listeners) )
    {
        l = LIST_FIRST(&server.listeners);
        listener_free( l );
	}
}
/****************************************************************
 *  Helper function to setup signal catch
 ****************************************************************/
void cf_signal_setup( void )
{
    struct sigaction sa;

    sig_recv = 0;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = cf_signal;

    if( sigfillset(&sa.sa_mask) == -1 )
        cf_fatal("sigfillset: %s", errno_s);

    if( sigaction(SIGHUP, &sa, NULL) == -1 )
        cf_fatal("sigaction: %s", errno_s);
    if( sigaction(SIGQUIT, &sa, NULL) == -1 )
        cf_fatal("sigaction: %s", errno_s);
    if( sigaction(SIGTERM, &sa, NULL) == -1 )
        cf_fatal("sigaction: %s", errno_s);
    if( sigaction(SIGUSR1, &sa, NULL) == -1 )
        cf_fatal("sigaction: %s", errno_s);

    if( server.foreground )
    {
        if( sigaction(SIGINT, &sa, NULL) == -1 )
            cf_fatal("sigaction: %s", errno_s);
    } else {
        signal(SIGINT, SIG_IGN);
    }

    signal(SIGPIPE, SIG_IGN);
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
static void server_sslstart( void )
{
#ifndef CF_NO_TLS
    log_debug("server_sslstart()");

	SSL_library_init();
	SSL_load_error_strings();
#endif
}
/****************************************************************
 *  Helper function server start
 ****************************************************************/
static void server_start( int argc, char *argv[] )
{
    uint32_t  tmp;
    int	quit;
    struct cf_runtime_call *rcall = NULL;

    if( server.foreground == 0 )
    {
#ifdef __sun
#else
        if( daemon(1, 0) == -1 )
            cf_fatal("cannot daemon(): %s", errno_s);
#endif

#ifdef CF_SINGLE_BINARY
        if( (rcall = cf_runtime_getcall("cf_parent_daemonized")) != NULL )
        {
            cf_runtime_execute( rcall );
            mem_free(rcall);
        }
#endif
    }

    if( !server.foreground )
        write_pid();

    cf_log(LOG_NOTICE, "%s is starting up (%d)", __progname, server.pid);

    /* Log out builtin options */
    builtin_report();

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
    tmp = server.worker_max_connections;
    server.worker_max_connections = server.worker_count;

	net_init();
    cf_connection_init();
    cf_platform_event_init();
    cf_msg_parent_init();

	quit = 0;
    server.worker_max_connections = tmp;

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
            case SIGUSR1:
                cf_worker_dispatch_signal(sig_recv);
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
    cf_connection_cleanup();
    cf_domain_cleanup();
	net_cleanup();
}
/************************************************************************
 *  Helper function to write proccess pid to file
 ************************************************************************/
static void write_pid( void )
{
    int fd;
    FILE *fp = NULL;
    struct flock lock;
    struct stat sb;

    if( stat(server.pidfile, &sb) == 0 )
    {
        /* file exists, perhaps previously kepts by SIGKILL */
        if( unlink(server.pidfile) == -1 ) {
            cf_fatal("Couldn't remove old pid file '%s' (%s)", server.pidfile, errno_s);
        }
    }

    if( (fd = open(server.pidfile, O_WRONLY | O_CREAT | O_CLOEXEC, 0444)) < 0 ) {
         cf_fatal("Couldn't create pid file '%s' (%s)", server.pidfile, errno_s);
    }

    /* create a write exclusive lock for the entire file */
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

     if( fcntl(fd, F_SETLK, &lock) < 0 )
     {
         close( fd );
         cf_fatal("Couldn't set the lock for the pid file '%s' (%s)", server.pidfile, errno_s);
     }

    if( (fp = fdopen(fd, "w+")) == NULL )
    {
        close( fd );
        cf_fatal("Couldn't write pid to %s (%s)", server.pidfile, errno_s);
    }

    /* Write pid to file */
    fprintf(fp, "%d\n", (int)server.pid);
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
    struct cf_runtime_call* rcall = NULL;

    /* Init default global variables */
    init_server_config();

#ifndef CF_SINGLE_BINARY
    while( (ch = getopt(argc, argv, "c:dfhnrv")) != -1 )
    {
#else
    while ((ch = getopt(argc, argv, "dfhnrv")) != -1) {
#endif
        flags++;
        switch( ch )
        {
#ifndef CF_SINGLE_BINARY
        case 'c':
            server.config_file = optarg;
            break;
#endif

#ifdef CF_DEBUG
        case 'd':
            server.debug_log = 1;
            break;
#endif
        case 'f':
            server.foreground = 1;
            break;
        case 'h':
            usage();
            break;
        case 'n':
            server.skip_chroot = 1;
            break;
        case 'r':
            server.skip_runas = 1;
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

    LIST_INIT(&server.listeners);

    cf_log_init();

#ifdef CF_LUA
     cf_lua_init();
#endif

#ifndef CF_NO_HTTP
    //http_parent_init();
    cf_auth_init();
    cf_validator_init();
    cf_filemap_init();
#endif    

    cf_domain_init();
    cf_module_init();
    /* Start SSL server */
    server_sslstart();

#ifndef CF_SINGLE_BINARY
    if( server.config_file == NULL )
        usage();    
#endif

    cf_module_load( NULL, NULL, CF_MODULE_NATIVE );

#ifdef CF_PYTHON
     cf_python_init();
#endif

    /* Read configuration file */
    cf_parse_config();

#ifdef CF_SINGLE_BINARY
    if( (rcall = cf_runtime_getcall("cf_parent_configure")) != NULL )
    {
        cf_runtime_configure(rcall, argc, argv);
        mem_free(rcall);
    }
#endif

    /* Platform initialization */
    cf_platform_init();

#ifndef CF_NO_HTTP
    if( server.http_body_disk_offload > 0 )
    {
        if( mkdir(server.http_body_disk_path, 0700) == -1 && errno != EEXIST )
        {
            printf("can't create http_body_disk_path '%s': %s\n", server.http_body_disk_path, errno_s);
            return CF_RESULT_ERROR;
        }
    }
#endif

    /* Setup signal catch functions */
    cf_signal_setup();
    /* Start server */
    server_start(argc, argv);

    cf_log(LOG_NOTICE, "server shutting down");
    cf_worker_shutdown();

    if( (rcall = cf_runtime_getcall("cf_parent_teardown")) != NULL )
    {
        cf_runtime_execute(rcall);
        mem_free(rcall);
    }

    if( !server.foreground )
        unlink( server.pidfile );

    cf_listener_cleanup();
    cf_log(LOG_NOTICE, "goodbye cruel world");

#ifdef CF_PYTHON
    cf_python_cleanup();
#endif

    mem_cleanup();
    return 0;
}

void cf_shutdown(void)
 {
    if( server.worker != NULL ) {
        cf_msg_send(CF_MSG_PARENT, CF_MSG_SHUTDOWN, NULL, 0);
        return;
    }

    cf_fatal("cf_shutdown: called from parent");
 }
