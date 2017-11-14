// cf_redis.c

#include "zfrog.h"
#include "cf_redis.h"

#include <ctype.h>
#include <netdb.h>

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

/* Default timeouts, 5 seconds for connecting, 15 seconds otherwise. */
#define REDIS_TIMEOUT			(15 * 1000)
#define REDIS_CONNECT_TIMEOUT	(5 * 1000)


#define REDIS_CONN_MAX      2        /* Default maximum redis connections */

#define REDIS_LIST_INSERTED     0x0100


struct redis_db
{
    char      *name;
    char      *host;
    uint16_t   port;
    uint16_t   conn_max;
    uint16_t   conn_count;

    LIST_ENTRY(redis_db) rlist;
};

struct redis_job
{
    struct cf_redis	*redis;
    TAILQ_ENTRY(redis_job)	list;
};

struct redis_wait
{
    struct cf_redis	*redis;
    TAILQ_ENTRY(redis_wait)	list;
};


/* Forward static function declaration */
static struct redis_conn * redis_conn_next(struct cf_redis*, struct redis_db*);
static void redis_conn_release(struct cf_redis*);
static void redis_conn_cleanup(struct redis_conn*);
static void redis_queue_add(struct cf_redis*);
static void redis_queue_remove(struct cf_redis*);
static void	redis_set_error(struct cf_redis *, const char *);
static void redis_read_result(struct cf_redis*);
static struct redis_conn* redis_conn_create(struct cf_redis*, struct redis_db*);
static void redis_queue_wakeup(void);

static int redis_vformat_command( char **target, const char *format, va_list ap );

static uint32_t countDigits( uint64_t v );
static size_t bulklen( size_t len );

//static int redis_tcp_socket( struct redis_conn *conn, struct redis_db *db );


/* Global variables */
static struct cf_mem_pool redis_job_pool;     /* Memory pool for Redis request job */
static struct cf_mem_pool redis_wait_pool;

static LIST_HEAD(, redis_db)     redis_db_hosts_list;  /* List of available Redis db hosts */
static TAILQ_HEAD(, redis_conn)	 redis_conn_free_queue;
static TAILQ_HEAD(, redis_wait)	 redis_wait_queue;

uint16_t redis_serv_conn_max = REDIS_CONN_MAX;

/************************************************************************
 *  Redis system initialization
 ************************************************************************/
void cf_redis_sys_init( void )
{
    /* Init list & queues */
    LIST_INIT( &redis_db_hosts_list );
    TAILQ_INIT( &redis_conn_free_queue );
    TAILQ_INIT( &redis_wait_queue );

    cf_mem_pool_init( &redis_job_pool, "redis_job_pool", sizeof(struct redis_job), 100 );
    cf_mem_pool_init( &redis_wait_pool, "redis_wait_pool", sizeof(struct redis_wait), 100);
}
/************************************************************************
 *  Redis system cleanup
 ************************************************************************/
void cf_redis_sys_cleanup( void )
{
    struct redis_conn *conn, *next;

    cf_mem_pool_cleanup( &redis_job_pool );
    cf_mem_pool_cleanup( &redis_wait_pool );

    for( conn = TAILQ_FIRST(&redis_conn_free_queue); conn != NULL; conn = next )
    {
        next = TAILQ_NEXT(conn, list);
        redis_conn_cleanup(conn);
    }
}
/************************************************************************
 *  Helper function to add new one Redis server host connection
 ************************************************************************/
int cf_redis_register( char* name, char *host, int port )
{
    struct redis_db *db = NULL;

    LIST_FOREACH(db, &redis_db_hosts_list, rlist)
    {
        if( !strcmp(db->host, host) )
            return CF_RESULT_ERROR;
    }

    db = mem_malloc(sizeof(*db));
    db->name = mem_strdup(name);
    db->host = mem_strdup(host);
    db->port = port > 0 ? port:6379;
    db->conn_count = 0;
    db->conn_max = redis_serv_conn_max;

    /* Add Redis host to our internal list */
    LIST_INSERT_HEAD( &redis_db_hosts_list, db, rlist );

    cf_log(LOG_NOTICE, "redis adding (%s) host: %s (%d)", db->name, db->host, db->port);

    return CF_RESULT_OK;
}
/************************************************************************
 *  Helper function Redis connection initialization
 ************************************************************************/
void cf_redis_init( struct cf_redis *redis )
{
    memset(redis, 0, sizeof(*redis));
    redis->state = CF_REDIS_STATE_INIT;
}
/************************************************************************
 *  Helper function Redis connection setup
 ************************************************************************/
int cf_redis_setup( struct cf_redis *redis, const char *dbname, int flags )
{
    struct redis_db* db = NULL;

    if( (flags & CF_REDIS_ASYNC) && (flags & CF_REDIS_SYNC) )
    {
        return CF_RESULT_ERROR;
    }

    if( flags & CF_REDIS_ASYNC )
    {
        if( redis->req == NULL && redis->cb == NULL )
        {
            return CF_RESULT_ERROR;
        }
    }

    redis->flags |= flags;

    LIST_FOREACH(db, &redis_db_hosts_list, rlist)
    {
        if( !strcmp(db->name, dbname) )
            break;
    }

    if( db == NULL )
    {
        return CF_RESULT_ERROR;
    }

    if( (redis->conn = redis_conn_next(redis, db)) == NULL )
        return CF_RESULT_ERROR;

    if( redis->flags & CF_REDIS_ASYNC )
    {
        redis->conn->job = cf_mem_pool_get( &redis_job_pool );
        redis->conn->job->redis = redis;
    }

    return CF_RESULT_OK;
}
/************************************************************************
 *  Helper function Redis connection setup
 ************************************************************************/
void cf_redis_cleanup( struct cf_redis *redis )
{
    log_debug("cf_redis_cleanup(%p)", redis);

    redis_queue_remove( redis );

    if( redis->error != NULL )
        mem_free( redis->error );

    if( redis->conn != NULL )
        redis_conn_release(redis);

    redis->error = NULL;
    redis->conn = NULL;

    if( redis->flags & REDIS_LIST_INSERTED )
    {
        LIST_REMOVE(redis, rlist);
        redis->flags &= ~REDIS_LIST_INSERTED;
    }
}
/************************************************************************
 *  Default Redis handler function
 ************************************************************************/
void cf_redis_handle( struct redis_conn *conn, int err )
{
    struct cf_redis	*redis = NULL;

    if( err )
    {
        redis_conn_cleanup( conn );
        return;
    }

    redis = conn->job->redis;

/*
    if( !PQconsumeInput(conn->db) )
    {
        redis->state = CF_REDIS_STATE_ERROR;
        redis->error = mem_strdup(PQerrorMessage(conn->db));
    }
    else
*/    {
        redis_read_result( redis );
    }

    if( redis->state == CF_REDIS_STATE_WAIT )
    {
#ifndef CF_NO_HTTP
        if( redis->req != NULL )
            http_request_sleep(redis->req);
#endif
        if( redis->cb != NULL )
            redis->cb(redis, redis->arg);
    }
    else
    {
#ifndef CF_NO_HTTP
        if( redis->req != NULL )
            http_request_wakeup(redis->req);
#endif
        if( redis->cb != NULL )
            redis->cb(redis, redis->arg);
    }
}
/************************************************************************
 *  Helper function to create Redis command
 ************************************************************************/
int cf_redis_format_command( char **target, const char *format, ... )
{
    va_list ap;
    int len = -1;
    va_start(ap,format);
    len = redis_vformat_command(target, format, ap);
    va_end(ap);

    /* The API says "-1" means bad result, but we now also return "-2" in some
     * cases.  Force the return value to always be -1. */
    if( len < 0 )
        len = -1;

    return len;
}
/************************************************************************
 *  Helper function to get Redis connection structure
 ************************************************************************/
static struct redis_conn* redis_conn_next( struct cf_redis *redis, struct redis_db *db )
{
    struct redis_conn *conn = NULL;
    //struct cf_redis	*rollback = NULL;

    while( 1 )
    {
        conn = NULL;

        TAILQ_FOREACH(conn, &redis_conn_free_queue, list)
        {
            if( !(conn->flags & REDIS_CONN_FREE ) )
                cf_fatal("got a redis connection that was not free?");
            if( !strcmp(conn->name, db->name) )
                break;
        }

        break;
    }

    if( conn == NULL )
    {
        if( db->conn_max != 0 && db->conn_count >= db->conn_max )
        {
            if( redis->flags & CF_REDIS_ASYNC )
                redis_queue_add( redis );
            else
                redis_set_error(redis,"no available connection");

            return NULL;
        }

        if( (conn = redis_conn_create(redis, db)) == NULL )
            return NULL;
    }

    conn->flags &= ~REDIS_CONN_FREE;
    TAILQ_REMOVE(&redis_conn_free_queue, conn, list);

    return conn;
}
/************************************************************************
 *  Helper function Redis add to wait queue
 ************************************************************************/
static void redis_queue_add( struct cf_redis *redis )
{
    struct redis_wait *rw = NULL;

#ifndef CF_NO_HTTP
    if( redis->req != NULL )
        http_request_sleep( redis->req );
#endif

    rw = cf_mem_pool_get( &redis_wait_pool );
    rw->redis = redis;
    TAILQ_INSERT_TAIL( &redis_wait_queue, rw, list );
}
/************************************************************************
 *  Helper function Redis connection cleanup
 ************************************************************************/
static void redis_conn_cleanup( struct redis_conn *conn )
{
    struct cf_redis	*redis = NULL;

    log_debug("redis_conn_cleanup(): %p", conn);

    if( conn->flags & REDIS_CONN_FREE )
        TAILQ_REMOVE( &redis_conn_free_queue, conn, list );

    if( conn->job )
    {
        redis = conn->job->redis;

#ifndef CF_NO_HTTP
        if( redis->req != NULL )
            http_request_wakeup( redis->req );
#endif

        redis->conn = NULL;

        cf_mem_pool_put( &redis_job_pool, conn->job);
        conn->job = NULL;
    }

    mem_free(conn->name);
    mem_free(conn);
}
/************************************************************************
 *  Helper function Redis set error result string
 ************************************************************************/
static void redis_set_error( struct cf_redis *redis, const char *msg )
{
    if( redis->error != NULL )
        mem_free( redis->error );

    redis->error = mem_strdup(msg);
    redis->state = CF_REDIS_STATE_ERROR;
}
/************************************************************************
 *  Helper function Redis read result
 ************************************************************************/
static void redis_read_result( struct cf_redis *redis )
{

}
/************************************************************************
 *  Helper function Redis connection release
 ************************************************************************/
static void redis_conn_release( struct cf_redis *redis )
{
    if( redis == NULL || redis->conn == NULL )
        return;

    /* Async query cleanup */
    if( redis->flags & CF_REDIS_ASYNC )
    {
        if( redis->flags & CF_REDIS_SCHEDULED )
        {
            cf_platform_disable_read( redis->conn->fd );

            //if( redis->state != CF_REDIS_STATE_DONE )
            //    redis_cancel( redis );
        }

        cf_mem_pool_put( &redis_job_pool, redis->conn->job );
    }

    redis->conn->job = NULL;
    redis->conn->flags |= REDIS_CONN_FREE;
    TAILQ_INSERT_TAIL( &redis_conn_free_queue, redis->conn, list );

    redis->conn = NULL;
    redis->state = CF_REDIS_STATE_COMPLETE;

    if( redis->cb != NULL )
        redis->cb(redis, redis->arg);

    redis_queue_wakeup();
}
/************************************************************************
 *  Helper function create Redis TCP/IP socket
 ************************************************************************/
#ifdef MMM
static int redis_tcp_socket( struct redis_conn *conn, struct redis_db *db )
{
    int rv = -1;
    int fd;
    struct addrinfo hints;
    struct addrinfo *servinfo = NULL;
    struct addrinfo *p = NULL;
    char _port[6];

    /* Init structure */
    memset( &hints, 0, sizeof(hints) );

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(_port, 6, "%d", db->port);

    /* Try with IPv6 if no IPv4 address was found. We do it in this order since
     * in a Redis client you can't afford to test if you have IPv6 connectivity
     * as this would add latency to every connect. Otherwise a more sensible
     * route could be: Use IPv6 if both addresses are available and there is IPv6
     * connectivity. */
    if( (rv = getaddrinfo( db->host, _port, &hints, &servinfo)) != 0 )
    {
        hints.ai_family = AF_INET6;
        if( (rv = getaddrinfo( db->host, _port, &hints, &servinfo)) != 0 )
        {
            return CF_RESULT_ERROR;
        }
    }

    for( p = servinfo; p != NULL; p = p->ai_next )
    {
        if( (fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1 )
            continue;
    }

    if( fd != -1 )
    {
        conn->fd = fd;
        return CF_RESULT_OK;
    }

    return CF_RESULT_OK;
}
#endif
/************************************************************************
 *  Helper function Redis connection create
 ************************************************************************/
static struct redis_conn* redis_conn_create( struct cf_redis *redis, struct redis_db *db )
{
    struct redis_conn *rd_conn = NULL;
    struct connection *conn = NULL;
    int fd = -1;

    if( db == NULL || db->host == NULL )
        cf_fatal("redis_conn_create: no connection host");

    /* Create socket */
    if( (fd = cf_tcp_socket( db->host, SOCK_STREAM)) != -1 )
    {
        /* Set it to non blocking */
        if( !cf_connection_nonblock(fd, 1) )
        {
            close( fd );
            return NULL;
        }

        conn = cf_connection_new(NULL);

        /* Prepare our connection. */
        conn->addrtype = AF_INET;
        conn->addr.ipv4.sin_family = AF_INET;
        conn->addr.ipv4.sin_port = htons( db->port);
        conn->addr.ipv4.sin_addr.s_addr = inet_addr( db->host );

        /* Set the file descriptor for Redis connection */
        conn->fd = fd;

        /* Default write/read callbacks for Redis */
        conn->read = net_read;
        conn->write = net_write;

        /* Connection type */
        conn->proto = CONN_PROTO_REDIS;
        conn->state = CONN_STATE_ESTABLISHED;

        /* Redis server idle timer is set first to connection timeout */
        conn->idle_timer.length = REDIS_CONNECT_TIMEOUT;
        //conn->handle = redis_handle_connect;
        /* Set the disconnect method for both connections */
        //conn->disconnect = redis_handle_disconnect;

        /* Queue write events for the backend connection for now */
        cf_platform_schedule_write(conn->fd, conn);
    }

#ifdef MMM
    /* Increment connection count */
    db->conn_count++;

    conn = mem_malloc(sizeof(*conn));
    conn->job = NULL;
    conn->flags = REDIS_CONN_FREE;
    conn->type = CF_TYPE_REDIS;
    conn->name = mem_strdup(db->name);
    TAILQ_INSERT_TAIL( &redis_conn_free_queue, conn, list);

    log_debug("redis_conn_create(): %p", conn);
#endif

    return rd_conn;
}
/************************************************************************
 *  Helper function to wakeup Redis connections
 ************************************************************************/
static void redis_queue_wakeup( void )
{
    struct redis_wait *rw, *next;

    for( rw = TAILQ_FIRST( &redis_wait_queue ); rw != NULL; rw = next )
    {
        next = TAILQ_NEXT(rw, list);

#ifndef CF_NO_HTTP
        if( rw->redis->req != NULL )
        {
            if( rw->redis->req->flags & HTTP_REQUEST_DELETE )
            {
                TAILQ_REMOVE( &redis_wait_queue, rw, list );
                cf_mem_pool_put( &redis_wait_pool, rw );
                continue;
            }

            http_request_wakeup(rw->redis->req);
        }
#endif

        if( rw->redis->cb != NULL )
            rw->redis->cb(rw->redis, rw->redis->arg);

        TAILQ_REMOVE( &redis_wait_queue, rw, list );
        cf_mem_pool_put( &redis_wait_pool, rw );
    }
}
/************************************************************************
 *  Helper function to remove Redis structure from internal queue
 ************************************************************************/
static void redis_queue_remove( struct cf_redis *redis )
{
    struct redis_wait *rw, *next;

    for( rw = TAILQ_FIRST( &redis_wait_queue ); rw != NULL; rw = next)
    {
        next = TAILQ_NEXT(rw, list);
        if( rw->redis != redis )
            continue;

        TAILQ_REMOVE( &redis_wait_queue, rw, list );
        cf_mem_pool_put( &redis_wait_pool, rw);
        return;
    }
}
/****************************************************************************
 *  Return the number of digits of 'v' when converted to string in radix 10
 ***************************************************************************/
static uint32_t countDigits( uint64_t v )
{
    uint32_t result = 1;

    for(;;)
    {
        if( v < 10 ) return result;
        if( v < 100 ) return result + 1;
        if( v < 1000 ) return result + 2;
        if( v < 10000 ) return result + 3;
        v /= 10000U;
        result += 4;
    }
}
/*************************************************************************
*  Helper that calculates the bulk length given a certain string length
*************************************************************************/
static size_t bulklen( size_t len )
{
    return 1 + countDigits(len) + 2 + len + 2;
}
/************************************************************************
*  Helper function create Redis format command
************************************************************************/
static int redis_vformat_command( char **target, const char *format, va_list ap )
{
    int error_type = 0; /* 0 = no error; -1 = memory error; -2 = format error */
    int touched = 0;    /* was the current argument touched? */
    int argc = 0;       /* Total number of arguments */

    const char *c = format;

    struct cf_buf curarg; /* Temporary buffer for current argument */
    struct cf_buf args;   /* Temporary buffer for all arguments in final commands */

    /* Init buffer for current argument */
    cf_buf_init( &curarg, 256);
    /* Init buffer for all incoming arguments */
    cf_buf_init( &args, 256);

    /* Init response cmd */
    *target = NULL;

    while( *c != '\0' && error_type == 0 )
    {
        if( *c != '%' || c[1] == '\0' )
        {
            if( *c == ' ' )
            {
                if( touched )
                {
                    argc++; /* Increment total number of arguments */
                    /* Add current argument to args buffer */
                    cf_buf_appendf( &args, "$%zu\r\n", curarg.offset );
                    cf_buf_append( &args, curarg.data, curarg.offset );
                    cf_buf_append( &args, "\r\n", 2 );
                    /* Reset current argument buffer */
                    cf_buf_reset( &curarg );
                }
            }
            else
            {
                cf_buf_append( &curarg, c, 1);
                touched = 1;
            }
        }
        else
        {
            char *arg = NULL;
            size_t size = 0;

            switch( c[1] )
            {
            case 's':
                arg = va_arg(ap,char*);
                size = strlen(arg);
                if( size > 0 )
                    cf_buf_append( &curarg, arg, size );
                break;
            case 'b':
                arg = va_arg(ap,char*);
                size = va_arg(ap,size_t);
                if( size > 0 )
                    cf_buf_append( &curarg, arg, size );
                break;
            case '%':
                cf_buf_append( &curarg, "%", 1 );
                break;
            default:
                /* Try to detect printf format */
                {
                    static const char intfmts[] = "diouxX";
                    static const char flags[] = "#0-+ ";
                    char _format[16];
                    const char *_p = c+1;
                    size_t _l = 0;
                    va_list _cpy;

                    /* Flags */
                    while( *_p != '\0' && strchr(flags,*_p) != NULL ) _p++;

                    /* Field width */
                    while( *_p != '\0' && isdigit(*_p) ) _p++;

                    /* Precision */
                    if( *_p == '.' )
                    {
                        _p++;
                        while (*_p != '\0' && isdigit(*_p)) _p++;
                    }

                    /* Copy va_list before consuming with va_arg */
                    va_copy(_cpy,ap);

                    /* Integer conversion (without modifiers) */
                    if( strchr(intfmts,*_p) != NULL )
                        va_arg(ap,int);
                    /* Double conversion (without modifiers) */
                    else if( strchr("eEfFgGaA",*_p) != NULL )
                        va_arg(ap,double);
                    else if( _p[0] == 'h' && _p[1] == 'h' ) /* Size: char */
                    {
                        _p += 2;

                        if( *_p != '\0' && strchr(intfmts,*_p) != NULL )
                            va_arg(ap,int); /* char gets promoted to int */
                        else
                            error_type = -2;
                    }
                    else if( _p[0] == 'h' ) /* Size: short */
                    {
                        _p += 1;
                        if( *_p != '\0' && strchr(intfmts,*_p) != NULL )
                            va_arg(ap,int); /* short gets promoted to int */
                        else
                            error_type = -2;
                    }
                    else if( _p[0] == 'l' && _p[1] == 'l' ) /* Size: long long */
                    {
                        _p += 2;
                        if( *_p != '\0' && strchr(intfmts,*_p) != NULL )
                            va_arg(ap,long long);
                        else
                            error_type = -2;
                    }
                    else if( _p[0] == 'l' ) /* Size: long */
                    {
                        _p += 1;
                        if( *_p != '\0' && strchr(intfmts,*_p) != NULL )
                            va_arg(ap,long);
                        else
                            error_type = -2;
                    }

                    if( error_type == 0 )
                    {
                        _l = (_p + 1)-c;
                        if( _l < sizeof(_format) - 2 )
                        {
                            memcpy(_format,c,_l);
                            _format[_l] = '\0';
                            cf_buf_appendv( &curarg,_format,_cpy );
                            /* Update current position (note: outer blocks
                             * increment c twice so compensate here) */
                            c = _p - 1;
                        }
                    }

                    va_end(_cpy);
                    break;
                }
            }

            touched = 1;
            c++;
        }

        c++;
    }

    if( error_type == 0 && ( argc > 0 || touched ) )
    {
        int pos = 0;
        char *cmd = NULL;   /* final command */
        int totlen = args.offset; /* Set current data length */

        /* Add the last argument if needed */
        if( touched )
        {
            /* Increment total length */
            totlen += bulklen( curarg.offset );
            argc++; /* Increment total number of arguments */

            /* Add current argument to args buffer */
            cf_buf_appendf( &args, "$%zu\r\n", curarg.offset );
            cf_buf_append( &args, curarg.data, curarg.offset );
            cf_buf_append( &args, "\r\n", 2 );
        }

        /* Add bytes needed to hold multi bulk count */
        totlen += 1 + countDigits(argc) + 2;
        /* Build the command at protocol level */
        cmd = mem_malloc( totlen + 1 );
        pos = sprintf(cmd,"*%d\r\n",argc);
        /* Set data to final command */
        memcpy( cmd + pos, args.data, args.offset );
        cmd[totlen] = '\0'; /* Set end of string */

        /* Set final command */
        *target = cmd;

        /* Set return code as total cmd length */
        error_type = totlen;
    }

    /* Clean up temporary buffers */
    cf_buf_cleanup( &curarg );
    cf_buf_cleanup( &args );

    return error_type;
}
/************************************************************************
 *  Helper function to bind PGSQL connection to HTTP request
 ************************************************************************/
#ifndef CF_NO_HTTP
void cf_redis_bind_request( struct cf_redis *redis, struct http_request *req )
{
    if( redis->req != NULL || redis->cb != NULL )
        cf_fatal("cf_redis_bind_request: already bound");

    redis->req = req;
    //redis->flags |= PGSQL_LIST_INSERTED;

    //LIST_INSERT_HEAD(&(req->pgsqls), pgsql, rlist);
}
#endif

void cf_redis_logerror( struct cf_redis *redis )
{
    //cf_log(LOG_NOTICE, "pgsql error: %s", (pgsql->error) ? pgsql->error : "unknown");
}

void cf_redis_continue( struct cf_redis *redis )
{

}

void cf_redis_bind_callback( struct cf_redis *redis, void (*cb)(struct cf_redis *, void *), void *arg )
{
    if( redis->req != NULL )
        cf_fatal("cf_redis_bind_callback: already bound");

    if( redis->cb != NULL )
        cf_fatal("cf_redis_bind_callback: already bound");

    redis->cb = cb;
    redis->arg = arg;
}


