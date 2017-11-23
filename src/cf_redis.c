// cf_redis.c

#include <stdbool.h>
#include <netdb.h>
#include <ctype.h>

#include "zfrog.h"
#include "cf_redis.h"

#include <stddef.h>

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif


#define REDIS_CONN_MAX          2   /* Default maximum redis connections */

/* Default timeouts, 5 seconds for connecting, 15 seconds otherwise. */
#define REDIS_TIMEOUT			(15 * 1000)
#define REDIS_CONNECT_TIMEOUT	(5 * 1000)


#define REDIS_LIST_INSERTED     0x0100

/* Redis host structure description */
struct redis_db
{
    char      *name;
    char      *host;
    uint16_t   port;
    uint16_t   conn_max;
    uint16_t   conn_count;

    LIST_ENTRY(redis_db) rlist;
};

/* Redis connection structure description */
struct redis_conn
{
    struct connection  *c;  /* Link to physical (socket) connection */
    struct redis_db    *db; /* Link to Redis db host description */

    //uint8_t  state;
    uint8_t  flags;

    uint8_t	 type;

    struct redis_job   *job;
    TAILQ_ENTRY(redis_conn) list;
};



/*  Redis job structure */
struct redis_job
{
    struct cf_redis	*redis;
    TAILQ_ENTRY(redis_job)	list;
};

/*  Redis wait structure */
struct redis_wait
{
    struct cf_redis	*redis;
    struct redis_db *db;        /* Link to Redis db host */
    TAILQ_ENTRY(redis_wait)	list;
};


/* Forward static function declaration */
static struct redis_conn* redis_conn_next(struct cf_redis*, struct redis_db*);
static void	redis_set_error(struct cf_redis*, const char*);
static void redis_schedule(struct cf_redis*);
static void redis_queue_add(struct cf_redis*, struct redis_db*);
static void redis_queue_remove(struct cf_redis*);
static void redis_queue_wakeup(uint8_t, struct redis_db*);
static struct redis_conn* redis_conn_create(struct cf_redis*, struct redis_db*);
static void redis_conn_release(struct cf_redis*);
static void redis_conn_cleanup(struct redis_conn*);
static void redis_read_result(struct cf_redis*);
static void redis_cancel(struct cf_redis*);
static int redis_handle_connect(struct connection*);
static int redis_recv(struct netbuf*);
static void redis_handle_disconnect(struct connection *, int);
static int redis_handle(struct connection*);
static uint32_t countDigits(uint64_t);
static size_t bulklen(size_t);
static int redis_vformat_command( char**, const char*, va_list);

static int redis_get_reply(struct cf_redis_reply**, uint8_t*, size_t);
static int redis_process_line_item(struct cf_redis_reply**, uint8_t*, size_t, uint8_t);
static int redis_process_bulk_item(struct cf_redis_reply**, uint8_t*, size_t);
static int redis_process_multi_bulk_item(struct cf_redis_reply**, uint8_t*, size_t);
static void redis_free_reply(struct cf_redis*);

#define redisConnection(_r) (_r->conn->c)
#define redisSocket(_r) (_r->conn->c->fd)

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
    redis->state = CF_REDIS_STATE_CONNECTING;
}
/************************************************************************
 *  Helper function log out Redis error
 ************************************************************************/
void cf_redis_logerror( struct cf_redis *redis )
{
    cf_log(LOG_NOTICE, "redis error: %s", (redis->error) ? redis->error : "unknown");
}
/************************************************************************
 *  Set callback function to notify with Redis status change
 ************************************************************************/
void cf_redis_bind_callback( struct cf_redis *redis, void (*cb)(struct cf_redis *, void *), void *arg )
{
    if( redis->arg != NULL || redis->cb != NULL )
        cf_fatal("cf_redis_bind_callback: already bound");

    redis->cb = cb;
    redis->arg = arg;
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
 *  Helper function Redis connection setup
 ************************************************************************/
int cf_redis_setup( struct cf_redis *redis, const char *dbname, int flags )
{
    struct redis_db* db = NULL;

    /* Check first that current redis state is not error */
    if( redis->state == CF_REDIS_STATE_ERROR )
    {
        redis_set_error(redis, "Couldn't connect to Redis server");
        return CF_RESULT_ERROR;
    }

    /* Check that connection flags is invalid */
    if( (flags & CF_REDIS_ASYNC) && (flags & CF_REDIS_SYNC) )
    {
        redis_set_error(redis, "invalid query init parameters");
        return CF_RESULT_ERROR;
    }

    /* Check that request is async */
    if( flags & CF_REDIS_ASYNC )
    {
        if( redis->req == NULL && redis->cb == NULL )
        {
            redis_set_error(redis, "nothing was bound");
            return CF_RESULT_ERROR;
        }
    }

    /* Add request's flag */
    redis->flags |= flags;

    /* Try to find register Redis DB host */
    LIST_FOREACH(db, &redis_db_hosts_list, rlist)
    {
        if( !strcmp(db->name, dbname) )
            break;
    }

    /* Redis db host is not found as registered db */
    if( db == NULL )
    {
        redis_set_error(redis, "no database found");
        return CF_RESULT_ERROR;
    }

    /* Try to find available connection */
    if( (redis->conn = redis_conn_next(redis, db)) == NULL )
        return CF_RESULT_ERROR;

    /* Free connection is found, so try to use it */

    if( redis->flags & CF_REDIS_ASYNC )
    {
        redis->conn->job = cf_mem_pool_get( &redis_job_pool );
        redis->conn->job->redis = redis;
        redis->state = CF_REDIS_STATE_INIT;
    }

    return CF_RESULT_OK;
}
/************************************************************************
 *  Helper function to bind Redis query (connection) to HTTP request
 ************************************************************************/
#ifndef CF_NO_HTTP
void cf_redis_bind_request( struct cf_redis *redis, struct http_request *req )
{
    if( redis->req != NULL || redis->cb != NULL )
        cf_fatal("cf_redis_bind_request: already bound");

    redis->req = req;
    redis->flags |= REDIS_LIST_INSERTED;

    LIST_INSERT_HEAD(&(req->redisls), redis, rlist);
}
#endif
/************************************************************************
 *  Make request (query) to Redis server
 ************************************************************************/
int cf_redis_query( struct cf_redis *redis, const char *format, ... )
{
    if( redis->conn == NULL )
    {
        redis_set_error(redis, "no connection was set before query");
        return CF_RESULT_ERROR;
    }

    if( redis->flags & CF_REDIS_SYNC )
    {
        /* Make Redis sync request query */
        redis->state = CF_REDIS_STATE_DONE;
        return CF_RESULT_ERROR;
    }
    else
    {
        char* query = NULL;
        int query_len = 0;
        va_list ap;

        va_start(ap, format);
        /* Format Redis query */
        query_len = redis_vformat_command( &query, format, ap );
        va_end( ap );

        if( query_len > 0 && query != NULL )
        {
            /* Flush data out towards destination. */
            net_send_queue( redisConnection(redis), query, query_len );

            /* Delete temporary buffer */
            mem_free( query );

            if( net_send_flush( redisConnection(redis) ) != CF_RESULT_OK )
            {
                redis_set_error(redis, "net_send_flush error");
                return CF_RESULT_ERROR;
            }

            redis_schedule( redis );
        }
        else
        {
            redis_set_error(redis, "redis_vformat_command error");
            return CF_RESULT_ERROR;
        }
    }

    return CF_RESULT_OK;
}
/************************************************************************
 *  Helper function Redis query cleanup
 ************************************************************************/
void cf_redis_cleanup( struct cf_redis *redis )
{
    log_debug("cf_redis_cleanup(%p)", redis);

    /* Remove redis query from waitable list */
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
 *  Helper function to continue Redis query
 ************************************************************************/
void cf_redis_continue( struct cf_redis *redis )
{
    /* Clear error string */
    if( redis->error )
    {
        mem_free(redis->error);
        redis->error = NULL;
    }
/*
    if( redis->result )
    {
        //PQclear(pgsql->result);
        redis->result = NULL;
    }
*/
    switch( redis->state )
    {
    case CF_REDIS_STATE_INIT:
    case CF_REDIS_STATE_WAIT:
        break;
    case CF_REDIS_STATE_DONE:
#ifndef CF_NO_HTTP
        if( redis->req != NULL )
            http_request_wakeup( redis->req );
#endif
        redis_conn_release( redis );
        break;
    case CF_REDIS_STATE_ERROR:
    case CF_REDIS_STATE_RESULT:
        cf_redis_handle( redis->conn, 0);
        break;
    default:
        cf_fatal("unknown redis state %d", redis->state);
    }
}
/************************************************************************
 *  Helper Redis handler function
 ************************************************************************/
void cf_redis_handle( void *c, int err )
{
    struct cf_redis	*redis = NULL;
    struct redis_conn *conn = (struct redis_conn*)c;

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
            http_request_sleep( redis->req );
#endif
        if( redis->cb != NULL )
            redis->cb(redis, redis->arg);
    }
    else
    {
#ifndef CF_NO_HTTP
        if( redis->req != NULL )
            http_request_wakeup( redis->req );
#endif
        if( redis->cb != NULL )
            redis->cb(redis, redis->arg);
    }
}
/************************************************************************
 *  Helper function to get Redis connection structure
 ************************************************************************/
static struct redis_conn* redis_conn_next( struct cf_redis *redis, struct redis_db *db )
{
    struct redis_conn *conn = NULL;

    while( true )
    {
        conn = NULL;

        /* Try to find free connection object first */
        TAILQ_FOREACH(conn, &redis_conn_free_queue, list)
        {
            if( !(conn->flags & REDIS_CONN_FREE ) )
                cf_fatal("got a redis connection that was not free?");
            if( !strcmp(conn->db->name, db->name) )
                break;
        }

        break;
    }

    /* No free connection is available right now */
    if( conn == NULL )
    {
        if( db->conn_max != 0 && db->conn_count >= db->conn_max )
        {
            /* No more connection create */
            if( redis->flags & CF_REDIS_ASYNC )
                redis_queue_add( redis, db ); /* Wait for available */
            else
                redis_set_error(redis,"no available free connections");

            return NULL;
        }

        /* Try to create new one connection */
        if( (conn = redis_conn_create(redis, db)) == NULL )
            return NULL;
    }

    /* Remove redis connection from waitable list */
    conn->flags &= ~REDIS_CONN_FREE;
    TAILQ_REMOVE(&redis_conn_free_queue, conn, list);

    return conn;
}
/************************************************************************
 *  Set error Redis result string and switch to error state
 ************************************************************************/
static void redis_set_error( struct cf_redis *redis, const char *msg )
{
    if( redis->error != NULL )
        mem_free( redis->error );

    redis->error = mem_strdup(msg);
    redis->state = CF_REDIS_STATE_ERROR;
}
/************************************************************************
 *  Helper function Redis schedule
 ************************************************************************/
static void redis_schedule( struct cf_redis *redis )
{
    if( redisSocket(redis) < 0 )
        cf_fatal("Redis returned < 0 fd on open connection");

    cf_platform_schedule_read( redisSocket(redis), redisConnection(redis) );

    redis->state = CF_REDIS_STATE_WAIT;
    redis->flags |= CF_REDIS_SCHEDULED;

#ifndef CF_NO_HTTP
    if( redis->req != NULL ) /* Switch HTTP request to wait state */
        http_request_sleep( redis->req );
#endif

    if( redis->cb != NULL )
        redis->cb(redis, redis->arg);
}
/************************************************************************
 *  Add Redis query to wait queue
 ************************************************************************/
static void redis_queue_add( struct cf_redis *redis, struct redis_db *db )
{
    struct redis_wait *rw = NULL;

#ifndef CF_NO_HTTP
    if( redis->req != NULL )
        http_request_sleep( redis->req );
#endif

    rw = cf_mem_pool_get( &redis_wait_pool );
    rw->redis = redis;
    rw->db = db;
    TAILQ_INSERT_TAIL( &redis_wait_queue, rw, list );
}
/************************************************************************
 *  Remove Redis query from wait queue
 ************************************************************************/
static void redis_queue_remove( struct cf_redis *redis )
{
    struct redis_wait *rw, *next;

    for( rw = TAILQ_FIRST(&redis_wait_queue); rw != NULL; rw = next)
    {
        next = TAILQ_NEXT(rw, list);
        if( rw->redis != redis )
            continue;

        TAILQ_REMOVE(&redis_wait_queue, rw, list);
        cf_mem_pool_put( &redis_wait_pool, rw);
        return;
    }
}
/************************************************************************
 *  Helper function to wakeup Redis query, when new free connection
 *  is available
 ************************************************************************/
static void redis_queue_wakeup( uint8_t	state, struct redis_db *db )
{
    struct redis_wait *rw, *next;

    for( rw = TAILQ_FIRST( &redis_wait_queue ); rw != NULL; rw = next )
    {
        next = TAILQ_NEXT(rw, list);

#ifndef CF_NO_HTTP
        if( rw->redis->req != NULL )
        {
            /* Try first to check, that HTTP request already need to be deleted */
            if( rw->redis->req->flags & HTTP_REQUEST_DELETE )
            {
                TAILQ_REMOVE( &redis_wait_queue, rw, list );
                cf_mem_pool_put( &redis_wait_pool, rw );
                continue;
            }

            /* Check if that query related to current db, if not skip to wakeup */
            if( db && strcmp(rw->db->name, db->name) )
                continue;

            /* wakeup HTTP request */
            http_request_wakeup(rw->redis->req);

            db = NULL; /* Skip to continue check Redis db */
        }
#endif
        /* Check if that query related to current db, if not skip to wakeup */
        if( db && strcmp(rw->db->name, db->name) )
            continue;

        /* Change query state for current wait Redis connection query */
        if( state != 0 )
            rw->redis->state = state;

        if( rw->redis->cb != NULL )
            rw->redis->cb(rw->redis, rw->redis->arg);

        TAILQ_REMOVE( &redis_wait_queue, rw, list );
        cf_mem_pool_put( &redis_wait_pool, rw );
    }
}
/************************************************************************
 *  Helper function Redis connection create
 ************************************************************************/
static struct redis_conn* redis_conn_create( struct cf_redis *redis, struct redis_db *db )
{
    int fd = -1;

    if( db == NULL || db->host == NULL )
        cf_fatal("redis_conn_create: no connection host");

    /* Create socket */
    if( (fd = cf_tcp_socket( db->host, SOCK_STREAM)) != -1 )
    {
        struct redis_conn *conn = NULL;

        /* Set it to non blocking */
        if( !cf_socket_nonblock(fd, 1) )
        {
            close( fd );
            return NULL;
        }

        /* Allocate redis_conn structure */
        conn = mem_malloc( sizeof(*conn) );
        /* Init structure fields */
        conn->job = NULL;
        conn->db = db;      /* Set Redis host DB */

        /* Allocate connection structure & prepare Redis connection */
        conn->c = cf_connection_new( conn, CF_TYPE_BACKEND );
        /* Set connection address */
        conn->c->addrtype = AF_INET;
        conn->c->addr.ipv4.sin_family = AF_INET;
        conn->c->addr.ipv4.sin_port = htons( db->port );
        conn->c->addr.ipv4.sin_addr.s_addr = inet_addr( db->host );
        /* Set the file descriptor for Redis connection */
        conn->c->fd = fd;
        /* Default write/read callbacks for Redis server connection */
        conn->c->read = net_read;
        conn->c->write = net_write;
        /* Connection protocol type & init state as current connecting */
        conn->c->proto = CONN_PROTO_REDIS;
        conn->c->state = CONN_STATE_CONNECTING;
        /* Redis server idle timer is set first to connection timeout */
        conn->c->idle_timer.length = REDIS_CONNECT_TIMEOUT;
        /* Set callback handler for connection success */
        conn->c->handle = redis_handle_connect;
        /* Set the disconnect method for Redis server connections & error callback */
        conn->c->disconnect = redis_handle_disconnect;

        /* Increment connection count for Redis db host */
        db->conn_count++;

        if( redis->flags & CF_REDIS_ASYNC )
            redis->state = CF_REDIS_STATE_CONNECTING;

        redis_queue_add( redis, db );

        /* Queue write events for the backend connection for now */
        cf_platform_schedule_write(conn->c->fd, conn->c);

        connection_add_backend( conn->c );

        /* Kick off connecting */
        conn->c->flags |= CONN_WRITE_POSSIBLE;
        conn->c->handle( conn->c );

        log_debug("redis_conn_create(): %p", conn);
    }

    return NULL;
}
/************************************************************************
 *  Helper function to release Redis server connection, move back to list
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
            cf_platform_disable_events( redisSocket(redis) );

            if( redis->state != CF_REDIS_STATE_DONE )
                redis_cancel( redis );
        }

        cf_mem_pool_put( &redis_job_pool, redis->conn->job );
    }

    redis_free_reply( redis );
    redis->conn->job = NULL;
    redis->conn->flags |= REDIS_CONN_FREE;
    TAILQ_INSERT_TAIL( &redis_conn_free_queue, redis->conn, list );

    redis->conn = NULL;
    redis->state = CF_REDIS_STATE_COMPLETE;

    if( redis->cb != NULL )
        redis->cb(redis, redis->arg);

    redis_queue_wakeup(0, NULL);
}
/************************************************************************
 *  Clean up Redis database connection & remove from host's list
 ************************************************************************/
static void redis_conn_cleanup( struct redis_conn *conn )
{
    struct cf_redis	*redis = NULL;
    struct redis_db	*redisdb = NULL;

    log_debug("redis_conn_cleanup(): %p", conn);

    if( conn->flags & REDIS_CONN_FREE )
        TAILQ_REMOVE( &redis_conn_free_queue, conn, list);

    if( conn->job )
    {
        redis = conn->job->redis;

#ifndef CF_NO_HTTP
        if( redis->req != NULL )
            http_request_wakeup( redis->req );
#endif

        redis->conn = NULL;
        //redis_set_error(redis, "");

        cf_mem_pool_put( &redis_job_pool, conn->job );
        conn->job = NULL;
    }

    /* Disconnect from server */
/*
    if( conn->db != NULL )
        PQfinish(conn->db);
*/
    /* Delete Redis host from host's list */
    LIST_FOREACH(redisdb, &redis_db_hosts_list, rlist)
    {
        if( strcmp(redisdb->name, conn->db->name) )
        {
            redisdb->conn_count--;
            break;
        }
    }

    /* Clear structure fields */
    mem_free(conn);
}
/************************************************************************
 *  Helper function Redis read result
 ************************************************************************/
static void redis_read_result( struct cf_redis *redis )
{

}
/************************************************************************
 *  Helper function to cancel PGSQL query
 ************************************************************************/
static void redis_cancel( struct cf_redis *redis )
{

}
/****************************************************************
 *  Connection handler for Redis server
 ****************************************************************/
static int redis_handle_connect( struct connection *c )
{
    struct redis_conn* redis_c = NULL;

    /* We will get a write notification when we can progress */
    if( !(c->flags & CONN_WRITE_POSSIBLE) )
        return CF_RESULT_OK;

    cf_connection_stop_idletimer( c );

    /* Attempt connecting */

    /* If we failed check why, we are non blocking */
    if( cf_connection_connect_toaddr( c ) == -1 )
    {
        /* If we got a real error, disconnect */
        if( errno != EALREADY && errno != EINPROGRESS && errno != EISCONN )
        {
            cf_log(LOG_ERR, "connect(): %s", errno_s);
            return CF_RESULT_ERROR;
        }

        /* Clean the write flag, we'll be called later */
        if( errno != EISCONN )
        {
            c->flags &= ~CONN_WRITE_POSSIBLE;
            cf_connection_start_idletimer(c);
            return CF_RESULT_OK;
        }
    }

    /* Set connection state as established */
    c->state = CONN_STATE_ESTABLISHED;
    c->idle_timer.length = REDIS_TIMEOUT;

    /* The connection to the server succeeded */
    c->handle = redis_handle; /* Set default Redis handle callback function */

    /* Setup read calls for backend connection */
    net_recv_queue(c, NETBUF_SEND_PAYLOAD_MAX, NETBUF_CALL_CB_ALWAYS, redis_recv);

    redis_c = (struct redis_conn*)c->owner;
    redis_c->flags = REDIS_CONN_FREE;
    /* Add to the free connection's list */
    TAILQ_INSERT_TAIL( &redis_conn_free_queue, redis_c, list);

    cf_connection_start_idletimer( c );
    /* Allow for all events now */
    cf_platform_event_all(c->fd, c);

    printf("%p: redis connected\n", (void *)c);

    /* Notify wait consumers */
    redis_queue_wakeup(CF_REDIS_STATE_READY, redis_c->db);

    return CF_RESULT_OK;
}
/****************************************************************
 *  Read data Redis server response from input buffer
 ****************************************************************/
static int redis_recv( struct netbuf *nb )
{
    struct cf_redis_reply* r = NULL;
    struct connection *c = (struct connection *)nb->owner;
    struct redis_conn *conn = (struct redis_conn*)c->owner;
    struct cf_redis* redis = conn->job->redis;

    printf("redis resp: %s (%lu)\n", nb->buf, nb->s_off);

    if( redis_get_reply( &r, nb->buf, nb->s_off ) == CF_RESULT_OK )
    {
        redis->reply = r;
        redis->state = CF_REDIS_STATE_COMPLETE;
        //redis_queue_wakeup(CF_REDIS_STATE_COMPLETE, conn->name);
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

    log_debug("redis_recv(%p)", c);

    return CF_RESULT_OK;
}
/****************************************************************
 *  Connection handler for Redis server
 ****************************************************************/
static void redis_handle_disconnect( struct connection *c, int err )
{
    /* Disable catch events */
    cf_platform_disable_events( c->fd );

    if( err )
    {
        struct redis_conn* redis_c = (struct redis_conn*)c->owner;

        //if( c->state == CONN_STATE_CONNECTING )
        //    redis_set_error(redis, "couldn't connect to Redis server");

        redis_queue_wakeup(CF_REDIS_STATE_ERROR, redis_c->db);

        /* Remove disconnect function handler */
        cf_connection_disconnect( c );
    }
    else
    {
        if( c->state == CONN_STATE_DISCONNECTING )
        {
            if( err )
            //struct redis_conn* conn = (struct redis_conn*)c->owner;
            //conn->redis;

            cf_connection_stop_idletimer( c );

            printf("!!! redis disconected !!!\n");
        }
    }

}
/****************************************************************
 *  Redis server response handler
 ****************************************************************/
static int redis_handle( struct connection *c )
{
    //printf("redis handle\n");
    return cf_connection_handle(c);
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
    int error_type = 0; /* 0 = no error (empty response);
                           -1 = memory error;
                           -2 = format error;
                           > 0 = no error (good response) */
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
*  Helper function to get Redis reply function
************************************************************************/
static int redis_get_reply( struct cf_redis_reply** r, uint8_t* buf, size_t len )
{
    if( buf && len > 1 )
    {
        uint8_t r_type = 0;

        switch( buf[0] )
        {
        case '-':
            r_type = REDIS_REPLY_ERROR;
            break;
        case '+':
            r_type = REDIS_REPLY_STATUS;
            break;
        case ':':
            r_type = REDIS_REPLY_INTEGER;
            break;
        case '$':
            r_type = REDIS_REPLY_STRING;
            break;
        case '*':
            r_type = REDIS_REPLY_ARRAY;
            break;
        default:
                return CF_RESULT_ERROR;
        }

        /* process typed item */
        switch( r_type )
        {
        case REDIS_REPLY_ERROR:
        case REDIS_REPLY_STATUS:
        case REDIS_REPLY_INTEGER:
            return redis_process_line_item( r, buf + 1, len - 1, r_type );
        case REDIS_REPLY_STRING:
            return redis_process_bulk_item( r, buf + 1, len - 1 );
        case REDIS_REPLY_ARRAY:
            return redis_process_multi_bulk_item( r, buf, len );
        default:
            return CF_RESULT_ERROR;
        }
    }

    return CF_RESULT_ERROR;
}
/************************************************************************
*  Helper function to get Redis reply function
************************************************************************/
static int redis_process_line_item( struct cf_redis_reply** r, uint8_t* buf, size_t len, uint8_t r_type )
{
    /* Try to find end of line */
    uint8_t* end_line = cf_mem_find( buf, len, "\r\n", 2);

    if( end_line )
    {
        ptrdiff_t len_reply = end_line - buf;

        /* Allocate redis reply structure */
        *r = mem_malloc(sizeof(*r));

        if( r_type == REDIS_REPLY_INTEGER )
        {

        }
        else /* create string object */
        {
            (*r)->str = mem_malloc( len_reply + 1 );
            /* Copy string value */
            memcpy( (*r)->str, buf, len_reply );
            (*r)->str[len_reply] = '\0';
        }
    }

    return CF_RESULT_OK;
}

static int redis_process_bulk_item( struct cf_redis_reply** r, uint8_t* buf, size_t len )
{
    return CF_RESULT_ERROR;
}

static int redis_process_multi_bulk_item( struct cf_redis_reply** r, uint8_t* buf, size_t len )
{
    return CF_RESULT_ERROR;
}
/************************************************************************
*  Helper function to free Redis reply structure
************************************************************************/
static void redis_free_reply( struct cf_redis* redis )
{

}





