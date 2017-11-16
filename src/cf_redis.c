// cf_redis.c

#include "zfrog.h"
#include "cf_redis.h"

#include <stdbool.h>
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

static int redis_handle_connect(struct connection*);
static void redis_handle_disconnect(struct connection *);
static int redis_handle( struct connection* );
static void redis_schedule(struct cf_redis*);


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

    /* Try to find available connection */
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
 *  Helper function to get Redis connection structure
 ************************************************************************/
static struct redis_conn* redis_conn_next( struct cf_redis *redis, struct redis_db *db )
{
    struct redis_conn *c = NULL;
    //struct cf_redis	*rollback = NULL;

    while( true )
    {
        c = NULL;

        TAILQ_FOREACH(c, &redis_conn_free_queue, list)
        {
            if( !(c->flags & REDIS_CONN_FREE ) )
                cf_fatal("got a redis connection that was not free?");
            if( !strcmp(c->name, db->name) )
                break;
        }

        break;
    }

    if( c == NULL )
    {
        if( db->conn_max != 0 && db->conn_count >= db->conn_max )
        {
            if( redis->flags & CF_REDIS_ASYNC )
                redis_queue_add( redis );
            else
                redis_set_error(redis,"no available connection");

            return NULL;
        }

        if( (c = redis_conn_create(redis, db)) == NULL )
            return NULL;
    }

    c->flags &= ~REDIS_CONN_FREE;
    TAILQ_REMOVE(&redis_conn_free_queue, c, list);

    return c;
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
void cf_redis_handle( struct connection *c, int err )
{
    struct redis_conn *conn = (struct redis_conn*)c->owner;
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
            cf_platform_disable_read( redis->conn->conn->fd );

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
 *  Helper function Redis connection create
 ************************************************************************/
static struct redis_conn* redis_conn_create( struct cf_redis *redis, struct redis_db *db )
{
    struct redis_conn *c = NULL;
    int fd = -1;

    if( db == NULL || db->host == NULL )
        cf_fatal("redis_conn_create: no connection host");

    /* Create socket */
    if( (fd = cf_tcp_socket( db->host, SOCK_STREAM)) != -1 )
    {
        /* Set it to non blocking */
        if( !cf_socket_nonblock(fd, 1) )
        {
            close( fd );
            return NULL;
        }

        /* Increment connection count */
        db->conn_count++;

        redis_queue_add( redis );

        /* Allocate redis_conn structure */
        c = mem_malloc(sizeof(*c));

        /* Init structure */
        c->job = NULL;
        c->name = mem_strdup(db->name);

        /* Allocate connection structure */
        c->conn = cf_connection_new( c );

        /* Prepare our connection. */
        c->conn->addrtype = AF_INET;
        c->conn->addr.ipv4.sin_family = AF_INET;
        c->conn->addr.ipv4.sin_port = htons( db->port );
        c->conn->addr.ipv4.sin_addr.s_addr = inet_addr( db->host );

        /* Set the file descriptor for Redis connection */
        c->conn->fd = fd;

        /* Default write/read callbacks for Redis server connection */
        c->conn->read = net_read;
        c->conn->write = net_write;

        /* Connection protocol type & init state */
        c->conn->proto = CONN_PROTO_REDIS;
        c->conn->state = CONN_STATE_CONNECTING;

        /* Redis server idle timer is set first to connection timeout */
        c->conn->idle_timer.length = REDIS_CONNECT_TIMEOUT;
        c->conn->handle = redis_handle_connect;
        /* Set the disconnect method for Redis server connections */
        c->conn->disconnect = redis_handle_disconnect;

        /* Queue write events for the backend connection for now */
        cf_platform_schedule_write(c->conn->fd, c->conn);

        connection_add_backend( c->conn );

        /* Kick off connecting */
        c->conn->flags |= CONN_WRITE_POSSIBLE;
        c->conn->handle( c->conn );

        log_debug("redis_conn_create(): %p", c);
    }

    return NULL;
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

    for( rw = TAILQ_FIRST( &redis_wait_queue ); rw != NULL; rw = next )
    {
        next = TAILQ_NEXT(rw, list);
        if( rw->redis != redis )
            continue;

        TAILQ_REMOVE( &redis_wait_queue, rw, list );
        cf_mem_pool_put( &redis_wait_pool, rw);
        return;
    }
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
    cf_log(LOG_NOTICE, "redis error: %s", (redis->error) ? redis->error : "unknown");
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
/****************************************************************
 *  Read data Redis server response from input buffer
 ****************************************************************/
int redis_recv( struct netbuf *nb )
{
    struct connection *c = (struct connection *)nb->owner;

    printf("redis resp: %s (%lu)\n", nb->buf, nb->s_off);

    log_debug("redis_recv(%p)", c);

    return CF_RESULT_OK;
}
/****************************************************************
 *  Connection handler for Redis server
 ****************************************************************/
static void redis_handle_disconnect( struct connection *c )
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
    /* Add to the free */
    TAILQ_INSERT_TAIL( &redis_conn_free_queue, redis_c, list);

    cf_connection_start_idletimer( c );
    /* Allow for all events now */
    cf_platform_event_all(c->fd, c);

    printf("%p: redis connected\n", (void *)c);

    redis_queue_wakeup();

    return CF_RESULT_OK;
}
/****************************************************************
 *  Redis server response handler
 ****************************************************************/
static int redis_handle( struct connection *c )
{
    return cf_connection_handle(c);
}

static void redis_schedule( struct cf_redis *redis )
{
    int	fd = redis->conn->conn->fd;

    if( fd < 0 )
        cf_fatal("Redis returned < 0 fd on open connection");

    cf_platform_schedule_read(fd, redis->conn->conn);

    redis->state = CF_REDIS_STATE_WAIT;
    redis->flags |= CF_REDIS_SCHEDULED;

#ifndef CF_NO_HTTP
    if( redis->req != NULL )
        http_request_sleep( redis->req );
#endif

    if( redis->cb != NULL )
        redis->cb(redis, redis->arg);
}

/************************************************************************
 *  Make request (query) to PQSQL server
 ************************************************************************/
int cf_redis_query( struct cf_redis *redis, const char *query )
{
    if( redis->conn == NULL )
    {
        redis_set_error(redis, "no connection was set before query");
        return CF_RESULT_ERROR;
    }

    if( redis->flags & CF_REDIS_SYNC )
    {
        redis->state = CF_REDIS_STATE_DONE;
        return CF_RESULT_ERROR;
    }
    else
    {
        char* cmd = NULL;

        cf_redis_format_command( &cmd, query );

        /* Flush data out towards destination. */
        net_send_queue(redis->conn->conn, cmd, strlen(cmd) );
        net_send_flush(redis->conn->conn);
        mem_free( cmd);
        redis_schedule( redis );
    }

    return CF_RESULT_OK;
}
