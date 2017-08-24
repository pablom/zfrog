// cf_redis.c

#include <hiredis/hiredis.h>
#include "zfrog.h"
#include "cf_redis.h"

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

#define REDIS_CONN_MAX      2        /* Default maximum redis connections */

#define REDIS_CONN_FREE         0x0001
#define REDIS_LIST_INSERTED     0x0100


struct redis_db
{
    char      *name;
    char      *host;
    uint16_t   port;

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


/* Global variables */
static uint16_t  g_redis_conn_count;

static struct cf_mem_pool g_redis_job_pool;     /* Memory pool for Redis request job */
static struct cf_mem_pool g_redis_wait_pool;

static LIST_HEAD(, redis_db)     g_redis_db_hosts;  /* List of available Redis db hosts */
static TAILQ_HEAD(, redis_conn)	 g_redis_conn_free;
static TAILQ_HEAD(, redis_wait)	 g_redis_wait_queue;

uint16_t g_redis_conn_max = REDIS_CONN_MAX;

/************************************************************************
 *  Redis system initialization
 ************************************************************************/
void cf_redis_sys_init( void )
{
    /* Set current connection count */
    g_redis_conn_count = 0;
    /* Init list & queues */
    LIST_INIT(&g_redis_db_hosts);
    TAILQ_INIT(&g_redis_conn_free);
    TAILQ_INIT(&g_redis_wait_queue);

    cf_mem_pool_init(&g_redis_job_pool, "redis_job_pool", sizeof(struct redis_job), 100);        
    cf_mem_pool_init(&g_redis_wait_pool, "redis_wait_pool", sizeof(struct redis_wait), 100);
}
/************************************************************************
 *  Redis system cleanup
 ************************************************************************/
void cf_redis_sys_cleanup( void )
{
    struct redis_conn *conn, *next;

    cf_mem_pool_cleanup(&g_redis_job_pool);
    cf_mem_pool_cleanup(&g_redis_wait_pool);

    for( conn = TAILQ_FIRST(&g_redis_conn_free); conn != NULL; conn = next )
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

    LIST_FOREACH(db, &g_redis_db_hosts, rlist)
    {
        if( !strcmp(db->host, host) )
            return CF_RESULT_ERROR;
    }

    db = mem_malloc(sizeof(*db));
    db->name = mem_strdup(name);
    db->host = mem_strdup(host);
    db->port = port;

    /* Add Redis host to our internal list */
    LIST_INSERT_HEAD(&g_redis_db_hosts, db, rlist);

    cf_log(LOG_NOTICE, "redis adding host: %s (%d)", host, port);

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
        //pgsql_set_error(pgsql, "invalid query init parameters");
        return CF_RESULT_ERROR;
    }

    if( flags & CF_REDIS_ASYNC )
    {
        if( redis->req == NULL && redis->cb == NULL )
        {
            //pgsql_set_error(pgsql, "nothing was bound");
            return CF_RESULT_ERROR;
        }
    }

    redis->flags |= flags;

    LIST_FOREACH(db, &g_redis_db_hosts, rlist)
    {
        if( !strcmp(db->name, dbname) )
            break;
    }

    if( db == NULL )
    {
        //pgsql_set_error(pgsql, "no database found");
        return CF_RESULT_ERROR;
    }

    if( (redis->conn = redis_conn_next(redis, db)) == NULL )
        return CF_RESULT_ERROR;

    if( redis->flags & CF_REDIS_ASYNC )
    {
        redis->conn->job = cf_mem_pool_get(&g_redis_job_pool);
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
 *  Deafault Redis handler function
 ************************************************************************/
void cf_redis_handle( void *c, int err )
{
    struct cf_redis	*redis = NULL;
    struct redis_conn *conn = (struct redis_conn *)c;

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
int cf_redis_format_command(char **target, const char *format, ...)
{
    va_list ap;
    int len = -1;
    va_start(ap,format);
    //len = redisvFormatCommand(target,format,ap);
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

    TAILQ_FOREACH(conn, &g_redis_conn_free, list)
    {
        if( !(conn->flags & REDIS_CONN_FREE ) )
            cf_fatal("got a redis connection that was not free?");
        if( !strcmp(conn->name, db->name) )
            break;
    }

    if( conn == NULL )
    {
        if( g_redis_conn_count >= g_redis_conn_max )
        {
            if( redis->flags & CF_REDIS_ASYNC )
            {
                redis_queue_add( redis );
            }
            else
            {
                redis_set_error(redis,"no available connection");
            }

            return NULL;
        }

        if( (conn = redis_conn_create(redis, db)) == NULL )
            return NULL;
    }

    conn->flags &= ~REDIS_CONN_FREE;
    TAILQ_REMOVE(&g_redis_conn_free, conn, list);

    return conn;
}
/************************************************************************
 *  Helper function Redis add to queue
 ************************************************************************/
static void redis_queue_add( struct cf_redis *redis )
{
    struct redis_wait *rw = NULL;

#ifndef CF_NO_HTTP
    if( redis->req != NULL )
        http_request_sleep( redis->req );
#endif

    rw = cf_mem_pool_get(&g_redis_wait_pool);
    rw->redis = redis;
    TAILQ_INSERT_TAIL(&g_redis_wait_queue, rw, list);
}
/************************************************************************
 *  Helper function Redis connection cleanup
 ************************************************************************/
static void redis_conn_cleanup( struct redis_conn *conn )
{
    struct cf_redis	*redis = NULL;

    log_debug("redis_conn_cleanup(): %p", conn);

    if( conn->flags & REDIS_CONN_FREE )
        TAILQ_REMOVE(&g_redis_conn_free, conn, list);

    if( conn->job )
    {
        redis = conn->job->redis;

#ifndef CF_NO_HTTP
        if( redis->req != NULL )
            http_request_wakeup( redis->req );
#endif

        redis->conn = NULL;
        //pgsql_set_error(pgsql, PQerrorMessage(conn->db));

        cf_mem_pool_put( &g_redis_job_pool, conn->job);
        conn->job = NULL;
    }

    //if( conn->db != NULL )
    //    PQfinish(conn->db);

    g_redis_conn_count--;
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
static void redis_read_result(struct cf_redis *redis)
{

}
/************************************************************************
 *  Helper function Redis connection release
 ************************************************************************/
static void redis_conn_release( struct cf_redis *redis )
{
    int	fd = -1;

    if( redis->conn == NULL )
        return;

    /* Async query cleanup */
    if( redis->flags & CF_REDIS_ASYNC )
    {
        if( redis->flags & CF_REDIS_SCHEDULED )
        {
            //fd = PQsocket(pgsql->conn->db);
            cf_platform_disable_read( fd );

//            if( redis->state != CF_REDIS_STATE_DONE )
//                redis_cancel( redis );
        }

        cf_mem_pool_put(&g_redis_job_pool, redis->conn->job);
    }

    redis->conn->job = NULL;
    redis->conn->flags |= REDIS_CONN_FREE;
    TAILQ_INSERT_TAIL(&g_redis_conn_free, redis->conn, list);

    redis->conn = NULL;
    redis->state = CF_REDIS_STATE_COMPLETE;

    if( redis->cb != NULL )
        redis->cb(redis, redis->arg);

    redis_queue_wakeup();
}
/************************************************************************
 *  Helper function Redis connection release
 ************************************************************************/
static struct redis_conn* redis_conn_create( struct cf_redis *redis, struct redis_db *db )
{
    struct redis_conn *conn = NULL;

    if( db == NULL || db->host == NULL )
        cf_fatal("redis_conn_create: no connection host");

    g_redis_conn_count++;

    conn = mem_malloc(sizeof(*conn));
    conn->job = NULL;
    conn->flags = REDIS_CONN_FREE;
    conn->type = CF_TYPE_REDIS;
    conn->name = mem_strdup(db->name);
    TAILQ_INSERT_TAIL( &g_redis_conn_free, conn, list);

    log_debug("redis_conn_create(): %p", conn);

/*
    conn->db = PQconnectdb(db->conn_string);
    if( conn->db == NULL || (PQstatus(conn->db) != CONNECTION_OK) )
    {
        pgsql_set_error(pgsql, PQerrorMessage(conn->db));
        pgsql_conn_cleanup(conn);
        return (NULL);
    }
*/

    return conn;
}
/************************************************************************
 *  Helper function to wakeup Redis connections
 ************************************************************************/
static void redis_queue_wakeup( void )
{
    struct redis_wait *rw, *next;

    for( rw = TAILQ_FIRST(&g_redis_wait_queue); rw != NULL; rw = next )
    {
        next = TAILQ_NEXT(rw, list);

#ifndef CF_NO_HTTP
        if( rw->redis->req != NULL )
        {
            if( rw->redis->req->flags & HTTP_REQUEST_DELETE )
            {
                TAILQ_REMOVE(&g_redis_wait_queue, rw, list);
                cf_mem_pool_put( &g_redis_wait_pool, rw );
                continue;
            }

            http_request_wakeup(rw->redis->req);
        }
#endif

        if( rw->redis->cb != NULL )
            rw->redis->cb(rw->redis, rw->redis->arg);

        TAILQ_REMOVE(&g_redis_wait_queue, rw, list);
        cf_mem_pool_put( &g_redis_wait_pool, rw );
    }
}
/************************************************************************
 *  Helper function to remove Redis structure from internal queue
 ************************************************************************/
static void redis_queue_remove( struct cf_redis *redis )
{
    struct redis_wait *rw, *next;

    for( rw = TAILQ_FIRST(&g_redis_wait_queue); rw != NULL; rw = next)
    {
        next = TAILQ_NEXT(rw, list);
        if( rw->redis != redis )
            continue;

        TAILQ_REMOVE(&g_redis_wait_queue, rw, list);
        cf_mem_pool_put( &g_redis_wait_pool, rw);
        return;
    }
}


#ifdef MMM

int redis_vformat_command( char **target, const char *format, va_list ap )
{
    const char *c = format;
    char *cmd = NULL; /* final command */
    int pos; /* position in final command */
    sds curarg, newarg; /* current argument */
    int touched = 0; /* was the current argument touched? */
    char **curargv = NULL, **newargv = NULL;
    int argc = 0;
    int totlen = 0;
    int error_type = 0; /* 0 = no error; -1 = memory error; -2 = format error */
    int j;

    /* Abort if there is not target to set */
    if( target == NULL )
        return -1;

    /* Build the command string accordingly to protocol */
    curarg = sdsempty();
    if( curarg == NULL )
        return -1;

    while( *c != '\0' )
    {
        if( *c != '%' || c[1] == '\0' )
        {
            if( *c == ' ' )
            {
                if( touched )
                {
                    newargv = realloc(curargv,sizeof(char*)*(argc+1));
                    if (newargv == NULL) goto memory_err;
                    curargv = newargv;
                    curargv[argc++] = curarg;
                    totlen += bulklen(sdslen(curarg));

                    /* curarg is put in argv so it can be overwritten. */
                    curarg = sdsempty();
                    if (curarg == NULL) goto memory_err;
                    touched = 0;
                }
            }
            else
            {
                newarg = sdscatlen(curarg,c,1);
                if (newarg == NULL) goto memory_err;
                curarg = newarg;
                touched = 1;
            }
        }
        else
        {
            char *arg;
            size_t size;

            /* Set newarg so it can be checked even if it is not touched. */
            newarg = curarg;

            switch(c[1]) {
            case 's':
                arg = va_arg(ap,char*);
                size = strlen(arg);
                if (size > 0)
                    newarg = sdscatlen(curarg,arg,size);
                break;
            case 'b':
                arg = va_arg(ap,char*);
                size = va_arg(ap,size_t);
                if (size > 0)
                    newarg = sdscatlen(curarg,arg,size);
                break;
            case '%':
                newarg = sdscat(curarg,"%");
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
                    while (*_p != '\0' && strchr(flags,*_p) != NULL) _p++;

                    /* Field width */
                    while (*_p != '\0' && isdigit(*_p)) _p++;

                    /* Precision */
                    if (*_p == '.') {
                        _p++;
                        while (*_p != '\0' && isdigit(*_p)) _p++;
                    }

                    /* Copy va_list before consuming with va_arg */
                    va_copy(_cpy,ap);

                    /* Integer conversion (without modifiers) */
                    if( strchr(intfmts,*_p) != NULL )
                    {
                        va_arg(ap,int);
                        goto fmt_valid;
                    }

                    /* Double conversion (without modifiers) */
                    if( strchr("eEfFgGaA",*_p) != NULL )
                    {
                        va_arg(ap,double);
                        goto fmt_valid;
                    }

                    /* Size: char */
                    if( _p[0] == 'h' && _p[1] == 'h' )
                    {
                        _p += 2;
                        if( *_p != '\0' && strchr(intfmts,*_p) != NULL )
                        {
                            va_arg(ap,int); /* char gets promoted to int */
                            goto fmt_valid;
                        }
                        goto fmt_invalid;
                    }

                    /* Size: short */
                    if( _p[0] == 'h' )
                    {
                        _p += 1;
                        if( *_p != '\0' && strchr(intfmts,*_p) != NULL )
                        {
                            va_arg(ap,int); /* short gets promoted to int */
                            goto fmt_valid;
                        }
                        goto fmt_invalid;
                    }

                    /* Size: long long */
                    if( _p[0] == 'l' && _p[1] == 'l' )
                    {
                        _p += 2;
                        if( *_p != '\0' && strchr(intfmts,*_p) != NULL )
                        {
                            va_arg(ap,long long);
                            goto fmt_valid;
                        }
                        goto fmt_invalid;
                    }

                    /* Size: long */
                    if( _p[0] == 'l' )
                    {
                        _p += 1;
                        if( *_p != '\0' && strchr(intfmts,*_p) != NULL )
                        {
                            va_arg(ap,long);
                            goto fmt_valid;
                        }
                        goto fmt_invalid;
                    }

                fmt_invalid:
                    va_end(_cpy);
                    goto format_err;

                fmt_valid:
                    _l = (_p+1)-c;
                    if( _l < sizeof(_format) - 2 )
                    {
                        memcpy(_format,c,_l);
                        _format[_l] = '\0';
                        newarg = sdscatvprintf(curarg,_format,_cpy);

                        /* Update current position (note: outer blocks
                         * increment c twice so compensate here) */
                        c = _p - 1;
                    }

                    va_end(_cpy);
                    break;
                }
            }

            if (newarg == NULL) goto memory_err;
            curarg = newarg;

            touched = 1;
            c++;
        }
        c++;
    }

    /* Add the last argument if needed */
    if(touched)
    {
        newargv = realloc(curargv,sizeof(char*)*(argc+1));
        if (newargv == NULL) goto memory_err;
        curargv = newargv;
        curargv[argc++] = curarg;
        totlen += bulklen(sdslen(curarg));
    }
    else
    {
        sdsfree(curarg);
    }

    /* Clear curarg because it was put in curargv or was free'd. */
    curarg = NULL;

    /* Add bytes needed to hold multi bulk count */
    totlen += 1+countDigits(argc)+2;

    /* Build the command at protocol level */
    cmd = malloc(totlen+1);
    if (cmd == NULL) goto memory_err;

    pos = sprintf(cmd,"*%d\r\n",argc);

    for( j = 0; j < argc; j++ )
    {
        pos += sprintf(cmd+pos,"$%zu\r\n",sdslen(curargv[j]));
        memcpy(cmd+pos,curargv[j],sdslen(curargv[j]));
        pos += sdslen(curargv[j]);
        sdsfree(curargv[j]);
        cmd[pos++] = '\r';
        cmd[pos++] = '\n';
    }
    assert(pos == totlen);
    cmd[pos] = '\0';

    free(curargv);
    *target = cmd;
    return totlen;

format_err:
    error_type = -2;
    goto cleanup;

memory_err:
    error_type = -1;
    goto cleanup;

cleanup:
    if(curargv)
    {
        while(argc--)
            sdsfree(curargv[argc]);
        free(curargv);
    }

    sdsfree(curarg);

    /* No need to check cmd since it is the last statement that can fail,
     * but do it anyway to be as defensive as possible. */
    if (cmd != NULL)
        free(cmd);

    return error_type;
}
#endif

