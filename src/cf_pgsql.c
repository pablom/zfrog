// cf_pgsql.c

#include <sys/param.h>
#include <sys/queue.h>

#include <libpq-fe.h>
#include <pg_config.h>

#include "zfrog.h"
#include "cf_pgsql.h"

#ifndef CF_NO_HTTP
#include "cf_http.h"
#endif

struct pgsql_job
{
    struct cf_pgsql	*pgsql;
	TAILQ_ENTRY(pgsql_job)	list;
};

struct pgsql_wait
{
    struct cf_pgsql	*pgsql;
	TAILQ_ENTRY(pgsql_wait)		list;
};

#define PGSQL_CONN_FREE         0x01
#define PGSQL_LIST_INSERTED     0x0100

static void	pgsql_queue_wakeup(void);
static void	pgsql_cancel(struct cf_pgsql*);
static void	pgsql_set_error(struct cf_pgsql*, const char*);
static void	pgsql_queue_add(struct cf_pgsql*);
static void	pgsql_queue_remove(struct cf_pgsql*);
static void	pgsql_conn_release(struct cf_pgsql*);
static void	pgsql_conn_cleanup(struct pgsql_conn*);
static void	pgsql_read_result(struct cf_pgsql*);
static void	pgsql_schedule(struct cf_pgsql*);

static struct pgsql_conn *pgsql_conn_create(struct cf_pgsql*, struct pgsql_db*);
static struct pgsql_conn *pgsql_conn_next(struct cf_pgsql*, struct pgsql_db*);

static struct cf_mem_pool           pgsql_job_pool;
static struct cf_mem_pool           pgsql_wait_pool;
static TAILQ_HEAD(, pgsql_conn)		pgsql_conn_free;
static TAILQ_HEAD(, pgsql_wait)		pgsql_wait_queue;
static LIST_HEAD(, pgsql_db)		pgsql_db_conn_strings;

/************************************************************************
 *  Helper function PGSQL system initialization
 ************************************************************************/
void cf_pgsql_sys_init( void )
{
	TAILQ_INIT(&pgsql_conn_free);
	TAILQ_INIT(&pgsql_wait_queue);
	LIST_INIT(&pgsql_db_conn_strings);

    cf_mem_pool_init(&pgsql_job_pool, "pgsql_job_pool", sizeof(struct pgsql_job), 100);
    cf_mem_pool_init(&pgsql_wait_pool, "pgsql_wait_pool", sizeof(struct pgsql_wait), 100);
}
/************************************************************************
 *  Helper function PGSQL system cleanup
 ************************************************************************/
void cf_pgsql_sys_cleanup( void )
{
    struct pgsql_conn *conn, *next;

    cf_mem_pool_cleanup( &pgsql_job_pool );
    cf_mem_pool_cleanup( &pgsql_wait_pool );

    for(conn = TAILQ_FIRST(&pgsql_conn_free); conn != NULL; conn = next)
    {
        next = TAILQ_NEXT(conn, list);
        pgsql_conn_cleanup(conn);
    }
}
/************************************************************************
 *  Helper function PGSQL connection initialization
 ************************************************************************/
void cf_pgsql_init( struct cf_pgsql *pgsql )
{
    memset(pgsql, 0, sizeof(*pgsql));
    pgsql->state = CF_PGSQL_STATE_INIT;
}
/************************************************************************
 *  Helper function PGSQL connection setup
 ************************************************************************/
int cf_pgsql_setup( struct cf_pgsql *pgsql, const char *dbname, int flags )
{
    struct pgsql_db	*db = NULL;

    if( (flags & CF_PGSQL_ASYNC) && (flags & CF_PGSQL_SYNC) )
    {
        pgsql_set_error(pgsql, "invalid query init parameters");
        return CF_RESULT_ERROR;
    }

    if( flags & CF_PGSQL_ASYNC )
    {
        if( pgsql->req == NULL && pgsql->cb == NULL )
        {
            pgsql_set_error(pgsql, "nothing was bound");
            return CF_RESULT_ERROR;
        }
    }

    pgsql->flags |= flags;

    LIST_FOREACH(db, &pgsql_db_conn_strings, rlist)
    {
        if( !strcmp(db->name, dbname) )
            break;
    }

    if( db == NULL )
    {
        pgsql_set_error(pgsql, "no database found");
        return CF_RESULT_ERROR;
    }

    if( (pgsql->conn = pgsql_conn_next(pgsql, db)) == NULL )
        return CF_RESULT_ERROR;

    if( pgsql->flags & CF_PGSQL_ASYNC )
    {
        pgsql->conn->job = cf_mem_pool_get(&pgsql_job_pool);
        pgsql->conn->job->pgsql = pgsql;
    }

    return CF_RESULT_OK;
}
/************************************************************************
 *  Helper function to bind PGSQL connection to HTTP request
 ************************************************************************/
#ifndef CF_NO_HTTP
void cf_pgsql_bind_request( struct cf_pgsql *pgsql, struct http_request *req )
{
    if( pgsql->req != NULL || pgsql->cb != NULL )
        cf_fatal("cf_pgsql_bind_request: already bound");

    pgsql->req = req;
    pgsql->flags |= PGSQL_LIST_INSERTED;

    LIST_INSERT_HEAD(&(req->pgsqls), pgsql, rlist);
}
#endif
/************************************************************************
 *  Set callback function to notify with PGSQL status change
 ************************************************************************/
void cf_pgsql_bind_callback( struct cf_pgsql *pgsql, void (*cb)(struct cf_pgsql *, void *), void *arg )
{
    if( pgsql->req != NULL )
        cf_fatal("cf_pgsql_bind_callback: already bound");

    if( pgsql->cb != NULL )
        cf_fatal("cf_pgsql_bind_callback: already bound");

    pgsql->cb = cb;
    pgsql->arg = arg;
}
/************************************************************************
 *  Make request (query) to PQSQL server
 ************************************************************************/
int cf_pgsql_query( struct cf_pgsql *pgsql, const char *query )
{
    if( pgsql->conn == NULL )
    {
		pgsql_set_error(pgsql, "no connection was set before query");
        return CF_RESULT_ERROR;
	}

    if( pgsql->flags & CF_PGSQL_SYNC )
    {
		pgsql->result = PQexec(pgsql->conn->db, query);

        if( (PQresultStatus(pgsql->result) != PGRES_TUPLES_OK) &&
            (PQresultStatus(pgsql->result) != PGRES_COMMAND_OK))
        {
			pgsql_set_error(pgsql, PQerrorMessage(pgsql->conn->db));
            return CF_RESULT_ERROR;
		}

        pgsql->state = CF_PGSQL_STATE_DONE;
    }
    else
    {
        if( !PQsendQuery(pgsql->conn->db, query) )
        {
			pgsql_set_error(pgsql, PQerrorMessage(pgsql->conn->db));
            return CF_RESULT_ERROR;
		}

		pgsql_schedule(pgsql);
	}

    return CF_RESULT_OK;
}
/************************************************************************
 *  Make request (query) to PQSQL server
 ************************************************************************/
int cf_pgsql_v_query_params( struct cf_pgsql *pgsql, const char *query, int result, uint8_t count, va_list args )
{
	uint8_t	i;
    char **values;
    int	*lengths, *formats, ret;

    if( pgsql->conn == NULL )
    {
		pgsql_set_error(pgsql, "no connection was set before query");
        return CF_RESULT_ERROR;
	}

    if( count > 0 )
    {
        lengths = mem_calloc(count, sizeof(int));
        formats = mem_calloc(count, sizeof(int));
        values = mem_calloc(count, sizeof(char *));

        for( i = 0; i < count; i++ )
        {
			values[i] = va_arg(args, void *);
            lengths[i] = va_arg(args, int);
			formats[i] = va_arg(args, int);
		}
    }
    else
    {
		lengths = NULL;
		formats = NULL;
		values = NULL;
	}

    ret = CF_RESULT_ERROR;

    if( pgsql->flags & CF_PGSQL_SYNC )
    {
		pgsql->result = PQexecParams(pgsql->conn->db, query, count,
		    NULL, (const char * const *)values, lengths, formats,
		    result);

        if( (PQresultStatus(pgsql->result) != PGRES_TUPLES_OK) &&
            (PQresultStatus(pgsql->result) != PGRES_COMMAND_OK))
        {
			pgsql_set_error(pgsql, PQerrorMessage(pgsql->conn->db));
		}
        else
        {
            pgsql->state = CF_PGSQL_STATE_DONE;
            ret = CF_RESULT_OK;
        }
    }
    else
    {
        if( !PQsendQueryParams(pgsql->conn->db, query, count, NULL,
            (const char * const *)values, lengths, formats, result) )
        {
			pgsql_set_error(pgsql, PQerrorMessage(pgsql->conn->db));
		}
        else
        {
            ret = CF_RESULT_OK;
            pgsql_schedule( pgsql );
        }
	}

    mem_free(values);
    mem_free(lengths);
    mem_free(formats);

    return ret;
}
/************************************************************************
 *  Make request to PQSQL server
 ************************************************************************/
int cf_pgsql_query_params(struct cf_pgsql *pgsql, const char *query, int result, uint8_t count, ...)
{
    int	ret;
    va_list	args;

	va_start(args, count);
    ret = cf_pgsql_v_query_params(pgsql, query, result, count, args);
	va_end(args);

    return ret;
}
/************************************************************************
 *  Helper function to register PQSQL new one connection
 ************************************************************************/
int cf_pgsql_register( const char *dbname, const char *connstring )
{
    struct pgsql_db	*pgsqldb = NULL;

    LIST_FOREACH(pgsqldb, &pgsql_db_conn_strings, rlist)
    {
        if( !strcmp(pgsqldb->name, dbname) )
            return CF_RESULT_ERROR;
	}

    pgsqldb = mem_malloc(sizeof(*pgsqldb));
    pgsqldb->name = mem_strdup(dbname);
    pgsqldb->conn_count = 0;
    pgsqldb->conn_max = server.pgsql_conn_max;
    pgsqldb->conn_string = mem_strdup(connstring);
	LIST_INSERT_HEAD(&pgsql_db_conn_strings, pgsqldb, rlist);

    return CF_RESULT_OK;
}
/************************************************************************
 *  PQSQL default handler callback function
 ************************************************************************/
void cf_pgsql_handle( void *c, int err )
{
    struct cf_pgsql	*pgsql = NULL;
    struct pgsql_conn *conn = (struct pgsql_conn *)c;

    if( err )
    {
		pgsql_conn_cleanup(conn);
		return;
	}

	pgsql = conn->job->pgsql;

    if( !PQconsumeInput(conn->db) )
    {
        pgsql->state = CF_PGSQL_STATE_ERROR;
        pgsql->error = mem_strdup(PQerrorMessage(conn->db));
    }
    else
    {
		pgsql_read_result(pgsql);
	}

    if( pgsql->state == CF_PGSQL_STATE_WAIT )
    {
#ifndef CF_NO_HTTP
        if( pgsql->req != NULL )
            http_request_sleep(pgsql->req);
#endif
        if( pgsql->cb != NULL )
            pgsql->cb(pgsql, pgsql->arg);
    }
    else
    {
#ifndef CF_NO_HTTP
        if( pgsql->req != NULL )
            http_request_wakeup(pgsql->req);
#endif
        if( pgsql->cb != NULL )
            pgsql->cb(pgsql, pgsql->arg);
	}
}
/************************************************************************
 *  Helper function to continue PGSQL query
 ************************************************************************/
void cf_pgsql_continue( struct cf_pgsql *pgsql )
{
    if( pgsql->error )
    {
        mem_free(pgsql->error);
        pgsql->error = NULL;
    }

    if( pgsql->result )
    {
        PQclear(pgsql->result);
        pgsql->result = NULL;
    }

    switch( pgsql->state )
    {
    case CF_PGSQL_STATE_INIT:
    case CF_PGSQL_STATE_WAIT:
        break;
    case CF_PGSQL_STATE_DONE:
#ifndef CF_NO_HTTP
        if( pgsql->req != NULL )
            http_request_wakeup(pgsql->req);
#endif
        pgsql_conn_release(pgsql);
        break;
    case CF_PGSQL_STATE_ERROR:
    case CF_PGSQL_STATE_RESULT:
    case CF_PGSQL_STATE_NOTIFY:
        cf_pgsql_handle(pgsql->conn, 0);
        break;
    default:
        cf_fatal("unknown pgsql state %d", pgsql->state);
    }
}
/************************************************************************
 *  Helper function PGSQL query cleanup
 ************************************************************************/
void cf_pgsql_cleanup( struct cf_pgsql *pgsql )
{
    log_debug("cf_pgsql_cleanup(%p)", pgsql);

    pgsql_queue_remove( pgsql );

    if( pgsql->result != NULL )
		PQclear(pgsql->result);

    if( pgsql->error != NULL )
        mem_free( pgsql->error );

    if( pgsql->conn != NULL )
		pgsql_conn_release(pgsql);

	pgsql->result = NULL;
	pgsql->error = NULL;
	pgsql->conn = NULL;

    if( pgsql->flags & PGSQL_LIST_INSERTED )
    {
		LIST_REMOVE(pgsql, rlist);
		pgsql->flags &= ~PGSQL_LIST_INSERTED;
	}
}
/************************************************************************
 *  Helper function to log out PGSQL error
 ************************************************************************/
void cf_pgsql_logerror( struct cf_pgsql *pgsql )
{
    cf_log(LOG_NOTICE, "pgsql error: %s", (pgsql->error) ? pgsql->error : "unknown");
}

int cf_pgsql_ntuples( struct cf_pgsql *pgsql )
{
    return PQntuples(pgsql->result);
}

int cf_pgsql_nfields( struct cf_pgsql *pgsql )
{
    return PQnfields( pgsql->result );
}

int cf_pgsql_getlength( struct cf_pgsql *pgsql, int row, int col )
{
    return PQgetlength(pgsql->result, row, col);
}

char* cf_pgsql_fieldname( struct cf_pgsql *pgsql, int field )
{
    return (PQfname(pgsql->result, field));
}

char* cf_pgsql_getvalue( struct cf_pgsql *pgsql, int row, int col )
{
    return PQgetvalue(pgsql->result, row, col);
}
/************************************************************************
 *  Helper function to get PGSQL connection structure
 ************************************************************************/
static struct pgsql_conn* pgsql_conn_next( struct cf_pgsql *pgsql, struct pgsql_db *db )
{
    PGTransactionStatusType	state;
    struct pgsql_conn *conn = NULL;
    struct cf_pgsql	rollback;

    while( 1 )
    {
        conn = NULL;

        TAILQ_FOREACH(conn, &pgsql_conn_free, list)
        {
            if( !(conn->flags & PGSQL_CONN_FREE ))
                cf_fatal("got a pgsql connection that was not free?");
            if( !strcmp(conn->name, db->name) )
                break;
        }

        if( conn != NULL )
        {
            if( (state = PQtransactionStatus(conn->db)) == PQTRANS_INERROR )
            {
                conn->flags &= ~PGSQL_CONN_FREE;
                TAILQ_REMOVE( &pgsql_conn_free, conn, list );

                cf_pgsql_init( &rollback );
                rollback.conn = conn;
                rollback.flags = CF_PGSQL_SYNC;

                if( !cf_pgsql_query(&rollback, "ROLLBACK") )
                {
                    cf_pgsql_logerror( &rollback );
                    cf_pgsql_cleanup( &rollback );
                    pgsql_conn_cleanup(conn);
                }
                else
                    cf_pgsql_cleanup( &rollback );

                continue;
            }
        }

        break;
    }

    if( conn == NULL )
    {
        if( db->conn_max != 0 && db->conn_count >= db->conn_max )
        {
            if( (pgsql->flags & CF_PGSQL_ASYNC) &&
                    server.pgsql_queue_count < server.pgsql_queue_limit )
                pgsql_queue_add( pgsql );
            else
                pgsql_set_error(pgsql,"no available connection");

            return NULL;
        }

        if( (conn = pgsql_conn_create(pgsql, db)) == NULL )
            return NULL;
    }

	conn->flags &= ~PGSQL_CONN_FREE;
	TAILQ_REMOVE(&pgsql_conn_free, conn, list);

    return conn;
}
/************************************************************************
 *  Helper function PGSQL set error result string
 ************************************************************************/
static void pgsql_set_error( struct cf_pgsql *pgsql, const char *msg )
{
    if( pgsql->error != NULL )
        mem_free(pgsql->error);

    pgsql->error = mem_strdup(msg);
    pgsql->state = CF_PGSQL_STATE_ERROR;
}
/************************************************************************
 *  Helper function PGSQL schedule
 ************************************************************************/
static void pgsql_schedule( struct cf_pgsql *pgsql )
{
    int	fd = PQsocket(pgsql->conn->db);

    if( fd < 0 )
		cf_fatal("PQsocket returned < 0 fd on open connection");

    cf_platform_schedule_read(fd, pgsql->conn);
    pgsql->state = CF_PGSQL_STATE_WAIT;
    pgsql->flags |= CF_PGSQL_SCHEDULED;

#ifndef CF_NO_HTTP
    if( pgsql->req != NULL )
        http_request_sleep( pgsql->req );
#endif

    if( pgsql->cb != NULL )
        pgsql->cb(pgsql, pgsql->arg);
}
/************************************************************************
 *  Helper function PGSQL add to wait queue
 ************************************************************************/
static void pgsql_queue_add( struct cf_pgsql *pgsql )
{
    struct pgsql_wait *pgw = NULL;

#ifndef CF_NO_HTTP
    if( pgsql->req != NULL )
        http_request_sleep( pgsql->req );
#endif

    pgw = cf_mem_pool_get(&pgsql_wait_pool);
    pgw->pgsql = pgsql;

    server.pgsql_queue_count++;
	TAILQ_INSERT_TAIL(&pgsql_wait_queue, pgw, list);
}
/************************************************************************
 *  Remove PGSQL item from wait queue
 ************************************************************************/
static void pgsql_queue_remove( struct cf_pgsql *pgsql )
{
    struct pgsql_wait *pgw, *next;

    for( pgw = TAILQ_FIRST(&pgsql_wait_queue); pgw != NULL; pgw = next)
    {
		next = TAILQ_NEXT(pgw, list);
		if( pgw->pgsql != pgsql )
			continue;

        server.pgsql_queue_count--;
        TAILQ_REMOVE( &pgsql_wait_queue, pgw, list );
        cf_mem_pool_put( &pgsql_wait_pool, pgw );
		return;
	}
}
/************************************************************************
 *  Helper function to wakeup PGSQL query, when new free connection
 *  is available
 ************************************************************************/
static void pgsql_queue_wakeup( void )
{
    struct pgsql_wait *pgw, *next;

    for( pgw = TAILQ_FIRST(&pgsql_wait_queue); pgw != NULL; pgw = next )
    {
		next = TAILQ_NEXT(pgw, list);

#ifndef CF_NO_HTTP
        if( pgw->pgsql->req != NULL )
        {
            if( pgw->pgsql->req->flags & HTTP_REQUEST_DELETE )
            {
                server.pgsql_queue_count--;
                TAILQ_REMOVE(&pgsql_wait_queue, pgw, list);
                cf_mem_pool_put( &pgsql_wait_pool, pgw );
                continue;
            }

            http_request_wakeup(pgw->pgsql->req);
        }
#endif

        if( pgw->pgsql->cb != NULL )
            pgw->pgsql->cb(pgw->pgsql, pgw->pgsql->arg);

        server.pgsql_queue_count--;
		TAILQ_REMOVE(&pgsql_wait_queue, pgw, list);
        cf_mem_pool_put( &pgsql_wait_pool, pgw );
		return;
	}
}
/************************************************************************
 *  Helper function to create PGSQL new one connection
 ************************************************************************/
static struct pgsql_conn* pgsql_conn_create( struct cf_pgsql *pgsql, struct pgsql_db *db )
{
    struct pgsql_conn *conn = NULL;

    if( db == NULL || db->conn_string == NULL )
		cf_fatal("pgsql_conn_create: no connection string");

    db->conn_count++;

    conn = mem_malloc(sizeof(*conn));
	conn->job = NULL;
	conn->flags = PGSQL_CONN_FREE;
    conn->type = CF_TYPE_PGSQL_CONN;
    conn->name = mem_strdup(db->name);
	TAILQ_INSERT_TAIL(&pgsql_conn_free, conn, list);

    log_debug("pgsql_conn_create(): %p", conn);

    conn->db = PQconnectdb(db->conn_string);

    if( conn->db == NULL || (PQstatus(conn->db) != CONNECTION_OK) )
    {
        pgsql_set_error(pgsql, PQerrorMessage(conn->db));
        pgsql_conn_cleanup(conn);
        return NULL;
    }

    return conn;
}
/************************************************************************
 *  Helper function to release PGSQL server connection and move to
 *  free connection's list
 ************************************************************************/
static void pgsql_conn_release( struct cf_pgsql *pgsql )
{
    int	fd;
    PGresult* result = NULL;

    if( pgsql->conn == NULL )
		return;

	/* Async query cleanup */
    if( pgsql->flags & CF_PGSQL_ASYNC )
    {
        if( pgsql->flags & CF_PGSQL_SCHEDULED )
        {
			fd = PQsocket(pgsql->conn->db);
            cf_platform_disable_events( fd );

            if( pgsql->state != CF_PGSQL_STATE_DONE )
                pgsql_cancel(pgsql);
		}

        cf_mem_pool_put(&pgsql_job_pool, pgsql->conn->job);
	}

    /* Drain just in case */
    while( (result = PQgetResult(pgsql->conn->db)) != NULL ) {
        PQclear( result );
    }

	pgsql->conn->job = NULL;
	pgsql->conn->flags |= PGSQL_CONN_FREE;
	TAILQ_INSERT_TAIL(&pgsql_conn_free, pgsql->conn, list);

	pgsql->conn = NULL;
    pgsql->state = CF_PGSQL_STATE_COMPLETE;

    if( pgsql->cb != NULL ) {
        pgsql->cb(pgsql, pgsql->arg);
    }

	pgsql_queue_wakeup();
}
/************************************************************************
 *  Clean up PGSQL database connection
 ************************************************************************/
static void pgsql_conn_cleanup( struct pgsql_conn *conn )
{
    struct cf_pgsql	*pgsql = NULL;
    struct pgsql_db	*pgsqldb = NULL;

    log_debug("pgsql_conn_cleanup(): %p", conn);

    if( conn->flags & PGSQL_CONN_FREE )
		TAILQ_REMOVE(&pgsql_conn_free, conn, list);

    if( conn->job )
    {
		pgsql = conn->job->pgsql;

#ifndef CF_NO_HTTP
        if( pgsql->req != NULL )
            http_request_wakeup( pgsql->req );
#endif

		pgsql->conn = NULL;
		pgsql_set_error(pgsql, PQerrorMessage(conn->db));

        cf_mem_pool_put(&pgsql_job_pool, conn->job);
		conn->job = NULL;
	}

    if( conn->db != NULL )
		PQfinish(conn->db);

    LIST_FOREACH(pgsqldb, &pgsql_db_conn_strings, rlist)
    {
        if( strcmp(pgsqldb->name, conn->name) )
        {
            pgsqldb->conn_count--;
            break;
        }
    }

    mem_free(conn->name);
    mem_free(conn);
}
/************************************************************************
 *  Helper function read result from PGSQL query
 ************************************************************************/
static void pgsql_read_result( struct cf_pgsql *pgsql )
{
    PGnotify *notify = NULL;

    if( PQisBusy(pgsql->conn->db) )
    {
        pgsql->state = CF_PGSQL_STATE_WAIT;
		return;
	}

    while( (notify = PQnotifies(pgsql->conn->db)) != NULL )
    {
        pgsql->state = CF_PGSQL_STATE_NOTIFY;
        pgsql->notify.extra = notify->extra;
        pgsql->notify.channel = notify->relname;

        if( pgsql->cb != NULL )
            pgsql->cb(pgsql, pgsql->arg);

        PQfreemem(notify);
    }

    pgsql->result = PQgetResult(pgsql->conn->db);

    if( pgsql->result == NULL )
    {
        pgsql->state = CF_PGSQL_STATE_DONE;
        return;
    }

    switch( PQresultStatus(pgsql->result) )
    {
    case PGRES_COPY_OUT:
    case PGRES_COPY_IN:
    case PGRES_NONFATAL_ERROR:
    case PGRES_COPY_BOTH:
        break;
    case PGRES_COMMAND_OK:
        pgsql->state = CF_PGSQL_STATE_DONE;
        break;
    case PGRES_TUPLES_OK:
#if PG_VERSION_NUM >= 90200
    case PGRES_SINGLE_TUPLE:
#endif
        pgsql->state = CF_PGSQL_STATE_RESULT;
        break;
    case PGRES_EMPTY_QUERY:
    case PGRES_BAD_RESPONSE:
    case PGRES_FATAL_ERROR:
        pgsql_set_error(pgsql, PQresultErrorMessage(pgsql->result));
        break;
    }
}
/************************************************************************
 *  Helper function to cancel PGSQL query
 ************************************************************************/
static void pgsql_cancel( struct cf_pgsql *pgsql )
{
    PGcancel *cancel = NULL;
    char buf[256];

    if( (cancel = PQgetCancel(pgsql->conn->db)) != NULL )
    {
        if( !PQcancel(cancel, buf, sizeof(buf)) )
            cf_log(LOG_ERR, "failed to cancel: %s", buf);
        PQfreeCancel(cancel);
    }
}


