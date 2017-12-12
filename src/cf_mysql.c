// cf_mysql.c

#include <sys/param.h>
#include <sys/queue.h>

#include "zfrog.h"
#include "cf_http.h"
#include "cf_mysql.h"

struct mysql_job
{
	struct http_request	*req;
    struct cf_mysql     *mysql;

	TAILQ_ENTRY(mysql_job)	list;
};

struct mysql_wait
{
    struct http_request	*req;
    TAILQ_ENTRY(mysql_wait)	list;
};


#define MYSQL_CONN_FREE         0x01
#define MYSQL_LIST_INSERTED     0x0100

static void	mysql_queue_wakeup();
static void	mysql_set_error(struct cf_mysql *, const char *);
static void	mysql_queue_add(struct http_request *);
static void	mysql_conn_release(struct cf_mysql *);
static void	mysql_conn_cleanup(struct mysql_conn *);
static void	mysql_read_result(struct cf_mysql *);
static void	mysql_schedule(struct cf_mysql *);

static struct mysql_conn *mysql_conn_create(struct cf_mysql *, struct mysql_db *);
static struct mysql_conn *mysql_conn_next(struct cf_mysql *, struct mysql_db *, struct http_request *);

static struct cf_pool mysql_job_pool;
static struct cf_pool mysql_wait_pool;

static TAILQ_HEAD(, mysql_conn)		mysql_conn_free;
static TAILQ_HEAD(, mysql_wait)		mysql_wait_queue;
static LIST_HEAD(, mysql_db)		mysql_db_conn;

static uint16_t mysql_conn_count;

void cf_mysql_sys_init( void )
{
	mysql_conn_count = 0;
	TAILQ_INIT(&mysql_conn_free);
	TAILQ_INIT(&mysql_wait_queue);
	LIST_INIT(&mysql_db_conn);

    cf_pool_init(&mysql_job_pool, "mysql_job_pool", sizeof(struct mysql_job), 100);
    cf_pool_init(&mysql_wait_pool, "mysql_wait_pool", sizeof(struct mysql_wait), 100);
}

int cf_mysql_query_init( struct cf_mysql *mysql, struct http_request *req,
                         const char *host, const char *user, const char *passwd, const char *dbname,
                         unsigned int port, const char *unix_socket,
                         unsigned long client_flags, int connector_flags )
{
    struct mysql_db	*db = NULL;

	memset(mysql, 0, sizeof(*mysql));
	mysql->connector_flags = connector_flags;
    mysql->state = CF_MYSQL_STATE_INIT;

    if( (req == NULL && (flags & CF_MYSQL_ASYNC)) || ((flags & CF_MYSQL_ASYNC) && (flags & CF_MYSQL_SYNC)) )
    {
		mysql_set_error(mysql, "Invalid query init parameters");
        return CF_RESULT_ERROR;
	}

    LIST_FOREACH(db, &mysql_db_conn, rlist)
    {
        if( !strcmp(db->host, host) ||
			!strcmp(db->user, user) ||
			!strcmp(db->passwd, passwd) ||
            !strcmp(db->dbname, dbname) )
			break;

        if( (db->port != port) && !strcmp(db->unix_socket, unix_socket) )
			break;
	}

    if( db == NULL )
    {
		mysql_set_error(mysql, "No database found");
        return CF_RESULT_ERROR;
	}

	
    if( (mysql->conn = mysql_conn_next(mysql, db, req)) == NULL )
        return CF_RESULT_ERROR;

    if( mysql->flags & CF_MYSQL_ASYNC )
    {
        mysql->conn->job = cf_mem_pool_get(&mysql_job_pool);
		mysql->conn->job->req = req;
		mysql->conn->job->mysql = mysql;

		http_request_sleep(req);
		mysql->flags |= MYSQL_LIST_INSERTED;
		LIST_INSERT_HEAD(&(req->mysqls), mysql, rlist);
	}

    return CF_RESULT_OK;
}

int cf_mysql_query( struct cf_mysql *mysql, const char *query )
{
    if( mysql->conn == NULL )
    {
        mysql_set_error(mysql, "No connection was set before query");
        return CF_RESULT_ERROR;
	}

    if( mysql->flags & CF_MYSQL_SYNC )
    {
        if( mysql_query(mysql->conn->mysql, query) != 0 )
        {
			mysql_set_error(mysql, mysql_error(mysql->conn->mysql));
            return CF_RESULT_ERROR;
		}

        mysql->result = mysql_store_result(mysql->conn->mysql);
		mysql->result = PQexec(mysql->conn->db, query);

        mysql->state = CF_MYSQL_STATE_DONE;
    }
    else
    {
        if( mysql_query(mysql->conn->mysql, query) != 0 )
        {
			mysql_set_error(mysql, mysql_error(mysql->conn->mysql));
            return CF_RESULT_ERROR;
		}

        mysql_schedule( mysql );
	}

    return CF_RESULT_OK;
}

int cf_mysql_register(const char *dbname, const char *connstring)
{
    struct mysql_db	*mysqldb = NULL;

    LIST_FOREACH(mysqldb, &mysql_db_conn_strings, rlist)
    {
        if( !strcmp(mysqldb->name, dbname) )
            return CF_RESULT_ERROR;
	}

    mysqldb = cf_malloc(sizeof(*mysqldb));
    mysqldb->name = mem_strdup(dbname);
    mysqldb->conn_string = mem_strdup( connstring );
	LIST_INSERT_HEAD(&mysql_db_conn_strings, mysqldb, rlist);

    return CF_RESULT_OK;
}

void cf_mysql_handle(void *c, int err)
{
    struct http_request	*req = NULL;
    struct cf_mysql	*mysql = NULL;
    struct mysql_conn *conn = (struct mysql_conn *)c;

    if( err )
    {
		mysql_conn_cleanup(conn);
		return;
	}

	req = conn->job->req;
	mysql = conn->job->mysql;
    cf_debug("cf_mysql_handle: %p (%d)", req, mysql->state);

    if( !PQconsumeInput(conn->db) )
    {
        mysql->state = CF_MYSQL_STATE_ERROR;
        mysql->error = mem_strdup( PQerrorMessage(conn->db) );
    }
    else
		mysql_read_result(mysql);

    if( mysql->state == CF_MYSQL_STATE_WAIT )
		http_request_sleep(req);
    else
		http_request_wakeup(req);
}

void cf_mysql_continue(struct http_request *req, struct cf_mysql *mysql)
{
    cf_debug("cf_mysql_continue: %p->%p (%d)", req->owner, req, mysql->state);

    if( mysql->error )
    {
        cf_mem_free(mysql->error);
		mysql->error = NULL;
	}

    if( mysql->result )
    {
		PQclear(mysql->result);
		mysql->result = NULL;
	}

    switch( mysql->state )
    {
    case CF_MYSQL_STATE_INIT:
    case CF_MYSQL_STATE_WAIT:
		break;
    case CF_MYSQL_STATE_DONE:
		http_request_wakeup(req);
		mysql_conn_release(mysql);
		break;
    case CF_MYSQL_STATE_ERROR:
    case CF_MYSQL_STATE_RESULT:
		cf_mysql_handle(mysql->conn, 0);
		break;
	default:
        cf_fatal("unknown mysql state %d", mysql->state);
	}
}

void cf_mysql_cleanup(struct cf_mysql *mysql)
{
    cf_debug("cf_mysql_cleanup(%p)", mysql);

    if( mysql->result != NULL )
		mysql_free_result(mysql->result);

    if( mysql->error != NULL )
        cf_mem_free(mysql->error);

    if( mysql->conn != NULL )
		mysql_conn_release(mysql);

	mysql->result = NULL;
	mysql->error = NULL;
	mysql->conn = NULL;

    if( mysql->flags & MYSQL_LIST_INSERTED )
    {
		LIST_REMOVE(mysql, rlist);
		mysql->flags &= ~MYSQL_LIST_INSERTED;
	}
}

void cf_mysql_logerror( struct cf_mysql *mysql )
{
    cf_log(LOG_NOTICE, "MySQL error: %s", (mysql->error) ? mysql->error : "unknown");
}

int cf_mysql_ntuples( struct cf_mysql *mysql )
{
    return PQntuples(mysql->result);
}

int cf_mysql_getlength( struct cf_mysql *mysql, int row, int col )
{
    return PQgetlength(mysql->result, row, col);
}

char* cf_mysql_getvalue( struct cf_mysql *mysql, int row, int col )
{
    return PQgetvalue(mysql->result, row, col);
}

void cf_mysql_queue_remove( struct http_request *req )
{
    struct mysql_wait *myw, *next;

    for( myw = TAILQ_FIRST(&mysql_wait_queue); myw != NULL; myw = next )
    {
		next = TAILQ_NEXT(myw, list);
        if( myw->req != req )
			continue;

		TAILQ_REMOVE(&mysql_wait_queue, myw, list);
        cf_pool_put(&mysql_wait_pool, myw);
		return;
	}
}

static struct mysql_conn* mysql_conn_next( struct cf_mysql *mysql, struct mysql_db *db, struct http_request *req )
{
    struct mysql_conn *conn = NULL;

    TAILQ_FOREACH(conn, &mysql_conn_free, list)
    {
        if( !(conn->flags & MYSQL_CONN_FREE) )
            cf_fatal("got a mysql connection that was not free?");

        if( !strcmp(conn->name, db->name) )
			break;
	}

    if( conn == NULL )
    {
        if( mysql_conn_count >= mysql_conn_max )
        {
            if( mysql->flags & CF_MYSQL_ASYNC )
				mysql_queue_add(req);
            else
				mysql_set_error(mysql,"no available connection");

            return NULL;
		}

        if( (conn = mysql_conn_create(mysql, db)) == NULL )
            return NULL;
	}

	conn->flags &= ~MYSQL_CONN_FREE;
	TAILQ_REMOVE(&mysql_conn_free, conn, list);

    return conn;
}

static void mysql_set_error(struct cf_mysql *mysql, const char *msg)
{
    if( mysql->error != NULL )
        cf_mem_free(mysql->error);

    mysql->error = mem_strdup(msg);
    mysql->state = CF_MYSQL_STATE_ERROR;
}

static void mysql_schedule( struct cf_mysql *mysql )
{
    int	fd = -1;

    fd = PQsocket( mysql->conn->db );
    if( fd < 0 )
		fatal("PQsocket returned < 0 fd on open connection");

    cf_platform_schedule_read(fd, mysql->conn);
    mysql->state = CF_MYSQL_STATE_WAIT;
}

static void mysql_queue_add( struct http_request *req )
{
    struct mysql_wait *myw = NULL;

	http_request_sleep(req);

    myw = cf_pool_get(&mysql_wait_pool);
	myw->req = req;
	myw->req->flags |= HTTP_REQUEST_MYSQL_QUEUE;

	TAILQ_INSERT_TAIL(&mysql_wait_queue, myw, list);
}

static void mysql_queue_wakeup()
{
    struct mysql_wait *myw, *next;

    for( myw = TAILQ_FIRST(&mysql_wait_queue); myw != NULL; myw = next )
    {
		next = TAILQ_NEXT(myw, list);
        if( myw->req->flags & HTTP_REQUEST_DELETE )
			continue;

        http_request_wakeup( myw->req );
		myw->req->flags &= ~HTTP_REQUEST_MYSQL_QUEUE;

		TAILQ_REMOVE(&mysql_wait_queue, myw, list);
        cf_pool_put(&mysql_wait_pool, myw);
		return;
	}
}

static struct mysql_conn* mysql_conn_create(struct cf_mysql *mysql, struct mysql_db *db)
{
    struct mysql_conn *conn = NULL;

    if( db == NULL || db->host == NULL || db->user == NULL || db->passwd == NULL || db->dbname == NULL )
            if( db->port == 0 || db->unix_socket == NULL )
                cf_fatal("mysql_conn_create: No connection data.");

	mysql_conn_count++;
    conn = cf_malloc(sizeof(*conn));
    cf_debug("mysql_conn_create(): %p", conn);

	conn->mysql = mysql_init(conn->mysql);

    if( conn->mysql == NULL )
    {
		mysql_set_error(mysql, mysql_error(conn->mysql));
		mysql_conn_cleanup(conn);
        return NULL;
	}
	
    if( mysql_real_connect(conn->mysql, db->host, db->user, db->passwd, db->dbname, db->port, db->unix_socket, db->flags) == NULL)
    {
		mysql_set_error(mysql, mysql_error(conn->mysql));
		mysql_conn_cleanup(conn);
        return NULL;
	}	

	conn->job = NULL;
	conn->flags = MYSQL_CONN_FREE;
    conn->type = CF_TYPE_MYSQL_CONN;
    conn->name = mem_strdup(db->name);
	TAILQ_INSERT_TAIL(&mysql_conn_free, conn, list);

    return conn;
}

static void mysql_conn_release( struct cf_mysql *mysql )
{
    int	fd;

    if( mysql->conn == NULL )
		return;

	/* Async query cleanup */
    if( mysql->flags & CF_MYSQL_ASYNC )
    {
        if( mysql->conn != NULL )
        {
			fd = PQsocket(mysql->conn->db);
            cf_platform_disable_events(fd);
            cf_pool_put( &mysql_job_pool, mysql->conn->job );
		}
	}

    /* Drain just in case */
    while( PQgetResult(mysql->conn->db) != NULL )
		;

	mysql->conn->job = NULL;
	mysql->conn->flags |= MYSQL_CONN_FREE;
	TAILQ_INSERT_TAIL(&mysql_conn_free, mysql->conn, list);

	mysql->conn = NULL;
    mysql->state = CF_MYSQL_STATE_COMPLETE;

	mysql_queue_wakeup();
}

static void mysql_conn_cleanup( struct mysql_conn *conn )
{
    struct http_request	*req = NULL;
    struct cf_mysql	*mysql = NULL;

    cf_debug("mysql_conn_cleanup(): %p", conn);

    if( conn->flags & MYSQL_CONN_FREE )
		TAILQ_REMOVE(&mysql_conn_free, conn, list);

    if( conn->job )
    {
		req = conn->job->req;
		mysql = conn->job->mysql;
		http_request_wakeup(req);

		mysql->conn = NULL;
		mysql_set_error(mysql, PQerrorMessage(conn->db));

        cf_pool_put(&mysql_job_pool, conn->job);
		conn->job = NULL;
	}

    if( conn->db != NULL )
        PQfinish( conn->db );

	mysql_conn_count--;
    cf_mem_free( conn->name );
    cf_mem_free( conn );
}

static void mysql_read_result( struct cf_mysql *mysql )
{
    if( PQisBusy(mysql->conn->db) )
    {
        mysql->state = CF_MYSQL_STATE_WAIT;
		return;
	}

	mysql->result = PQgetResult(mysql->conn->db);

    if( mysql->result == NULL )
    {
        mysql->state = CF_MYSQL_STATE_DONE;
		return;
	}

    switch( PQresultStatus(mysql->result) )
    {
	case MYRES_COPY_OUT:
	case MYRES_COPY_IN:
	case MYRES_NONFATAL_ERROR:
	case MYRES_COPY_BOTH:
		break;
	case MYRES_COMMAND_OK:
        mysql->state = CF_MYSQL_STATE_DONE;
		break;
	case MYRES_TUPLES_OK:
#if MY_VERSION_NUM >= 90200
	case MYRES_SINGLE_TUPLE:
#endif
        mysql->state = CF_MYSQL_STATE_RESULT;
		break;
	case MYRES_EMPTY_QUERY:
	case MYRES_BAD_RESPONSE:
	case MYRES_FATAL_ERROR:
		mysql_set_error(mysql, PQresultErrorMessage(mysql->result));
		break;
	}
}
