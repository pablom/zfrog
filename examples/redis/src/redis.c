// redis.c

#if !defined(CF_NO_HTTP)

#include <zfrog.h>
#include <cf_http.h>
#include <cf_redis.h>

#define REQ_STATE_INIT			0
#define REQ_STATE_QUERY			1
#define REQ_STATE_DB_WAIT		2
#define REQ_STATE_DB_READ		3
#define REQ_STATE_ERROR			4
#define REQ_STATE_DONE			5

int page( struct http_request * );

static int	request_perform_init(struct http_request *);
static int	request_perform_query(struct http_request *);
static int	request_db_wait(struct http_request *);
static int	request_db_read(struct http_request *);
static int	request_error(struct http_request *);
static int	request_done(struct http_request *);

struct http_state	mystates[] =
{
	{ "REQ_STATE_INIT",		request_perform_init },
    { "REQ_STATE_QUERY",	request_perform_query },
    { "REQ_STATE_DB_WAIT",	request_db_wait },
    { "REQ_STATE_DB_READ",	request_db_read },
    { "REQ_STATE_ERROR",	request_error },
	{ "REQ_STATE_DONE",		request_done },
};

#define mystates_size		(sizeof(mystates) / sizeof(mystates[0]))

struct rstate
{
    int             cnt;
    struct cf_redis	rd;
};
/****************************************************************************
 *  Page handler entry point (see config)
 ****************************************************************************/
int page( struct http_request *req )
{
    /* Drop into our state machine */
    cf_log(LOG_NOTICE, "%p: page start", (void *)req);
    return http_state_run(mystates, mystates_size, req);
}
/****************************************************************************
 *  Initialize our Redis data structure and prepare for an async query
 ****************************************************************************/
static int request_perform_init( struct http_request *req )
{
    struct rstate *state = NULL;

    /* Setup our state context (if not yet set) */
    if( !http_state_exists(req) )
    {
		state = http_state_create(req, sizeof(*state));

		/*
         * Initialize the cf_redis data structure and bind it
		 * to this request so we can be put to sleep / woken up
         * by the redis layer when required
		 */
        cf_redis_init( &state->rd );
        cf_redis_bind_request( &state->rd, req );
    }
    else
    {
		state = http_state_get(req);
	}

	/*
	 * Setup the query to be asynchronous in nature, aka just fire it
	 * off and return back to us.
	 */
    if( !cf_redis_setup( &state->rd, "db", CF_REDIS_ASYNC) )
    {
        printf("\t state = %d\n", state->rd.state);

		/*
		 * If the state was still in INIT we need to go to sleep and
         * wait until the redis layer wakes us up again when there
		 * an available connection to the database.
		 */
        if( state->rd.state == CF_REDIS_STATE_INIT || state->rd.state == CF_REDIS_STATE_CONNECTING )
        {
			req->fsm_state = REQ_STATE_INIT;
            return HTTP_STATE_RETRY;
		}

        cf_redis_logerror( &state->rd );
		req->fsm_state = REQ_STATE_ERROR;
    }
    else
    {
		/*
		 * The initial setup was complete, go for query.
		 */
		req->fsm_state = REQ_STATE_QUERY;
	}

    return HTTP_STATE_CONTINUE;
}
/****************************************************************************
 *  After setting everything up we will execute our async query
 ****************************************************************************/
static int request_perform_query( struct http_request *req )
{
 //   struct rstate *state = http_state_get(req);

	/* We want to move to read result after this. */
	req->fsm_state = REQ_STATE_DB_WAIT;


#ifdef MMM
    /* Fire off the query */
    if( !cf_redis_query( &state->rd,"SELECT * FROM coders, pg_sleep(5)") )
    {
		/*
		 * Let the state machine continue immediately since we
		 * have an error anyway.
		 */
        return HTTP_STATE_CONTINUE;
	}
#endif

    /* Resume state machine later when the query results start coming in */
    return HTTP_STATE_RETRY;
}
/****************************************************************************
 * After firing off the query, we returned HTTP_STATE_RETRY (see above).
 * When request_db_wait() finally is called by zfrog we will have results
 * from pgsql so we'll process them.
 ****************************************************************************/
static int request_db_wait( struct http_request *req )
{
    struct rstate *state = http_state_get(req);

    cf_log(LOG_NOTICE, "request_db_wait: %d", state->rd.state);

    printf("state change on redis %d\n", state->rd.state);

	/*
     * When we get here, our asynchronous redis query has
	 * given us something, check the state to figure out what.
	 */
    switch( state->rd.state )
    {
    case CF_REDIS_STATE_WAIT:
        return HTTP_STATE_RETRY;
    case CF_REDIS_STATE_COMPLETE:
		req->fsm_state = REQ_STATE_DONE;
		break;
    case CF_REDIS_STATE_ERROR:
		req->fsm_state = REQ_STATE_ERROR;
        cf_redis_logerror( &state->rd );
		break;
    case CF_REDIS_STATE_RESULT:
		req->fsm_state = REQ_STATE_DB_READ;
		break;
	default:
        /* This MUST be present in order to advance the redis state */
        cf_redis_continue( &state->rd );
		break;
	}

    return HTTP_STATE_CONTINUE;
}
/****************************************************************************
 * Called when there's an actual result to be gotten. After we handle the
 * entire result, we'll drop back into REQ_STATE_DB_WAIT (above) in order
 * to continue until the pgsql API returns CF_PGSQL_STATE_COMPLETE.
 ****************************************************************************/
static int request_db_read( struct http_request *req )
{
//    char *name = NULL;
//    int	i, rows;
    struct rstate *state = http_state_get(req);

#ifdef MMM

	/* We have sql data to read! */
    rows = cf_pgsql_ntuples(&state->sql);
    for( i = 0; i < rows; i++ )
    {
        name = cf_pgsql_getvalue(&state->sql, i, 0);
        cf_log(LOG_NOTICE, "name: '%s'", name);
	}
#endif
    /* Continue processing our query results */
    cf_redis_continue( &state->rd );

    /* Back to our DB waiting state */
	req->fsm_state = REQ_STATE_DB_WAIT;
    return HTTP_STATE_CONTINUE;
}
/* An error occurred */
int request_error( struct http_request *req )
{
    struct rstate *state = http_state_get(req);

    cf_redis_cleanup( &state->rd );
	http_state_cleanup(req);

	http_response(req, 500, NULL, 0);

    return HTTP_STATE_COMPLETE;
}
/* Request was completed successfully */
static int request_done( struct http_request *req )
{
    struct rstate *state = http_state_get( req );

    cf_redis_cleanup( &state->rd );
	http_state_cleanup(req);

	http_response(req, 200, NULL, 0);

    return HTTP_STATE_COMPLETE;
}

#endif /* !CF_NO_HTTP */
