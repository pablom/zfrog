#include <time.h>
#include <locale.h>
#include <xlocale.h>
#include <yajl/yajl_gen.h>
#include <yajl/yajl_tree.h>
#include <zfrog.h>
#include <cf_http.h>
#include <cf_jsonrpc.h>
#include <cf_redis.h>

// socat -v UNIX-LISTEN:/tmp/redisserv,fork,reuseaddr TCP4:10.101.128.104:6379

#define REQ_STATE_INIT			0
#define REQ_STATE_QUERY			1
#define REQ_STATE_DB_WAIT		2
#define REQ_STATE_DB_READ		3
#define REQ_STATE_ERROR			4
#define REQ_STATE_DONE			5

int	v1(struct http_request *req);

static int	request_perform_init(struct http_request *http_req);
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
    uint8_t*        redis_cmd;
    struct jsonrpc_request  json_req;
};
/*---------------------------------------------------------------------------*/
static int check_jsonrpc_request( struct jsonrpc_request *req, uint8_t** r_cmd )
{
    if( req )
    {
        const char *key_path[] = {"key", NULL};
        const char *val_path[] = {"value", NULL};
        yajl_val key;
        yajl_val val;

        if( !strcmp(req->method, "set") )
        {
            if( YAJL_IS_OBJECT(req->params) )
            {
                key = yajl_tree_get(req->params, key_path, yajl_t_string);
                val = yajl_tree_get(req->params, val_path, yajl_t_string);

                if( key && val )
                {
                    cf_redis_format_command(r_cmd, "SET %s %s", YAJL_GET_STRING(key), YAJL_GET_STRING(val));
                    return 0;
                }
            }

            return -2;
        }
        else if( !strcmp(req->method, "get") )
        {

        }
        else if( !strcmp(req->method, "info") )
        {

        }
    }

    return -1;
}
/*---------------------------------------------------------------------------*/
static int write_string( struct jsonrpc_request *req, void *ctx )
{
	const unsigned char *str = (unsigned char *)ctx;

	return yajl_gen_string(req->gen, str, strlen((const char *)str));
}
/*---------------------------------------------------------------------------*/
static int write_string_array_params( struct jsonrpc_request *req, void *ctx )
{
	int status = 0;

	if( !YAJL_GEN_KO(status = yajl_gen_array_open(req->gen)) ) 
	{
		for( size_t i = 0; i < req->params->u.array.len; i++ ) 
		{
			yajl_val yajl_str = req->params->u.array.values[i];
			char *str = YAJL_GET_STRING(yajl_str);

			if( YAJL_GEN_KO(status = yajl_gen_string(req->gen,(unsigned char *)str, strlen(str))) )
				break;
		}

		if( status == 0 )
			status = yajl_gen_array_close(req->gen);
	}

	return status;
}
/*---------------------------------------------------------------------------*/
int v1( struct http_request *req )
{
    /* First request */
    if( !http_state_exists(req) )
    {
        struct rstate *state = NULL;
        struct jsonrpc_request json_req;
        uint8_t* r_cmd = NULL;
        int ret;

        /* We only allow POST/PUT methods */
        if( req->method != HTTP_METHOD_POST &&
            req->method != HTTP_METHOD_PUT )
        {
            http_response_header(req, "allow", "POST, PUT");
            http_response(req, HTTP_STATUS_METHOD_NOT_ALLOWED, NULL, 0);
            return CF_RESULT_OK;
        }

        state = http_state_create(req, sizeof(*state));

        /* Read JSON-RPC request */
        if( (ret = jsonrpc_read_request(req, &(state->json_req))) != 0 )
            return jsonrpc_error(&(state->json_req), ret, NULL);

        /* Check allow methods & create Redis cmd */
        if( (ret = check_jsonrpc_request( &(state->json_req), &r_cmd)) )
        {
            if( ret == -1 )
                return jsonrpc_error(&(state->json_req), JSONRPC_METHOD_NOT_FOUND, NULL);

            return jsonrpc_error(&(state->json_req), JSONRPC_INVALID_PARAMS, NULL);
        }

        /* Setup our state context */
        //state = http_state_create(req, sizeof(*state));
        state->redis_cmd = r_cmd; /* Set redis cmd request */
        //state->json_req = json_req;

        /*
         * Initialize the cf_redis data structure and bind it
         * to this request so we can be put to sleep / woken up
         * by the redis layer when required
         */
        cf_redis_init( &state->rd );
        cf_redis_bind_request( &state->rd, req );
    }

    /* Drop into our state machine */
    cf_log(LOG_NOTICE, "%p: page start", (void *)req);
    return http_state_run(mystates, mystates_size, req);
}
/****************************************************************************
 *  Initialize our Redis data structure and prepare for an async query
 ****************************************************************************/
static int request_perform_init( struct http_request *req )
{
    struct rstate *state = http_state_get(req);

    /*
     * Setup the query to be asynchronous in nature, aka just fire it
     * off and return back to us.
     */
    if( !cf_redis_setup( &state->rd, "db", CF_REDIS_ASYNC) )
    {
        printf("\tredis state = %d\n", state->rd.state);

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
    struct rstate *state = http_state_get(req);

    /* We want to move to read result after this */
    req->fsm_state = REQ_STATE_DB_WAIT;

    /* Fire off the query */
    if( !cf_redis_query( &state->rd, state->redis_cmd, strlen(state->redis_cmd) ) )
    {
        /*
         * Let the state machine continue immediately since we
         * have an error anyway
         */
        return HTTP_STATE_CONTINUE;
    }

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
 * to continue until the redis API returns CF_REDIS_STATE_COMPLETE.
 ****************************************************************************/
static int request_db_read( struct http_request *req )
{
    struct rstate *state = http_state_get(req);

    /* Continue processing our query results */
    cf_redis_continue( &state->rd );

    /* Back to our DB waiting state */
    //req->fsm_state = REQ_STATE_DB_WAIT;

    req->fsm_state = REQ_STATE_DONE;

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

    if( state->redis_cmd )
        mem_free( state->redis_cmd );

    cf_redis_cleanup( &state->rd );
    http_state_cleanup(req);

    jsonrpc_result( &(state->json_req), write_string, state->rd.reply->str);

    //http_response(req, 200, NULL, 0);

    return HTTP_STATE_COMPLETE;
}


