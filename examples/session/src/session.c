// session.c

#include "session.h"
#include "session_util.h"
#include "assets.h"

struct session_config *CONFIG;

struct http_state  session_states[] = {

    { "REQ_STATE_INIT",       session_state_init  },
    { "REQ_STATE_QUERY",      session_state_query },
    { "REQ_STATE_WAIT",       session_state_wait  },
    { "REQ_STATE_READ",       session_state_read  },

    { "REQ_STATE_ERROR",      state_error },
    { "REQ_STATE_DONE",       state_done  },
};

#define session_states_size (sizeof(session_states) \
    / sizeof(session_states[0]))

const char* session_state_text(int s)
{
    return session_states[s].name;
}

const char* sql_state_text( int s )
{   
    return SQL_STATE_NAMES[s];
}

const char* session_request_state(struct http_request * req)
{
    return session_state_text( req->fsm_state );
}

void session_delete_context( struct http_request *req )
{
    struct session_context *ctx = NULL;

    ctx = http_state_get(req);
    cf_pgsql_cleanup(&ctx->sql);

    if( ctx->err != NULL )
        mem_free(ctx->err);
    if( ctx->client != NULL )
        mem_free(ctx->client);
    if( ctx->val_str != NULL )
        mem_free(ctx->val_str);
    if( ctx->val_json != NULL )
        json_decref(ctx->val_json);
    if (ctx->val_blob != NULL)
        mem_free(ctx->val_blob);
    if (ctx->token)
        jwt_free(ctx->token);
    
    http_state_cleanup( req );
}

int session_init( int state )
{
    CONFIG = mem_malloc(sizeof(struct session_config));
    memset(CONFIG, 0, sizeof(struct session_config));

    /* Configuration defaults */
    CONFIG->public_mode = 0;
    CONFIG->session_ttl = 300;
    CONFIG->max_sessions = 10;
    CONFIG->string_size = 255;
    CONFIG->json_size = 1024;
    CONFIG->blob_size = 4096;
    CONFIG->allow_origin = NULL;
    CONFIG->allow_ipaddr = NULL;
    CONFIG->jwt_key = NULL;
    CONFIG->jwt_key_len = 0;
    CONFIG->jwt_alg = JWT_ALG_NONE;

    if( !session_read_config(CONFIG) )
    {
        cf_log(LOG_ERR, "%s: session is not configured", __FUNCTION__);
        return CF_RESULT_ERROR;
    }

    if( CONFIG->jwt_key == NULL && CONFIG->jwt_alg != JWT_ALG_NONE )
    {
        cf_log(LOG_NOTICE, "no key given for auth, using random");
        CONFIG->jwt_key_len = 16;
        CONFIG->jwt_key = mem_malloc(CONFIG->jwt_key_len);
        CONFIG->jwt_key = session_random_string( CONFIG->jwt_key, CONFIG->jwt_key_len );
    }

    cf_log(LOG_NOTICE, "started worker pid: %d", (int)getpid());
    if( CONFIG->jwt_alg != JWT_ALG_NONE )
    {
        cf_log(LOG_NOTICE, "  auth key: %s", CONFIG->jwt_key);
    }
    else
        cf_log(LOG_NOTICE, "  auth key: disabled");

    cf_log(LOG_NOTICE, "  public mode: %s", CONFIG->public_mode != 0 ? "yes" : "no");
    cf_log(LOG_NOTICE, "  session ttl: %zu seconds", CONFIG->session_ttl);
    cf_log(LOG_NOTICE, "  max sessions: %zu", CONFIG->max_sessions);
    if( CONFIG->allow_origin != NULL )
        cf_log(LOG_NOTICE, "  allow origin: %s", CONFIG->allow_origin);
    if( CONFIG->allow_ipaddr != NULL )
        cf_log(LOG_NOTICE, "  allow ip address: %s", CONFIG->allow_ipaddr);
    
    cf_pgsql_register(DBNAME, CONFIG->database);
    
    return CF_RESULT_OK;
}

int session_init_context( session_context *ctx )
{
    uuid_t client_uuid;

    // set empty defaults
    ctx->client = NULL;
    ctx->status = 200;
    ctx->err = NULL;
    ctx->token = NULL;
    ctx->val_sz = 0;
    ctx->val_str = NULL;
    ctx->val_json = NULL;
    ctx->val_blob = NULL;

    /* read and write strings by default */
    ctx->in_content_type = SESSION_CONTENT_STRING;
    ctx->out_content_type = SESSION_CONTENT_STRING;

    /* Generate new client token and init fresh session */
    uuid_generate(client_uuid);

    ctx->client = mem_malloc( CLIENT_UUID_LEN );
    uuid_unparse(client_uuid, ctx->client);

    if( jwt_new(&ctx->token) != 0 )
    {
        cf_log(LOG_ERR, "%s: failed to allocate jwt", __FUNCTION__);
        ctx->token = NULL;
        return CF_RESULT_ERROR;
    }

    if( CONFIG->jwt_alg != JWT_ALG_NONE )
        if( jwt_set_alg(ctx->token, CONFIG->jwt_alg, (const unsigned char *)CONFIG->jwt_key, CONFIG->jwt_key_len) != 0 )
        {
            cf_log(LOG_ERR, "%s: failed set token alg", __FUNCTION__);
            jwt_free(ctx->token);
            ctx->token = NULL;
            return CF_RESULT_ERROR;
        }

    if( jwt_add_grant(ctx->token, "id", ctx->client) != 0 )
    {
        cf_log(LOG_ERR, "%s: failed add grant to jwt", __FUNCTION__);
        jwt_free( ctx->token );
        ctx->token = NULL;
        return CF_RESULT_ERROR;
    }

    return CF_RESULT_OK;
}

void session_write_context_token( struct http_request *req )
{
    struct session_context *ctx = NULL;
    char *token = NULL;
    struct cf_buf *token_hdr = NULL;

    ctx = http_state_get(req);
    token = jwt_encode_str(ctx->token);
    token_hdr = cf_buf_alloc(HTTP_HEADER_MAX_LEN);
    cf_buf_append(token_hdr, AUTH_TYPE_PREFIX, strlen(AUTH_TYPE_PREFIX));
    cf_buf_append(token_hdr, token, strlen(token));
    free( token );

    http_response_header(req, AUTH_HEADER, cf_buf_stringify(token_hdr, NULL));
    cf_buf_free(token_hdr);
}

int session_read_context_token( struct http_request *req )
{
    int n;
    struct session_context *ctx = NULL;
    char *t, *token_hdr,*hdr_parts[3];
    const char *client_id = NULL;

    ctx = http_state_get(req);
    if( ctx->token != NULL || ctx->client != NULL )
    {
        cf_log(LOG_ERR, "%s: trying to read non-empty context", __FUNCTION__);
        return CF_RESULT_ERROR;
    }

    if( !http_request_header(req, AUTH_HEADER, &t) )
    {
        return CF_RESULT_ERROR;
    }

    token_hdr = cf_strdup(t);
    n = cf_split_string(token_hdr, " ", hdr_parts, 3);
    mem_free(token_hdr);

    if( n != 2 )
    {
        cf_log(LOG_ERR, "%s: invalid header format, n=%d - '%s'", __FUNCTION__, n, t);
        return CF_RESULT_ERROR;
    }
    /* parse and verify json web token */
    if( jwt_decode(&ctx->token, hdr_parts[1], (const unsigned char *)CONFIG->jwt_key, CONFIG->jwt_key_len) != 0 )
    {
        cf_log(LOG_ERR, "%s: invalid json web token received: '%s'", __FUNCTION__, hdr_parts[1]);
        return CF_RESULT_ERROR;
    }

    client_id = NULL;
    client_id = jwt_get_grant(ctx->token, "id");

    if( client_id == NULL )
    {
        cf_log(LOG_ERR, "%s: failed to get client id from token", __FUNCTION__);
        jwt_free(ctx->token);
        ctx->token = NULL;
        ctx->client = NULL;
        return CF_RESULT_ERROR;
    }

    ctx->client = cf_strdup(client_id);
    cf_log(LOG_NOTICE, "existing client {%s}", ctx->client);
    return CF_RESULT_OK;
}

int session_start(struct http_request *req)
{
    if( !http_state_exists(req) )
    {
        http_state_create(req, sizeof(struct session_context));
    }
    return http_state_run(session_session_states, session_states_size, req);
}

int session_render_stats(struct http_request *req)
{
    int rc;
    json_t *stats = NULL;
    struct session_context *ctx = NULL;
    time_t last_read, last_write;

    rc = CF_RESULT_OK;
    ctx = (struct session_context *)http_state_get(req);
    // FIXME: real stats here
    last_read = time(NULL);
    last_write = time(NULL);    
    stats = json_pack("{s:s s:s s:s s:i}",
              "client",      ctx->client,
              "last_read",   session_format_date(&last_read),
              "last_write",  session_format_date(&last_write),
              "session_ttl", CONFIG->session_ttl);
    session_response_json(req, 200, stats);
    json_decref(stats);
    
    cf_log(LOG_NOTICE, "rendering stats for {%s}", ctx->client);
    return rc;
}

int session_connect_db( struct http_request *req, int retry_step, int success_step, int error_step )
{
    struct session_context *ctx = http_state_get(req);
    
    cf_pgsql_cleanup(&ctx->sql);
    cf_pgsql_init(&ctx->sql);
    cf_pgsql_bind_request(&ctx->sql, req);

    if( !cf_pgsql_setup(&ctx->sql, DBNAME, CF_PGSQL_ASYNC) )
    {
        /* If the state was still INIT, we'll try again later. */
        if( ctx->sql.state == CF_PGSQL_STATE_INIT )
        {
            req->fsm_state = retry_step;
            cf_log(LOG_ERR, "retrying connection, sql state is '%s'", sql_state_text(ctx->sql.state));
            return HTTP_STATE_RETRY;
        }

        /* Different state means error */
        cf_pgsql_logerror(&ctx->sql);
        ctx->status = 500;
        req->fsm_state = error_step;
        cf_log(LOG_ERR, "%s: failed to connect to database, sql state is '%s'", __FUNCTION__, sql_state_text(ctx->sql.state));
        cf_log(LOG_NOTICE, "hint: check database connection string in the configuration file.");
    }
    else {
        req->fsm_state = success_step;
    }

    return HTTP_STATE_CONTINUE;
}

void session_handle_pg_error( struct http_request *req )
{
    struct session_context *ctx = http_state_get(req);

    ctx->status = 500;

    if( strstr(ctx->sql.error, "duplicate key value violates unique constraint") != NULL )
    {
        ctx->status = 409; // Conflict
    }

    if (ctx->err == NULL) {
        ctx->err = cf_strdup(ctx->sql.error);
    }
}

int session_wait( struct http_request *req, int read_step, int complete_step, int error_step )
{
    struct session_context *ctx = http_state_get(req);

    switch( ctx->sql.state )
    {
    case CF_PGSQL_STATE_WAIT:
        /* keep waiting */
        cf_log(LOG_DEBUG, "io wating ~> %s", session_request_state(req));
        return HTTP_STATE_RETRY;

    case CF_PGSQL_STATE_COMPLETE:
        req->fsm_state = complete_step;
        cf_log(LOG_DEBUG, "io complete ~> %s", session_request_state(req));
        break;

    case CF_PGSQL_STATE_RESULT:
        req->fsm_state = read_step;
        cf_log(LOG_DEBUG, "io reading ~> %s", session_request_state(req));
        break;

    case CF_PGSQL_STATE_ERROR:
        req->fsm_state = error_step;
        cf_log(LOG_ERR, "io failed ~> %s.\n%s", session_request_state(req), ctx->sql.error);
        session_handle_pg_error(req);
        break;

    default:
        cf_pgsql_continue(&ctx->sql);
        break;
    }

    return HTTP_STATE_CONTINUE;
}

/* An error occurred */
int state_error(struct http_request *req)
{
    struct session_context *ctx = http_state_get(req);
    const char *msg = NULL;

    /* Handle redirect */
    if( session_is_redirect(ctx) )
    {
        msg = http_status_text(ctx->status);
        cf_log(LOG_DEBUG, "%d: %s ~> '%s' to {%s}", ctx->status, msg, req->path, ctx->client);

        http_response(req, ctx->status, msg, sizeof(msg));
        session_delete_context(req);
        return HTTP_STATE_COMPLETE;
    }

    if( session_is_success(ctx) )
    {
        ctx->status = 500;
        cf_log(LOG_DEBUG, "no error status set, default=500");
    }

    cf_log(LOG_ERR, "%d: %s, sql state: %s to {%s}",
        ctx->status, 
        http_status_text(ctx->status), 
        sql_state_text(ctx->sql.state),
        ctx->client);

    session_response_status( req, ctx->status, ctx->err != NULL ? ctx->err : http_status_text(ctx->status) );

    session_delete_context( req );
    return HTTP_STATE_COMPLETE;
}

/* Request was completed successfully. */
int state_done(struct http_request *req)
{
    struct session_context *ctx = http_state_get(req);
    const char *output = NULL;

    ctx->status = 200;
    if (req->method == HTTP_METHOD_POST ||
        req->method == HTTP_METHOD_PUT) 
    {
        switch( ctx->out_content_type )
        {
            case SESSION_CONTENT_STRING:
                http_response_header(req, "content-type", CONTENT_TYPE_STRING);
                break;
            case SESSION_CONTENT_JSON:
                http_response_header(req, "content-type", CONTENT_TYPE_JSON);
                break;

        }
        /* reply 201 Created on POSTs */
        if (req->method == HTTP_METHOD_POST)
            ctx->status = 201;

        output = http_status_text(ctx->status);
        switch( ctx->out_content_type )
        {
            default:
            case SESSION_CONTENT_BLOB:
                break;

            case SESSION_CONTENT_STRING:
                http_response(req, ctx->status, output, strlen(output));
                break;
            case SESSION_CONTENT_JSON:
                session_response_status(req, ctx->status, output);
                break;
        }

    }
    else if( session_is_item_request(req) )
    {

        cf_log(LOG_DEBUG, "serving item size %zu (%s) -> (%s) to {%s}",
            ctx->val_sz,
            SESSION_CONTENT_NAMES[ctx->in_content_type],
            SESSION_CONTENT_NAMES[ctx->out_content_type],
            ctx->client);
        
        switch( ctx->out_content_type )
        {
            default:
            case SESSION_CONTENT_STRING:
                output = session_item_to_string(ctx);
                http_response_header(req, "content-type", CONTENT_TYPE_STRING);
                http_response(req, ctx->status, 
                              output == NULL ? "" : output,
                              output == NULL ? 0 : strlen(output));
                break;

            case SESSION_CONTENT_JSON:
                output = session_item_to_json(ctx);
                http_response_header(req, "content-type", CONTENT_TYPE_JSON);
                http_response(req, ctx->status,
                              output == NULL ? "" : output,
                              output == NULL ? 0 : strlen(output));
                break;

            case SESSION_CONTENT_BLOB:
                session_response_status(req, 403, http_status_text(403));
                break;

        };
    }
    else {
        ctx->status = 403;
        http_response(req, ctx->status, "", 0);
    }
    
    cf_log(LOG_DEBUG, "%d: %s to {%s}", ctx->status, http_status_text(ctx->status), ctx->client);

    session_delete_context(req);
    return HTTP_STATE_COMPLETE;
}
