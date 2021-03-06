#include "session.h"
#include "session_util.h"
#include "assets.h"

int session_state_init( struct http_request *req )
{
    struct session_context *ctx = http_state_get(req);
    char *origin = NULL;
    char saddr[INET6_ADDRSTRLEN];
    int rc;

    /* Filter by Origin header */
    if( CONFIG->allow_origin != NULL )
    {
        if( !http_request_header(req, "Origin", &origin) && !CONFIG->public_mode )
        {
            cf_log(LOG_NOTICE, "%s: disallow access - no 'Origin' header sent", __FUNCTION__);
            session_response_status(req, 403, "'Origin' header is not found");
            session_delete_context(req);
            return HTTP_STATE_COMPLETE;
        }

        if( strcmp(origin, CONFIG->allow_origin) != 0 )
        {
            cf_log(LOG_NOTICE, "%s: disallow access - 'Origin' header mismatch %s != %s", __FUNCTION__, origin, CONFIG->allow_origin);
            session_response_status(req, 403, "Origin Access Denied");
            session_delete_context(req);
            return HTTP_STATE_COMPLETE;
        }
    }

    /* Filter by client ip address */
    if( CONFIG->allow_ipaddr != NULL )
    {
        memset(saddr, 0, sizeof(saddr));
        if( req->owner->addrtype == AF_INET )
        {
            inet_ntop(AF_INET, &req->owner->addr.ipv4.sin_addr, saddr, sizeof(saddr));
        }

        if( req->owner->addrtype == AF_INET6 )
        {
            inet_ntop(AF_INET6, &req->owner->addr.ipv6.sin6_addr, saddr, sizeof(saddr));
        }

        if( strcmp(saddr, CONFIG->allow_ipaddr) != 0 )
        {
            cf_log(LOG_NOTICE, "%s: disallow access - Client IP mismatch %s != %s", __FUNCTION__, saddr, CONFIG->allow_ipaddr);
            session_response_status(req, 403, "Client Access Denied");
            session_delete_context(req);
            return HTTP_STATE_COMPLETE;
        }
    }

    /* read header and parse json web token */
    if( !session_read_context_token(req) )
    {
        if( !session_init_context(ctx) )
        {
            /* finish request with 500 error */
            session_response_status(req, 500, http_status_text(500));
            session_delete_context(req);
            return HTTP_STATE_COMPLETE;
        }
    }

    /* set Authorization header */
    session_write_context_token(req);

    /* set Access-Control-Allow-Origin header accoring to config */
    if( CONFIG->allow_origin != NULL )
    {
        http_response_header(req, CORS_ALLOWORIGIN_HEADER, CONFIG->allow_origin);
    }
    else
    {
        http_response_header(req, CORS_ALLOWORIGIN_HEADER, "*");   
    }

    /* finish request now for OPTIONS and HEAD methods
     * since we need to respond with CORS *-Allow-* headers */
    if( req->method == HTTP_METHOD_OPTIONS || req->method == HTTP_METHOD_HEAD )
    {
        
        http_response_header(req, CORS_ALLOW_HEADER, AUTH_HEADER);
        session_delete_context(req);
        session_response_status(req, 200, http_status_text(200));
        return HTTP_STATE_COMPLETE;
    }

    /* set Access-Control-Expose-Headers to allow auth header
     * as indicated by Access-Control-Allow-Headers */
    http_response_header(req, CORS_EXPOSE_HEADER, AUTH_HEADER);
    
    /* render stats for client bootstrap */
    if( !session_is_item_request(req) )
    {
        rc = session_render_stats(req);
        session_delete_context(req);

        if( rc != CF_RESULT_OK )
        {
            cf_log(LOG_ERR, "%s: failed to render stats.", __FUNCTION__);
            return HTTP_STATE_ERROR;
        }
        return HTTP_STATE_COMPLETE;
    }

    /* into database io */
    return session_connect_db(req, REQ_STATE_INIT, REQ_STATE_QUERY, REQ_STATE_ERROR);
}

int state_handle_get(struct http_request *req)
{
    /* get_item.sql
     * $1 - client
     * $2 - item key 
     */
    struct session_context *ctx = NULL;

    ctx = (struct session_context*)http_state_get(req);
    cf_log(LOG_NOTICE, "GET %s for {%s}", req->path, ctx->client);
    return cf_pgsql_query_params(&ctx->sql,
                                (const char*)asset_get_item_sql, 
                                PGSQL_FORMAT_TEXT,
                                2,
                                // client
                                ctx->client,
                                strlen(ctx->client),
                                PGSQL_FORMAT_TEXT,
                                // key
                                req->path,
                                strlen(req->path),
                                PGSQL_FORMAT_TEXT);
}

int state_handle_post(struct http_request *req, struct cf_buf *body)
{
    /* post_item.sql expects 5 arguments: 
     client, key, string, json, blob
    */
    struct session_context *ctx = NULL;
    int rc;
    char *val_str = NULL;
    json_error_t             jerr;
    json_t                  *val_json;
    void                    *val_blob;
    size_t                   val_blob_sz;

    rc = CF_RESULT_OK;
    ctx = (struct session_context*)http_state_get(req);
    cf_log(LOG_NOTICE, "POST %s, %zu bytes (%s) read from {%s}",
        req->path, body->offset,
        SESSION_CONTENT_NAMES[ctx->in_content_type],
        ctx->client);

    switch(ctx->in_content_type)
    {
        default:
        case SESSION_CONTENT_STRING:
            val_str = cf_buf_stringify(body, NULL);
            rc = cf_pgsql_query_params(&ctx->sql,
                                (const char*)asset_post_item_sql, 
                                PGSQL_FORMAT_TEXT,
                                5,
                                // client
                                ctx->client,
                                strlen(ctx->client),
                                PGSQL_FORMAT_TEXT,
                                // key
                                req->path,
                                strlen(req->path),
                                PGSQL_FORMAT_TEXT,
                                // string
                                val_str,
                                strlen(val_str),
                                PGSQL_FORMAT_TEXT, 
                                // json
                                NULL, 0,
                                PGSQL_FORMAT_TEXT,
                                // blog
                                NULL, 0,
                                PGSQL_FORMAT_TEXT);
            break;

        case SESSION_CONTENT_JSON:
            val_str = cf_buf_stringify(body, NULL);
            val_json = json_loads(val_str, JSON_ALLOW_NUL, &jerr);
            if( val_json == NULL )
            {
                ctx->err = mem_malloc(512);
                snprintf(ctx->err, 512,
                         "%s at line: %d, column: %d, pos: %d",
                         jerr.text, jerr.line, jerr.column, jerr.position);
                cf_log(LOG_ERR, "%s: broken json - %s", __FUNCTION__, ctx->err);
                return CF_RESULT_ERROR;
            }
            rc = cf_pgsql_query_params(&ctx->sql,
                                (const char*)asset_post_item_sql, 
                                PGSQL_FORMAT_TEXT,
                                5,
                                // client
                                ctx->client,
                                strlen(ctx->client),
                                PGSQL_FORMAT_TEXT,
                                // key
                                req->path,
                                strlen(req->path),
                                PGSQL_FORMAT_TEXT,
                                // string
                                NULL,
                                0,
                                PGSQL_FORMAT_TEXT, 
                                // json
                                val_str, strlen(val_str),
                                PGSQL_FORMAT_TEXT,
                                // blog
                                NULL, 0,
                                PGSQL_FORMAT_TEXT);
            break;

        case SESSION_CONTENT_BLOB:
            val_blob = cf_buf_stringify(body, &val_blob_sz);
            rc = cf_pgsql_query_params(&ctx->sql,
                                (const char*)asset_post_item_sql, 
                                PGSQL_FORMAT_TEXT,
                                5,
                                // client
                                ctx->client,
                                strlen(ctx->client),
                                PGSQL_FORMAT_TEXT,
                                // key
                                req->path,
                                strlen(req->path),
                                PGSQL_FORMAT_TEXT,
                                // string
                                NULL,
                                0,
                                PGSQL_FORMAT_TEXT, 
                                // json
                                NULL, 0,
                                PGSQL_FORMAT_TEXT,
                                // blog
                                val_blob, val_blob_sz,
                                PGSQL_FORMAT_TEXT);
            break;
    }
    return rc;
}

int session_state_query(struct http_request *req)
{
    int rc, too_big;
    struct session_context *ctx = NULL;
    struct cf_buf *body = NULL;

    rc = CF_RESULT_OK;
    ctx = (struct session_context*)http_state_get(req);
    body = session_request_data(req);

    /* Check size limitations */
    too_big = 0;
    switch( ctx->in_content_type )
    {
        default:
        case SESSION_CONTENT_STRING:
            if( body->offset > CONFIG->string_size ) {
                too_big = 1;
            }
            break;
        case SESSION_CONTENT_JSON:
            if (body->offset > CONFIG->json_size) {
                too_big = 1;
            }
            break;
        case SESSION_CONTENT_BLOB:
            if (body->offset > CONFIG->blob_size) {
                too_big = 1;
            }
            break;
    };

    if( too_big )
    {
        cf_buf_free(body);
        ctx->status = 403;
        ctx->err = cf_strdup("Request is too large");
        req->fsm_state = REQ_STATE_ERROR;
        return HTTP_STATE_CONTINUE;
    }

    /* Handle item operation in http method */
    switch( req->method )
    {
        case HTTP_METHOD_POST:
            rc = state_handle_post(req, body); 
            break;

        case HTTP_METHOD_PUT:
            break;

        case HTTP_METHOD_DELETE:
            break;

        default:
        case HTTP_METHOD_GET:
            rc = state_handle_get(req);
            break;
    }

    cf_buf_free(body);

    if( rc != CF_RESULT_OK )
    {
        /* go to error handler
           PGSQL errors are internal 500
           the other case is broken json 
         */
        req->fsm_state = REQ_STATE_ERROR;
        if( ctx->sql.state == CF_PGSQL_STATE_ERROR )
        {
            cf_pgsql_logerror( &ctx->sql );
            ctx->status = 500;
        }
        else
            ctx->status = 400;
        return HTTP_STATE_CONTINUE;
    }

    /* Wait for item request completition */
    req->fsm_state = REQ_STATE_WAIT;
    return HTTP_STATE_CONTINUE;
}

int session_state_wait( struct http_request *req )
{
    return session_wait(req, REQ_STATE_READ, REQ_STATE_DONE, REQ_STATE_ERROR);
}

int session_state_read(struct http_request *req)
{
    int rows;
    struct session_context *ctx = NULL;
    char *val = NULL;
    json_error_t jerr;

    if( req->method != HTTP_METHOD_GET )
    {
        cf_log(LOG_ERR, "%s: method '%s' is forbidden for item", __FUNCTION__, http_method_text(req->method));
        return HTTP_STATE_ERROR;
    }

    rows = 0;
    val = NULL;

    ctx = (struct session_context*)http_state_get(req);
    ctx->val_str = NULL;
    ctx->val_json = NULL;
    ctx->val_blob = NULL;
    ctx->val_sz = 0;

    rows = cf_pgsql_ntuples(&ctx->sql);
    if( rows == 0 )
    {
        /* item was not found, report 404 */
        cf_log(LOG_DEBUG, "zero row selected for key \"%s\"", req->path);
        ctx->status = 404;
        req->fsm_state = REQ_STATE_ERROR;
        return HTTP_STATE_CONTINUE;
    }
    else if( rows == 1 )
    {
        /* found existing session record */
        val = cf_pgsql_getvalue(&ctx->sql, 0, 0);
        if( val != NULL && strlen(val) > 0 )
        {
            ctx->val_str = cf_strdup(val);
            ctx->val_sz = strlen(val);
        }

        val = cf_pgsql_getvalue(&ctx->sql, 0, 1);
        if( val != NULL && strlen(val) > 0 )
        {
            cf_log(LOG_NOTICE, "parsing stored json data: \"%s\"", val);
            ctx->val_json = json_loads(val, JSON_ALLOW_NUL, &jerr);
            if( ctx->val_json == NULL )
            {
                cf_log(LOG_ERR, "malformed json received from store");
                return HTTP_STATE_ERROR;
            }
            ctx->val_sz = strlen(val);
        }
        val = cf_pgsql_getvalue(&ctx->sql, 0, 2);
        if( val != NULL && strlen(val) > 0 )
        {
            ctx->val_blob = cf_strdup(val);
            ctx->val_sz = strlen(ctx->val_blob);
        }

        /* since we've read item, update in_content_type
           because it indicated type we store
         */
        if( ctx->val_str != NULL )
            ctx->in_content_type = SESSION_CONTENT_STRING;
        if( ctx->val_json != NULL )
            ctx->in_content_type = SESSION_CONTENT_JSON;
        if( ctx->val_blob != NULL )
            ctx->in_content_type = SESSION_CONTENT_BLOB;
    }
    else
    {
        cf_log(LOG_ERR, "%s: selected %d rows, 1 expected", __FUNCTION__, rows);
        return HTTP_STATE_ERROR;
    }

    /* Continue processing our query results */
    cf_pgsql_continue(&ctx->sql);

    /* Back to our DB waiting state */
    req->fsm_state = REQ_STATE_WAIT;
    return HTTP_STATE_CONTINUE;
}

