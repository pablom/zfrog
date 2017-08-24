#include "session_util.h"
#include "assets.h"
#include "session.h"
#include "cf_ini.h"

char *session_config_paths[] = {
    "$HOME/.session/conf",
    "$PREFIX/conf/session.conf"
};
#define session_config_paths_size (sizeof(session_config_paths) / sizeof(session_config_paths[0]))

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

static int session_read_config_handler( void* user, const char* section, const char* name, const char* value )
{
    struct session_config *cfg;

    cfg = (struct session_config *)user;
    if (MATCH("session", "public_mode")){
        cfg->public_mode = atoi(value);
    } else if (MATCH("session", "database")) {
        cfg->database = cf_strdup(value);
    } else if (MATCH("session", "ttl")) {
        cfg->session_ttl = atoi(value);
    } else if (MATCH("session", "string_size")) {
        cfg->string_size = atoi(value);
    } else if (MATCH("session", "json_size")) {
        cfg->json_size = atoi(value);
    } else if (MATCH("session", "blob_size")) {
        cfg->blob_size = atoi(value);
    } else if (MATCH("filter", "origin")) {
        cfg->allow_origin = cf_strdup(value);
    } else if (MATCH("filter", "ip_address")) {
        cfg->allow_ipaddr = cf_strdup(value);
    } else if( MATCH("auth", "key") )
    {
        cfg->jwt_key = cf_strdup(value);
        cfg->jwt_key_len = strlen(value);
    }
    else if( MATCH("auth", "alg") )
    {
        if( strcmp(value, "HS256") ) {
            cfg->jwt_alg = JWT_ALG_HS256;            
        }
        else if( strcmp(value, "HS384") ) {
            cfg->jwt_alg = JWT_ALG_HS384;            
        }
        else if( strcmp(value, "HS512") ) {
            cfg->jwt_alg = JWT_ALG_HS512;            
        }
        else if( strcmp(value, "RS256") ) {
            cfg->jwt_alg = JWT_ALG_RS256;            
        }
        else if( strcmp(value, "RS384") ) {
            cfg->jwt_alg = JWT_ALG_RS384;            
        }
        else if( strcmp(value, "RS512") ) {
            cfg->jwt_alg = JWT_ALG_RS512;            
        }
        else if( strcmp(value, "ES256") ) {
            cfg->jwt_alg = JWT_ALG_ES256;            
        }
        else if( strcmp(value, "ES384") ) {
            cfg->jwt_alg = JWT_ALG_ES384;            
        }
        else if( strcmp(value, "ES512") ) {
            cfg->jwt_alg = JWT_ALG_ES512;            
        }
        else if( strcmp(value, "TERM") ) {
            cfg->jwt_alg = JWT_ALG_TERM;            
        }
        else if( strcmp(value, "none") ) {
            cfg->jwt_alg = JWT_ALG_NONE;           
        }
        else {
            cf_log(LOG_ERR, "unknown auth algorithm: %s", value);
        }
    } else {
        cf_log(LOG_ERR, "unknown option \"%s.%s\"", section, name);
    }

    return 1;
}

static int session_parse_config( const char* path, struct session_config *cfg )
{
    struct stat st;

    if( stat(path, &st) != 0 )
    {
        return CF_RESULT_ERROR;
    }

    if( ini_parse(path, session_read_config_handler, cfg) < 0 )
    {
        cf_log(LOG_ERR, "failed to parse configuration.");
        return CF_RESULT_ERROR;
    }

    return CF_RESULT_OK;
}

int session_read_config( struct session_config *cfg )
{
    char *p, *path;
    char home[PATH_MAX], prefix[PATH_MAX];
    char *homevar;
    struct cf_buf *buf;
    int parsed;
    size_t i;
    
    parsed = 0;
    /* $HOME defaults to "." */
    homevar = getenv("HOME");
    if( homevar == NULL || strlen(homevar) == 0 )
        homevar = ".";

    memset(prefix, 0, sizeof(PATH_MAX));
    memset(home, 0, sizeof(PATH_MAX));
    strcpy(home, homevar);

#if defined(PREFIX)
    strcpy(prefix, PREFIX);
#else
    strcpy(prefix, "/usr/local/session");
#endif

    for( i = 0; i < session_config_paths_size; ++i )
    {
        p = session_config_paths[i];
        
        /* read config paths and replace supported variables:
         * $HOME => env variable
         * $PREFIX => "-DPREFIX" value or "/usr/local/session" default
         */
        buf = cf_buf_alloc(PATH_MAX);
        cf_buf_append(buf, p, strlen(p));

        if( strstr(p, "$HOME") != NULL )
        {
            cf_buf_replace_string(buf, "$HOME", home, strlen(home));
        }

        if( strstr(p, "$PREFIX") != NULL )
        {
            cf_buf_replace_string(buf, "$PREFIX", prefix, strlen(prefix));
        }

        path = cf_buf_stringify(buf, NULL);
        parsed = session_parse_config(path, cfg);
        cf_buf_free(buf);

        if( parsed )
        {
            cf_log(LOG_DEBUG, "using \"%s\"", path);
            break;
        }
    }

    if( !parsed )
        return CF_RESULT_ERROR;

    return CF_RESULT_OK;
}

void session_response_json( struct http_request * req, const unsigned int http_code, const json_t *data )
{
    struct cf_buf *buf = NULL;
    char *json = NULL;

    buf = cf_buf_alloc(http_body_max);
    json = json_dumps(data, JSON_ENCODE_ANY);
    cf_buf_append(buf, json, strlen(json));

    http_response_header(req, "content-type", CONTENT_TYPE_JSON);
    http_response(req, http_code, buf->data, buf->offset);
    cf_buf_free(buf);
    free(json);
}

void session_response_status(struct http_request *req, const unsigned int http_code, const char* msg)
{
    json_t* data = NULL;
    
    data = json_pack("{s:i s:s}", "code", http_code, "message", msg);
    session_response_json(req, http_code, data);
    json_decref(data);
}

struct cf_buf* session_request_data(struct http_request *req)
{
    struct cf_buf *buf = NULL;
    int r;
    char data[BUFSIZ];

    buf = cf_buf_alloc(http_body_max);

    for(;;)
    {
        r = http_body_read(req, data, sizeof(data));
        if( r == -1 )
        {
            cf_buf_free(buf);
            return NULL;
        }
        if( r == 0 )
            break;
        cf_buf_append(buf, data, r);
    }

    return buf;
}

int session_is_item_request(struct http_request *req)
{
    return (strcmp(req->path, ROOT_PATH) != 0 &&
            strcmp(req->path, CONSOLE_JS_PATH) != 0);
}

char* session_format_date(time_t* epoch)
{
    struct tm *t;
    static char sdate[80];

    t = gmtime(epoch);
    strftime(sdate, sizeof(sdate), "%a %Y-%m-%d %H:%M:%S %Z", t);
    return sdate;
}

void session_read_content_types(struct http_request *req)
{
    char *accept = NULL;
    char *content_type = NULL;
    struct session_context *ctx = NULL;

    ctx = (struct session_context*)http_state_get(req);
    if( http_request_header(req, "accept", &accept) )
    {
        if( strstr(accept, CONTENT_TYPE_HTML) != NULL )
            ctx->out_content_type = SESSION_CONTENT_HTML;
        else if( strstr(accept, CONTENT_TYPE_JSON) != NULL )
            ctx->out_content_type = SESSION_CONTENT_JSON;
        else if( strstr(accept, CONTENT_TYPE_BLOB) != NULL )
            ctx->out_content_type = SESSION_CONTENT_BLOB;
        else
            ctx->out_content_type = SESSION_CONTENT_STRING;
    }

    if( http_request_header(req, "content-type", &content_type) )
    {
        if( strstr(content_type, CONTENT_TYPE_HTML) != NULL )
            ctx->in_content_type = SESSION_CONTENT_HTML;
        else if( strstr(content_type, CONTENT_TYPE_JSON) != NULL )
            ctx->in_content_type = SESSION_CONTENT_JSON;
        else if( strstr(content_type, CONTENT_TYPE_BLOB) != NULL )
            ctx->in_content_type = SESSION_CONTENT_BLOB;
        else
            ctx->in_content_type = SESSION_CONTENT_STRING;
    }

    /* FIXME: handle Accept-Encoding here */
}

char* session_random_string(char *str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK0987654321";
    if( size )
    {
        --size;
        for( size_t n = 0; n < size; n++ )
        {
            int key = rand() % (int) (sizeof charset - 1);
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
    return str;
}

int session_is_success(struct session_context *ctx)
{
    if (ctx->status >= 200 && ctx->status < 300) {
        return 1;
    }

    return 0;
}

int session_is_redirect(struct session_context *ctx)
{
    if( ctx->status >= 300 && ctx->status < 400 )
        return 1;

    return 0;
}


char * session_item_to_string( struct session_context *ctx )
{
    char *b64 = NULL;

    switch( ctx->in_content_type )
    {
        case SESSION_CONTENT_STRING:
            return ctx->val_str;
        case SESSION_CONTENT_JSON:
            return json_dumps(ctx->val_json, JSON_INDENT(2));
        case SESSION_CONTENT_BLOB:
            cf_base64_encode(ctx->val_blob, ctx->val_sz, &b64);
            return b64;
    }

    return NULL;
}

char* session_item_to_json(struct session_context *ctx)
{
    /* FIXME: apply json selectors here */
    return session_item_to_string(ctx);
}
