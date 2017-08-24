// session.h

#ifndef __SESSION_H_
#define __SESSION_H_

#include <zfrog.h>
#include <cf_http.h>
#include <cf_pgsql.h>

#include <uuid/uuid.h>
#include <jwt/jwt.h>
#include <jansson.h>

/* States */
#define REQ_STATE_INIT          0
#define REQ_STATE_QUERY         1
#define REQ_STATE_WAIT          2
#define REQ_STATE_READ          3
#define REQ_STATE_ERROR         4
#define REQ_STATE_DONE          5

/* Common */

#define CLIENT_UUID_LEN         37
#define ITEM_KEY_MAX            255

#define PGSQL_FORMAT_TEXT       0
#define PGSQL_FORMAT_BINARY     1

#define CONSOLE_JS_PATH         "/console.js"
#define ROOT_PATH               "/"
#define AUTH_HEADER             "authorization"
#define AUTH_TYPE_PREFIX        "Bearer "
#define CORS_ALLOWORIGIN_HEADER "access-control-allow-origin"
#define CORS_EXPOSE_HEADER      "access-control-expose-headers"
#define CORS_ALLOW_HEADER       "access-control-allow-headers"

static char* DBNAME = "session-store";

static char    *SQL_STATE_NAMES[] = {
    "<null>",   // NULL
    "init",     // CF_PGSQL_STATE_INIT
    "wait",     // CF_PGSQL_STATE_WAIT
    "result",   // CF_PGSQL_STATE_RESULT
    "error",    // CF_PGSQL_STATE_ERROR
    "done",     // CF_PGSQL_STATE_DONE
    "complete"  // CF_PGSQL_STATE_COMPLETE
};

static char    *SESSION_CONTENT_NAMES[] = {
    "string",
    "json",
    "binary"
};

struct session_config
{
    char        *database;
    int          public_mode;
    size_t       session_ttl;
    size_t       max_sessions;
    char        *jwt_key;
    size_t       jwt_key_len;
    jwt_alg_t    jwt_alg;

    /* values size limits */
    size_t string_size;
    size_t json_size;
    size_t blob_size;

    /* filtering */
    char *allow_origin;
    char *allow_ipaddr;
};

/* shared config instance */
extern struct session_config *CONFIG;

struct session_context
{
    /* processing status & err message */
    int status;
    char *err;

    // PgSQL engine
    struct cf_pgsql sql;

    // Client ID and web token
    char *client;
    jwt_t *token;

    // in/out content-type
    int in_content_type;
    int out_content_type;

    // Current item data
    char *val_str;
    json_t *val_json;
    void *val_blob;
    size_t val_sz;
};

int session_init_context(struct session_context *);
int session_read_context_token(struct http_request *);
void session_write_context_token(struct http_request *);
void session_delete_context(struct http_request *);

int session_put_context(struct session_context *);
int session_purge_context(struct session_context *);

int session_init(int state);
int session_start(struct http_request *);
int session_render_stats(struct http_request *);

int session_state_init(struct http_request *);
int session_state_query(struct http_request *);
int session_state_wait(struct http_request *);
int session_state_read(struct http_request *);
int state_error(struct http_request *);
int state_done(struct http_request *);

int state_handle_get(struct http_request *);
int state_handle_post(struct http_request *, struct cf_buf *);
int state_handle_put(struct http_request *, struct cf_buf *);
int state_handle_delete(struct http_request *);
int state_handle_head(struct http_request *);


#endif //__SESSION_H_
