// session_util.h

#ifndef __SESSION_UTIL_H_
#define __SESSION_UTIL_H_

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <limits.h>

#include <zfrog.h>
#include <cf_http.h>

#include <jansson.h>

#include "session.h"

#define CONTENT_TYPE_STRING     "text/plain"
#define CONTENT_TYPE_JSON       "application/json"
#define CONTENT_TYPE_BLOB       "multipart/form-data"
#define CONTENT_TYPE_HTML       "text/html"

#define SESSION_CONTENT_STRING    0
#define SESSION_CONTENT_HTML      1
#define SESSION_CONTENT_JSON      2
#define SESSION_CONTENT_BLOB      3

int session_read_config(struct session_config *);

int session_is_item_request(struct http_request *);
struct cf_buf *session_request_data(struct http_request *);
void session_read_content_types(struct http_request *);
void session_response_json(struct http_request *, const unsigned int, const json_t *);
void session_response_status(struct http_request *, const unsigned int, const char *);
void sessiono_handle_pg_error(struct http_request *);
char *session_item_to_string(struct session_context *);
char *session_item_to_json(struct session_context *);
char *session_random_string(char *, size_t);
char *session_format_date(time_t*);
const char *session_state_text(int s);
const char *sql_state_text(int s);
const char *session_request_state(struct http_request *);

int session_connect_db(struct http_request *, int, int, int);
int session_wait(struct http_request *, int, int, int);

int session_is_success(struct session_context *);
int session_is_redirect(struct session_context *);

#endif //__SESSION_UTIL_H_
