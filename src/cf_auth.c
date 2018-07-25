// cf_auth.c

#include <sys/param.h>
#include <ctype.h>

#include "zfrog.h"
#include "cf_http.h"

TAILQ_HEAD(, cf_auth)   auth_list;


void cf_auth_init()
{
    TAILQ_INIT( &auth_list );
}

int cf_auth_new( const char *name )
{
    struct cf_auth *auth = NULL;

    if( (auth = cf_auth_lookup(name)) != NULL ) {
        return CF_RESULT_ERROR;
    }

	auth = mem_malloc(sizeof(*auth));
	auth->type = 0;
	auth->value = NULL;
	auth->redirect = NULL;
	auth->validator = NULL;
	auth->name = mem_strdup(name);

	TAILQ_INSERT_TAIL(&auth_list, auth, list);

    return CF_RESULT_OK;
}

int cf_auth_run( struct http_request *req, struct cf_auth *auth )
{
    int r = 0;

    log_debug("cf_auth(%p, %p)", req, auth);

    switch( auth->type )
    {
    case CF_AUTH_TYPE_COOKIE:
        r = cf_auth_cookie(req, auth);
		break;
    case CF_AUTH_TYPE_HEADER:
        r = cf_auth_header(req, auth);
		break;
    case CF_AUTH_TYPE_REQUEST:
        r = cf_auth_request(req, auth);
		break;
	default:
        cf_log(LOG_NOTICE, "unknown auth type %d", auth->type);
        return CF_RESULT_ERROR;
	}

    switch( r )
    {
    case CF_RESULT_OK:
		req->flags |= HTTP_REQUEST_AUTHED;
        log_debug("cf_auth_run() for %s successful", req->path);
    case CF_RESULT_RETRY:
        return r;
	default:
		break;
	}

	/* Authentication types of "request" send their own HTTP responses */
    if( auth->type == CF_AUTH_TYPE_REQUEST )
        return r;

    log_debug("cf_auth_run() for %s failed", req->path);

    if( auth->redirect == NULL )
    {
		http_response(req, 403, NULL, 0);
        return CF_RESULT_ERROR;
	}

	http_response_header(req, "location", auth->redirect);
	http_response(req, 302, NULL, 0);

    return CF_RESULT_ERROR;
}

int cf_auth_cookie( struct http_request *req, struct cf_auth *auth )
{
    int i, v;
    size_t len, slen;
    const char	*hdr = NULL;
    char *value, *c, *cookie, *cookies[HTTP_MAX_COOKIES];

    if( !http_request_header(req, "cookie", &hdr) ) {
        return CF_RESULT_ERROR;
    }

    cookie = mem_strdup(hdr);

	slen = strlen(auth->value);
    v = cf_split_string(cookie, ";", cookies, HTTP_MAX_COOKIES);
    for( i = 0; i < v; i++ )
    {
        for( c = cookies[i]; isspace(*c); c++ )
			;

		len = MIN(slen, strlen(cookies[i]));
        if( !strncmp(c, auth->value, len) )
			break;
	}

    if( i == v )
    {
		mem_free(cookie);
        return CF_RESULT_ERROR;
	}

	c = cookies[i];
    if( (value = strchr(c, '=')) == NULL )
    {
		mem_free(cookie);
        return CF_RESULT_ERROR;
	}

    i = cf_validator_check(req, auth->validator, ++value);
	mem_free(cookie);

    return i;
}

int cf_auth_header( struct http_request *req, struct cf_auth *auth )
{
    const char *header = NULL;

    if( !http_request_header(req, auth->value, &header) )
        return CF_RESULT_ERROR;

    return cf_validator_check(req, auth->validator, header);
}

int cf_auth_request( struct http_request *req, struct cf_auth *auth )
{    
    int	ret;

    req->flags |= HTTP_VALIDATOR_IS_REQUEST;
    ret = cf_validator_check(req, auth->validator, req);
    req->flags &= ~HTTP_VALIDATOR_IS_REQUEST;

    return ret;
}

struct cf_auth* cf_auth_lookup( const char *name )
{
    struct cf_auth *auth = NULL;

    TAILQ_FOREACH(auth, &auth_list, list)
    {
        if( !strcmp(auth->name, name) )
            return auth;
	}

    return NULL;
}
