// init.c

#include <zfrog.h>
#include <cf_pgsql.h>

#if !defined(CF_NO_HTTP)
#include <cf_http.h>
#endif

int	init(int);

#if !defined(CF_NO_HTTP)
int	hello(struct http_request *);
#endif

/* Called when our module is loaded (see config) */
int init( int state )
{
    /* Register our database */
    cf_pgsql_register("db", "host=/tmp dbname=test");

    return CF_RESULT_OK;
}

#if !defined(CF_NO_HTTP)
int hello( struct http_request *req )
{
	http_response(req, HTTP_STATUS_OK, "hello", 5);
    return CF_RESULT_OK;
}
#endif
