#include <zfrog.h>
#include <cf_redis.h>
#include <cf_http.h>

int	init(int);
int	homepage(struct http_request *);


/****************************************************************************
 * Called when our module is loaded (see config)
 ****************************************************************************/
int init( int state )
{
    /* Register our database */
    //cf_redis_register("db", "127.0.0.1", 0);
    cf_redis_register("db", "unix@/tmp/redisserv", 0);

    return CF_RESULT_OK;
}
/*---------------------------------------------------------------------------*/
int homepage( struct http_request *req )
{
    static const char response_body[] = "Redis JSON-RPC API\n";
	
    http_response_header(req, "content-type", "text/plain");
    http_response(req, 200, response_body, sizeof(response_body) - 1);
    return CF_RESULT_OK;
}
/*---------------------------------------------------------------------------*/

