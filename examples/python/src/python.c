
#include <zfrog.h>
#include <cf_http.h>

/*
 * Just some examples of things that can be mixed with python modules
 */

int	onload(int);
int	cpage(struct http_request *);
int	c_validator(struct http_request *, void *);

int c_validator(struct http_request *req, void *data)
{
	cf_log(LOG_NOTICE, "c_validator(): called!");
	return CF_RESULT_OK;
}

int onload( int action )
{
	cf_log(LOG_NOTICE, "onload called from native");
	return CF_RESULT_OK;
}

int cpage( struct http_request *req )
{
	http_populate_get(req);
	http_response(req, 200, "native", 6);

	return CF_RESULT_OK;
}
