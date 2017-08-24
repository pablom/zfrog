
#include <zfrog.h>
#include <cf_http.h>

static char *html = "<html><body><h1>Reload this page</h1></body></html>";

int	serve_cookies(struct http_request *);

int serve_cookies(struct http_request *req)
{
	char *value = NULL;
	struct http_cookie *cookie = NULL;

	http_populate_cookies(req);

	if( http_request_cookie(req, "Simple", &value) )
		cf_log(LOG_DEBUG, "Got simple: %s", value);
	if( http_request_cookie(req, "Complex", &value) )
		cf_log(LOG_DEBUG, "Got complex: %s", value);
	if( http_request_cookie(req, "Formatted", &value) )
		cf_log(LOG_DEBUG, "Got formatted: %s", value);

	/* no expire, no maxage for current path. */
	http_response_cookie(req, "Simple", "Hello World!", req->path, 0, 0, NULL);

	/* expire, no maxage, for /secure. */
	http_response_cookie(req, "Complex", "Secure Value!", "/secure", time(NULL) + (1 * 60 * 60), 0, NULL);

	/* maxage, no httponly, for current path. */
	http_response_cookie(req, "key", "value", req->path, 0, 60, &cookie);
	cookie->flags &= ~HTTP_COOKIE_HTTPONLY;

	/* set formatted cookie via header directly. */
	http_response_header(req, "set-cookie", "Formatted=TheValue; Path=/vault; HttpOnly");

	http_response(req, 200, html, strlen(html));

	return CF_RESULT_OK;
}
