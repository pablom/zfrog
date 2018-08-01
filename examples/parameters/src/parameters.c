// parameters.c

#include <zfrog.h>
#include <cf_http.h>

int	page(struct http_request *);

int page(struct http_request *req)
{
	uint16_t id = 0;
	char *sid = NULL;
	struct cf_buf *buf = NULL;

	/*
	 * Before we are able to obtain any parameters given to
	 * us via the query string we must tell zfrog to parse and
	 * validate them.
	 *
	 * NOTE: All parameters MUST be declared in a params {} block
	 * inside the configuration for zfrog! zfrog will filter out
	 * any parameters not explicitly defined.
	 *
	 * See conf/parameters.conf on how that is done, this is an
	 * important step as without the params block you will never
	 * get any parameters returned from zfrog.
	 */
	http_populate_get(req);

	/*
	 * Lets grab the "id" parameter if available. zfrog can obtain
	 * parameters in different data types native to C.
	 *
	 * In this scenario, lets grab it both as an actual string and
     * as an uint16_t (unsigned short).
	 *
	 * When trying to obtain a parameter as something else then
	 * a string, zfrog will automatically check if the value fits
	 * in said data type.
	 *
     * For example if id is 65536 it won't fit in an uint16_t
	 * and zfrog will return an error when trying to read it as such.
	 */

	buf = cf_buf_alloc(128);

	/* Grab it as a string, we shouldn't free the result in sid */
	if( http_argument_get_string(req, "id", &sid) )
		cf_buf_appendf(buf, "id as a string: '%s'\n", sid);

    /* Grab it as an actual uint16_t */
	if (http_argument_get_uint16(req, "id", &id))
		cf_buf_appendf(buf, "id as an uint16_t: %d\n", id);

	/* Now return the result to the client with a 200 status code */
	http_response(req, 200, buf->data, buf->offset);
	cf_buf_free(buf);

	return CF_RESULT_OK;
}
