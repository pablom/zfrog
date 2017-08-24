
#include <zfrog.h>
#include <cf_http.h>

#include <yajl/yajl_tree.h>

int	page(struct http_request *);

int page(struct http_request *req)
{
    ssize_t	ret;
    struct cf_buf *buf = NULL;
    char *body = NULL;
    yajl_val node, v;
    char eb[1024];
    uint8_t data[BUFSIZ];
    const char *path[] = { "foo", "bar", NULL };

	/* We only allow POST/PUT methods */
	if( req->method != HTTP_METHOD_POST && req->method != HTTP_METHOD_PUT ) 
	{
		http_response_header(req, "allow", "POST, PUT");
		http_response(req, HTTP_STATUS_METHOD_NOT_ALLOWED, NULL, 0);
		return CF_RESULT_OK;
	}

	/*
	 * Read the entire received body into a memory buffer
	 */
	buf = cf_buf_alloc(128);
	for(;;) 
	{
		ret = http_body_read(req, data, sizeof(data));
		if( ret == -1 ) 
		{
			cf_buf_free(buf);
			cf_log(LOG_NOTICE, "error reading body");
			http_response(req, 500, NULL, 0);
			return CF_RESULT_OK;
		}

		if (ret == 0)
			break;

		cf_buf_append(buf, data, ret);
	}

	/* Grab our body data as a NUL-terminated string */
	body = cf_buf_stringify(buf, NULL);

	/* Parse the body via yajl now. */
	node = yajl_tree_parse(body, eb, sizeof(eb));
	if( node == NULL ) 
	{
		if( strlen(eb) ) 
		{
			cf_log(LOG_NOTICE, "parse error: %s", eb);
		} 
		else {
			cf_log(LOG_NOTICE, "parse error: unknown");
		}

		cf_buf_free(buf);
		http_response(req, 400, NULL, 0);
		return CF_RESULT_OK;
	}

	/* Reuse old buffer, don't need it anymore for body */
	cf_buf_reset(buf);

	/* Attempt to grab foo.bar from the JSON tree */
	v = yajl_tree_get(node, path, yajl_t_string);
	if( v == NULL ) 
	{
		cf_buf_appendf(buf, "no such path: foo.bar\n");
	} 
	else {
		cf_buf_appendf(buf, "foo.bar = '%s'\n", YAJL_GET_STRING(v));
	}

	/* Release the JSON tree now */
	yajl_tree_free(node);

	/* Respond to the client */
	http_response(req, 200, buf->data, buf->offset);
	cf_buf_free(buf);

	return CF_RESULT_OK;
}
