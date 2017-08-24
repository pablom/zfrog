
#include <zfrog.h>
#include <cf_http.h>

#include <openssl/sha.h>

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "assets.h"

int	example_load(int);

int	serve_b64test(struct http_request *);
int	serve_file_upload(struct http_request *);
int	serve_validator(struct http_request *);
int	serve_params_test(struct http_request *);
int	serve_private(struct http_request *);
int	serve_private_test(struct http_request *);

int	v_example_func(struct http_request *, char *);
int	v_session_validate(struct http_request *, char *);
void test_base64(uint8_t *, uint32_t, struct cf_buf *);

char *b64tests[] = {
	"1234567890",
	"One two three four five",
	"Man",
	"any carnal pleasure.",
	"any carnal pleasure",
	"any carnal pleas",
	"I am a nobody, nobody is perfect, therefor I am.",
	NULL
};

int example_load(int state)
{
	switch (state) {
	case CF_MODULE_LOAD:
		cf_log(LOG_NOTICE, "module loading");

		/* Set server version */
		http_server_version("Server/0.1");
		break;
	case CF_MODULE_UNLOAD:
		cf_log(LOG_NOTICE, "module unloading");
		break;
	default:
		cf_log(LOG_NOTICE, "state %d unknown!", state);
		break;
	}

	return CF_RESULT_OK;
}

int serve_b64test( struct http_request *req )
{
	int	i;
	size_t len;
	struct cf_buf *res;
	uint8_t *data;

	res = cf_buf_alloc(1024);
	for( i = 0; b64tests[i] != NULL; i++ )
		test_base64((u_int8_t *)b64tests[i], strlen(b64tests[i]), res);

	data = cf_buf_release(res, &len);

	http_response_header(req, "content-type", "text/plain");
	http_response(req, 200, data, len);
	mem_free(data);

	return CF_RESULT_OK;
}

int serve_file_upload( struct http_request *req )
{
	uint8_t *d = NULL;
	struct cf_buf *b = NULL;
	struct http_file *f = NULL;
	size_t	len;
	char *name, buf[BUFSIZ];

	b = cf_buf_alloc(asset_len_upload_html);
	cf_buf_append(b, asset_upload_html, asset_len_upload_html);

	if( req->method == HTTP_METHOD_POST ) 
	{
		if( req->http_body_fd != -1 )
			cf_log(LOG_NOTICE, "file is on disk");

		http_populate_multipart_form(req);
		if( http_argument_get_string(req, "firstname", &name) ) 
		{
			cf_buf_replace_string(b, "$firstname$", name, strlen(name));
		} 
		else 
		{
			cf_buf_replace_string(b, "$firstname$", NULL, 0);
		}

		if( (f = http_file_lookup(req, "file")) != NULL ) 
		{
			snprintf(buf, sizeof(buf), "%s is %ld bytes", f->filename, f->length);
			cf_buf_replace_string(b, "$upload$", buf, strlen(buf));
		} 
		else 
		{
			cf_buf_replace_string(b, "$upload$", NULL, 0);
		}
	} 
	else 
	{
		cf_buf_replace_string(b, "$upload$", NULL, 0);
		cf_buf_replace_string(b, "$firstname$", NULL, 0);
	}

	d = cf_buf_release(b, &len);

	http_response_header(req, "content-type", "text/html");
	http_response(req, 200, d, len);
    mem_free(d);

	return CF_RESULT_OK;
}

void test_base64( uint8_t *src, uint32_t slen, struct cf_buf *res)
{
	char *in;
	size_t len;
	uint8_t	*out;

	cf_buf_appendf(res, "test '%s'\n", src);

	if( !cf_base64_encode(src, slen, &in) ) 
	{
		cf_buf_appendf(res, "encoding '%s' failed\n", src);
	} 
	else 
	{
		cf_buf_appendf(res, "encoded: '%s'\n", in);

        if( !cf_base64_decode(in, strlen(in) , &out, &len) )
		{
			cf_buf_appendf(res, "decoding failed\n");
		} 
		else {
			cf_buf_appendf(res, "decoded: ");
			cf_buf_append(res, out, len);
			cf_buf_appendf(res, "\n");
			mem_free( out );
		}

		mem_free(in);
	}

	cf_buf_appendf(res, "\n");
}

int serve_validator( struct http_request *req )
{
	if( cf_validator_run(NULL, "v_example", "test") )
		cf_log(LOG_NOTICE, "v_example ok (expected)");
	else
		cf_log(LOG_NOTICE, "v_example failed");

	if( cf_validator_run(NULL, "v_regex", "/test/123") )
		cf_log(LOG_NOTICE, "regex #1 ok");
	else
		cf_log(LOG_NOTICE, "regex #1 failed (expected)");

	if( cf_validator_run(NULL, "v_regex", "/test/joris") )
		cf_log(LOG_NOTICE, "regex #2 ok (expected)");
	else
		cf_log(LOG_NOTICE, "regex #2 failed");

	http_response(req, 200, "OK", 2);

	return CF_RESULT_OK;
}

int serve_params_test( struct http_request *req )
{
	struct cf_buf	*b;
	uint8_t *d;
	size_t len;
	int	r, i;
	char *test, name[10];

	if( req->method == HTTP_METHOD_GET )
		http_populate_get(req);
	else if( req->method == HTTP_METHOD_POST )
		http_populate_post(req);

	b = cf_buf_alloc(asset_len_params_html);
	cf_buf_append(b, asset_params_html, asset_len_params_html);

	/*
	 * The GET parameters will be filtered out on POST
	 */
	if( http_argument_get_string(req, "arg1", &test) ) 
	{
		cf_buf_replace_string(b, "$arg1$", test, strlen(test));
	} 
	else 
	{
		cf_buf_replace_string(b, "$arg1$", NULL, 0);
	}

	if( http_argument_get_string(req, "arg2", &test) ) 
	{
		cf_buf_replace_string(b, "$arg2$", test, strlen(test));
	} 
	else 
	{
		cf_buf_replace_string(b, "$arg2$", NULL, 0);
	}

	if( req->method == HTTP_METHOD_GET ) 
	{
		cf_buf_replace_string(b, "$test1$", NULL, 0);
		cf_buf_replace_string(b, "$test2$", NULL, 0);
		cf_buf_replace_string(b, "$test3$", NULL, 0);

		if( http_argument_get_uint16(req, "id", &r) )
			cf_log(LOG_NOTICE, "id: %d", r);
		else
			cf_log(LOG_NOTICE, "No id set");

		http_response_header(req, "content-type", "text/html");
		d = cf_buf_release(b, &len);
		http_response(req, 200, d, len);
		mem_free(d);

		return CF_RESULT_OK;
	}

	for( i = 1; i < 4; i++ ) 
	{
		snprintf(name, sizeof(name), "test%d", i);
		if( http_argument_get_string(req, name, &test) ) 
		{
			snprintf(name, sizeof(name), "$test%d$", i);
			cf_buf_replace_string(b, name, test, strlen(test));
		} 
		else 
		{
			snprintf(name, sizeof(name), "$test%d$", i);
			cf_buf_replace_string(b, name, NULL, 0);
		}
	}

	http_response_header(req, "content-type", "text/html");
	d = cf_buf_release(b, &len);
	http_response(req, 200, d, len);
	mem_free(d);

	return CF_RESULT_OK;
}

int serve_private( struct http_request *req )
{
	http_response_header(req, "content-type", "text/html");
	http_response_header(req, "set-cookie", "session_id=test123");
	http_response(req, 200, asset_private_html, asset_len_private_html);

	return CF_RESULT_OK;
}

int v_example_func( struct http_request *req, char *data )
{
	cf_log(LOG_NOTICE, "v_example_func called");

	if( !strcmp(data, "test") )
		return CF_RESULT_OK;

	return CF_RESULT_ERROR;
}

int v_session_validate(struct http_request *req, char *data)
{
	cf_log(LOG_NOTICE, "v_session_validate: %s", data);

	if( !strcmp(data, "test123") )
		return CF_RESULT_OK;

	return CF_RESULT_ERROR;
}
