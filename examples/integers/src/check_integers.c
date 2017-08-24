#include <zfrog.h>
#include <cf_http.h>

int page( struct http_request * );

int page( struct http_request *req )
{
	int16_t			s16;
	uint16_t		u16;
	int32_t			s32;
	int64_t			s64;
	uint64_t		u64;
	uint32_t		u32;
	size_t			len;
	struct cf_buf		*buf;
	uint8_t		c, *data;

	http_populate_get(req);
	buf = cf_buf_alloc(128);

	if( http_argument_get_byte(req, "id", &c) )
		cf_buf_appendf(buf, "byte\t%c\n", c);

	if( http_argument_get_int16(req, "id", &s16) )
		cf_buf_appendf(buf, "int16\t%d\n", s16);

	if( http_argument_get_uint16(req, "id", &u16) )
		cf_buf_appendf(buf, "uint16\t%d\n", u16);

	if( http_argument_get_int32(req, "id", &s32) )
		cf_buf_appendf(buf, "int32\t%d\n", s32);

	if( http_argument_get_uint32(req, "id", &u32) )
		cf_buf_appendf(buf, "uint32\t%d\n", u32);

	if( http_argument_get_int64(req, "id", &s64) )
		cf_buf_appendf(buf, "int64\t%ld\n", s64);

	if( http_argument_get_uint64(req, "id", &u64) )
		cf_buf_appendf(buf, "uint64\t%lu\n", u64);

	data = cf_buf_release(buf, &len);
	http_response(req, 200, data, len);
	mem_free(data);

	return CF_RESULT_OK;
}
