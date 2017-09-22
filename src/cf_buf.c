// cf_buf.c

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "zfrog.h"

/****************************************************************
 *  Allocate buffer with initial size
 ****************************************************************/
struct cf_buf* cf_buf_alloc( size_t initial_size )
{
    struct cf_buf *buf = mem_malloc( sizeof(*buf) );
    cf_buf_init(buf, initial_size);
	buf->flags = CF_BUF_OWNER_API;
    return buf;
}
/****************************************************************
 *  Initial buffer structure
 ****************************************************************/
void cf_buf_init( struct cf_buf *buf, size_t initial )
{
    if( initial > 0 )
		buf->data = mem_malloc(initial);
	else
		buf->data = NULL;

	buf->length = initial;
	buf->offset = 0;
	buf->flags = 0;
}
/****************************************************************
 *  Cleanup structure elements
 ****************************************************************/
void cf_buf_cleanup( struct cf_buf *buf )
{
	mem_free(buf->data);
	buf->data = NULL;
	buf->offset = 0;
	buf->length = 0;
}
/****************************************************************
 *  Cleanup & delete structure
 ****************************************************************/
void cf_buf_free( struct cf_buf *buf )
{
    cf_buf_cleanup(buf);
    if( buf->flags & CF_BUF_OWNER_API )
		mem_free(buf);
}
/****************************************************************
 *  Helper function to append data to buffer structure
 ****************************************************************/
void cf_buf_append( struct cf_buf *buf, const void *d, size_t len )
{
    if( (buf->offset + len) < len )
        cf_fatal("overflow in cf_buf_append");

    if( (buf->offset + len) > buf->length )
    {
		buf->length += len;
		buf->data = mem_realloc(buf->data, buf->length);
	}

	memcpy((buf->data + buf->offset), d, len);
	buf->offset += len;
}
/****************************************************************
 *  Append (formatted) data to buffer structure
 ****************************************************************/
void cf_buf_appendv( struct cf_buf *buf, const char *fmt, va_list args )
{
    int l;
    va_list	copy;
    char *b, sb[BUFSIZ];

    va_copy(copy, args);

	l = vsnprintf(sb, sizeof(sb), fmt, args);
    if( l == -1 )
        cf_fatal("cf_buf_appendv(): vsnprintf error");

    if( (size_t)l >= sizeof(sb) )
    {
        l = vasprintf(&b, fmt, copy);
        if( l == -1 )
            cf_fatal("cf_buf_appendv(): error or truncation");
    }
    else {
		b = sb;
	}

    cf_buf_append(buf, b, l);
    if( b != sb )
		free(b);

    va_end(copy);
}
/****************************************************************
 *  Append (formatted) data to buffer structure
 ****************************************************************/
void cf_buf_appendf( struct cf_buf *buf, const char *fmt, ... )
{
    va_list args;

	va_start(args, fmt);
    cf_buf_appendv(buf, fmt, args);
    va_end( args );
}
/****************************************************************
 *  Return data from buffer structure as string
 ****************************************************************/
char* cf_buf_stringify( struct cf_buf *buf, size_t *len )
{
    char c;

    if( len != NULL )
		*len = buf->offset;

	c = '\0';
    cf_buf_append(buf, &c, sizeof(c));

	return ((char *)buf->data);
}
/****************************************************************
 *  Detach data buffer from structure
 ****************************************************************/
uint8_t* cf_buf_release( struct cf_buf *buf, size_t *len )
{
    uint8_t *p = NULL;

	p = buf->data;
	*len = buf->offset;

	buf->data = NULL;
    cf_buf_free(buf);

    return p;
}
/****************************************************************
 *  Helper function to replace string in buffer
 ****************************************************************/
void cf_buf_replace_string( struct cf_buf *b, char *src, void *dst, size_t len )
{
    char *key, *end, *tmp, *p;
    size_t blen, off2, nlen;

    size_t off = 0;
    size_t klen = strlen(src);

    for(;;)
    {
		blen = b->offset;
		nlen = blen + len;
		p = (char *)b->data;

		key = cf_mem_find(p + off, b->offset - off, src, klen);
        if( key == NULL )
			break;

		end = key + klen;
		off = key - p;
		off2 = ((char *)(b->data + b->offset) - end);

		tmp = mem_malloc(nlen);
		memcpy(tmp, p, off);
        if( dst != NULL )
			memcpy((tmp + off), dst, len);
		memcpy((tmp + off + len), end, off2);

		mem_free(b->data);
        b->data = (uint8_t *)tmp;
		b->offset = off + len + off2;
		b->length = nlen;

		off = off + len;
	}
}

void cf_buf_replace_position_string( struct cf_buf *b, char *pos_start, size_t pos_length, void *dst, size_t len )
{
    char *tmp = NULL;

    size_t new_len = b->offset + len;
    char* pos_end = pos_start + pos_length;
    size_t pre_len = pos_start - (char *)b->data;
    size_t post_len = ((char *)(b->data + b->offset) - pos_end);

    tmp = mem_malloc( new_len );
    memcpy(tmp, b->data, pre_len);
    if( dst != NULL )
        memcpy((tmp + pre_len), dst, len);
    memcpy((tmp + pre_len + len), pos_end, post_len);

    mem_free(b->data);
    b->data = (uint8_t *)tmp;
    b->offset = pre_len + len + post_len;
    b->length = new_len;
}

void cf_buf_replace_first_string( struct cf_buf *b, char *src, void *dst, size_t len )
{
    char *pos_start, *pos_end, *tmp;
    size_t pre_len, post_len, new_len, pos_length;

    pos_length = strlen(src);
    pos_start = cf_mem_find(b->data, b->offset, src, pos_length);
    if( pos_start == NULL )
        return;

    new_len = b->offset + len;
    pos_end = pos_start + pos_length;
    pre_len = pos_start - (char *)b->data;
    post_len = ((char *)(b->data + b->offset) - pos_end);

    tmp = mem_malloc( new_len );
    memcpy(tmp, b->data, pre_len);
    if( dst != NULL )
        memcpy((tmp + pre_len), dst, len);
    memcpy((tmp + pre_len + len), pos_end, post_len);

    mem_free( b->data );
    b->data = (uint8_t *)tmp;
    b->offset = pre_len + len + post_len;
    b->length = new_len;
}


void cf_buf_reset( struct cf_buf *buf )
{
	buf->offset = 0;
}
