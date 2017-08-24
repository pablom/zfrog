// cf_mustach.c


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "zfrog.h"

#define NAME_LENGTH_MAX   1024
#define DEPTH_MAX         256

/* Forward function declaration */
static int getpartial(struct cf_mustach_itf *itf, void *closure, const char *name, char **result);
static int process(const char *template, struct cf_mustach_itf *itf, void *closure, FILE *file, const char *opstr, const char *clstr);

static int getpartial(struct cf_mustach_itf *itf, void *closure, const char *name, char **result)
{
	int rc;
    FILE *file = NULL;
    size_t size = 0;

	*result = NULL;

    if( (file = open_memstream(result, &size)) == NULL )
        rc = CF_MUSTACH_ERROR_SYSTEM;
    else
    {
        if( (rc = itf->put(closure, name, 0, file)) == 0 )
            rc = fputc(0, file) ? CF_MUSTACH_ERROR_SYSTEM : 0; /* adds terminating null */

        fclose( file );

        if( rc < 0 )
        {
			free(*result);
			*result = NULL;
		}
	}

	return rc;
}

static int process(const char *template, struct cf_mustach_itf *itf, void *closure, FILE *file, const char *opstr, const char *clstr)
{
	char name[NAME_LENGTH_MAX + 1], *partial, c;
	const char *beg, *term;
	struct { const char *name, *again; size_t length; int emit, entered; } stack[DEPTH_MAX];
	size_t oplen, cllen, len, l;
	int depth, rc, emit;

	emit = 1;
	oplen = strlen(opstr);
	cllen = strlen(clstr);
	depth = 0;

    for(;;)
    {
        if( (beg = strstr(template, opstr)) == NULL )
        {
			/* no more mustach */
            if( emit )
				fwrite(template, strlen(template), 1, file);
            return depth ? CF_MUSTACH_ERROR_UNEXPECTED_END : 0;
		}

        if( emit )
			fwrite(template, (size_t)(beg - template), 1, file);

        if( (term = strstr(template, clstr)) == NULL )
            return CF_MUSTACH_ERROR_UNEXPECTED_END;

		template = term + cllen;
		beg += oplen;
		len = (size_t)(term - beg);
		c = *beg;

        switch( c )
        {
		case '!':
		case '=':
			break;
		case '{':
            for(l = 0 ; clstr[l] == '}' ; l++);
            if( clstr[l] )
            {
                if( !len || beg[len-1] != '}' )
                    return CF_MUSTACH_ERROR_BAD_UNESCAPE_TAG;
				len--;
            }
            else
            {
                if( term[l] != '}')
                    return CF_MUSTACH_ERROR_BAD_UNESCAPE_TAG;
				template++;
			}
			c = '&';
		case '^':
		case '#':
		case '/':
		case '&':
		case '>':
#if !defined(NO_EXTENSION_FOR_MUSTACH) && !defined(NO_COLON_EXTENSION_FOR_MUSTACH)
		case ':':
#endif
			beg++; len--;
		default:
			while (len && isspace(beg[0])) { beg++; len--; }
			while (len && isspace(beg[len-1])) len--;
            if( len == 0 )
                return CF_MUSTACH_ERROR_EMPTY_TAG;
            if( len > NAME_LENGTH_MAX )
                return CF_MUSTACH_ERROR_TAG_TOO_LONG;
			memcpy(name, beg, len);
			name[len] = 0;
			break;
		}
		switch(c) {
		case '!':
			/* comment */
			/* nothing to do */
			break;
		case '=':
			/* defines separators */
			if (len < 5 || beg[len - 1] != '=')
                return CF_MUSTACH_ERROR_BAD_SEPARATORS;
			beg++;
			len -= 2;
			for (l = 0; l < len && !isspace(beg[l]) ; l++);
			if (l == len)
                return CF_MUSTACH_ERROR_BAD_SEPARATORS;
			opstr = strndupa(beg, l);
			while (l < len && isspace(beg[l])) l++;
			if (l == len)
                return CF_MUSTACH_ERROR_BAD_SEPARATORS;
			clstr = strndupa(beg + l, len - l);
			oplen = strlen(opstr);
			cllen = strlen(clstr);
			break;
		case '^':
		case '#':
			/* begin section */
            if( depth == DEPTH_MAX )
                return CF_MUSTACH_ERROR_TOO_DEPTH;
			rc = emit;
            if( rc )
            {
                if( (rc = itf->enter(closure, name)) < 0 )
					return rc;
			}
			stack[depth].name = beg;
			stack[depth].again = template;
			stack[depth].length = len;
			stack[depth].emit = emit;
			stack[depth].entered = rc;
            if( (c == '#') == (rc == 0) )
				emit = 0;
			depth++;
			break;
		case '/':
			/* end section */
            if( depth-- == 0 || len != stack[depth].length || memcmp(stack[depth].name, name, len) )
                return CF_MUSTACH_ERROR_CLOSING;
			rc = emit && stack[depth].entered ? itf->next(closure) : 0;
            if( rc < 0 )
				return rc;
            if( rc )
				template = stack[depth++].again;
            else
            {
				emit = stack[depth].emit;
                if( emit && stack[depth].entered )
					itf->leave(closure);
			}
			break;
		case '>':
			/* partials */
            if( emit )
            {
                if( (rc = getpartial(itf, closure, name, &partial)) == 0 )
                {
					rc = process(partial, itf, closure, file, opstr, clstr);
					free(partial);
				}
                if( rc < 0 )
					return rc;
			}
			break;
		default:
			/* replacement */
            if( emit )
            {
                if( (rc = itf->put(closure, name, c != '&', file)) < 0 )
					return rc;
			}
			break;
		}
	}
}

int cf_fmustach(const char *template, struct cf_mustach_itf *itf, void *closure, FILE *file)
{
	int rc = itf->start ? itf->start(closure) : 0;

    if( rc == 0 )
		rc = process(template, itf, closure, file, "{{", "}}");

	return rc;
}

int cf_fdmustach(const char *template, struct cf_mustach_itf *itf, void *closure, int fd)
{
	int rc;
	FILE *file;

    if( (file = fdopen(fd, "w")) == NULL )
    {
        rc = CF_MUSTACH_ERROR_SYSTEM;
		errno = ENOMEM;
    }
    else
    {
        rc = cf_fmustach(template, itf, closure, file);
		fclose(file);
	}

	return rc;
}

int cf_mustach( const char *template, struct cf_mustach_itf *itf, void *closure, char **result, size_t *size)
{
	int rc;
    FILE *file = NULL;
	size_t s;

	*result = NULL;
    if( size == NULL )
		size = &s;

    if( (file = open_memstream(result, size)) == NULL )
    {
        rc = CF_MUSTACH_ERROR_SYSTEM;
		errno = ENOMEM;
    }
    else
    {
        if( (rc = cf_fmustach(template, itf, closure, file)) == 0 ) /* adds terminating null */
            rc = fputc(0, file) ? CF_MUSTACH_ERROR_SYSTEM : 0;

        fclose( file );

        if( rc >= 0 ) /* removes terminating null of the length */
			(*size)--;
        else
        {
			free(*result);
			*result = NULL;
			*size = 0;
		}
	}
	return rc;
}

