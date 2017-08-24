// cf_utils.c

#include <sys/time.h>

#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "zfrog.h"

static struct {
    char	*name;
	int		value;
} month_names[] = {
	{ "Jan",	0 },
	{ "Feb",	1 },
	{ "Mar",	2 },
	{ "Apr",	3 },
	{ "May",	4 },
	{ "Jun",	5 },
	{ "Jul",	6 },
	{ "Aug",	7 },
	{ "Sep",	8 },
	{ "Oct",	9 },
	{ "Nov",	10 },
	{ "Dec",	11 },
	{ NULL,		0 },
};

static char b64table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#if (__sun && __SVR4)

static char *strsep (char **stringp, const char *delim)
{
  char *begin, *end;

  begin = *stringp;
  if( begin == NULL )
      return NULL;

  /* A frequent case is when the delimiter string contains only one
     character.  Here we don't need to call the expensive `strpbrk'
     function and instead work using `strchr'.  */
  if (delim[0] == '\0' || delim[1] == '\0')
    {
      char ch = delim[0];

      if (ch == '\0')
    end = NULL;
      else
    {
      if (*begin == ch)
        end = begin;
      else if (*begin == '\0')
        end = NULL;
      else
        end = strchr (begin + 1, ch);
    }
    }
  else
    /* Find the end of the token.  */
    end = strpbrk (begin, delim);

  if (end)
    {
      /* Terminate the token and set *STRINGP past NUL character.  */
      *end++ = '\0';
      *stringp = end;
    }
  else
    /* No more delimiters; this is the last token.  */
    *stringp = NULL;

  return begin;
}

#endif

void log_debug_internal(char *file, int line, const char *fmt, ...)
{
    va_list	args;
    char buf[2048];

	va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

    printf("[%d] %s:%d - %s\n", (int)cf_pid, file, line, buf);
}

void cf_log_init( void )
{
#if defined(CF_SINGLE_BINARY)
    extern const char *__progname;
    const char *name = __progname;
#else
    const char *name = "zfrog";
#endif

    if( !foreground )
		openlog(name, LOG_NDELAY | LOG_PID, LOG_DAEMON);
}

void cf_log(int prio, const char *fmt, ...)
{
    va_list	args;
    char buf[2048], tmp[32];

	va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

    if( worker != NULL )
    {
        snprintf(tmp, sizeof(tmp), "wrk %d", worker->id);
#ifndef CF_NO_TLS
        if( worker->id == CF_WORKER_KEYMGR )
            cf_strlcpy(tmp, "keymgr", sizeof(tmp));
#endif
        if( foreground )
			printf("[%s]: %s\n", tmp, buf);
		else
			syslog(prio, "[%s]: %s", tmp, buf);
    }
    else
    {
        if( foreground )
			printf("[parent]: %s\n", buf);
		else
			syslog(prio, "[parent]: %s", buf);
	}
}

size_t cf_strlcpy(char *dst, const char *src, const size_t len)
{
    char *d = dst;
    const char *s = src;
    const char *end = dst + len - 1;

    if( len == 0 )
        cf_fatal("cf_strlcpy: len == 0");

    while( (*d = *s) != '\0' )
    {
        if( d == end )
        {
			*d = '\0';
			break;
		}

		d++;
		s++;
	}

    while( *s != '\0' )
		s++;

	return (s - src);
}
/*
 * Version of strncpy that ensures dest (size bytes)
 * is null-terminated.
 */
char* cf_strncpy0( char *dst, const char *src, size_t len )
{
    strncpy(dst, src, len);
    dst[len - 1] = '\0';
    return dst;
}

int cf_snprintf( char *str, size_t size, int *len, const char *fmt, ... )
{
    int	l;
    va_list args;

	va_start(args, fmt);
	l = vsnprintf(str, size, fmt, args);
	va_end(args);

    if( l == -1 || (size_t)l >= size )
        return CF_RESULT_ERROR;

    if( len != NULL )
		*len = l;

    return CF_RESULT_OK;
}

long long cf_strtonum( const char *str, int base, long long min, long long max, int *err )
{
    long long l;
    char *ep = NULL;

    if( min > max )
    {
        *err = CF_RESULT_ERROR;
        return 0;
	}

	errno = 0;
	l = strtoll(str, &ep, base);
    if( errno != 0 || str == ep || *ep != '\0' )
    {
        *err = CF_RESULT_ERROR;
        return 0;
	}

    if( l < min )
    {
        *err = CF_RESULT_ERROR;
        return 0;
	}

    if( l > max )
    {
        *err = CF_RESULT_ERROR;
        return 0;
	}

    *err = CF_RESULT_OK;
    return l;
}

uint64_t cf_strtonum64( const char *str, int sign, int *err )
{
    uint64_t l = 0;
    long long ll = 0;
    char *ep = NULL;
    int check = 1;

	ll = strtoll(str, &ep, 10);
    if( (errno == EINVAL || errno == ERANGE) &&
        (ll == LLONG_MIN || ll == LLONG_MAX))
    {
        if( sign )
        {
            *err = CF_RESULT_ERROR;
            return 0;
		}

		check = 0;
	}

    if( !sign )
    {
		l = strtoull(str, &ep, 10);
        if( (errno == EINVAL || errno == ERANGE) && l == ULONG_MAX )
        {
            *err = CF_RESULT_ERROR;
            return 0;
		}

        if( check && ll < 0 )
        {
            *err = CF_RESULT_ERROR;
            return 0;
		}
	}

    if( str == ep || *ep != '\0' )
    {
        *err = CF_RESULT_ERROR;
        return 0;
	}

    *err = CF_RESULT_OK;
    return ((sign) ? (uint64_t)ll : l);
}

int cf_split_string(char *input, const char *delim, char **out, size_t ele)
{
    int	count = 0;
    char **ap;

    if( ele == 0 )
        return 0;

    for( ap = out; ap < &out[ele - 1] &&
        (*ap = strsep(&input, delim)) != NULL;)
    {
        if( **ap != '\0' )
        {
            ap++;
            count++;
        }
    }

    *ap = NULL;
    return count;
}

void cf_strip_chars(char *in, const char strip, char **out)
{
    uint32_t len = 0;
    char *s, *p;

	len = strlen(in);
    *out = mem_malloc(len + 1);
	p = *out;

    for( s = in; s < (in + len); s++ )
    {
        if( *s == strip )
			continue;

		*p++ = *s;
	}

	*p = '\0';
}

time_t cf_date_to_time(char *http_date)
{
    time_t t;
    int err, i;
    struct tm tm, *ltm;
    char *args[7], *tbuf[5], *sdup;

	time(&t);
	ltm = localtime(&t);
    sdup = mem_strdup(http_date);

    t = CF_RESULT_ERROR;

    if( cf_split_string(sdup, " ", args, 7) != 6 )
    {
        log_debug("misformed http-date: '%s'", http_date);
        mem_free( sdup );
        return t;
	}

	memset(&tm, 0, sizeof(tm));

    tm.tm_year = cf_strtonum(args[3], 10, 1900, 2068, &err) - 1900;
    if( err == CF_RESULT_ERROR )
    {
        log_debug("misformed year in http-date: '%s'", http_date);
        mem_free( sdup );
        return t;
	}

    for( i = 0; month_names[i].name != NULL; i++ )
    {
        if( !strcmp(month_names[i].name, args[2]) )
        {
			tm.tm_mon = month_names[i].value;
			break;
		}
	}

    if( month_names[i].name == NULL )
    {
        log_debug("misformed month in http-date: '%s'", http_date);
        mem_free( sdup );
        return t;
	}

    tm.tm_mday = cf_strtonum(args[1], 10, 1, 31, &err);
    if( err == CF_RESULT_ERROR )
    {
        log_debug("misformed mday in http-date: '%s'", http_date);
        mem_free( sdup );
        return t;
	}

    if( cf_split_string(args[4], ":", tbuf, 5) != 3 )
    {
        log_debug("misformed HH:MM:SS in http-date: '%s'", http_date);
        mem_free( sdup );
        return t;
	}

    tm.tm_hour = cf_strtonum(tbuf[0], 10, 0, 23, &err);

    if( err == CF_RESULT_ERROR )
    {
        log_debug("misformed hour in http-date: '%s'", http_date);
        mem_free( sdup );
        return t;
	}

    tm.tm_min = cf_strtonum(tbuf[1], 10, 0, 59, &err);

    if( err == CF_RESULT_ERROR )
    {
        log_debug("misformed minutes in http-date: '%s'", http_date);
        mem_free( sdup );
        return t;
	}

    tm.tm_sec = cf_strtonum(tbuf[2], 10, 0, 60, &err);

    if( err == CF_RESULT_ERROR )
    {
        log_debug("misformed seconds in http-date: '%s'", http_date);
        mem_free( sdup );
        return t;
	}

	tm.tm_isdst = ltm->tm_isdst;
#if (__sun && __SVR4)
    t = mktime(&tm);
#else
	t = mktime(&tm) + ltm->tm_gmtoff;
#endif
    if( t == -1 )
    {
		t = 0;
        log_debug("mktime() on '%s' failed", http_date);
	}

    mem_free( sdup );
    return t;
}

char* cf_time_to_date( time_t now )
{
    struct tm *tm;
    static time_t last = 0;
    static char	tbuf[32];

    if( now != last )
    {
		last = now;

		tm = gmtime(&now);

        if( !strftime(tbuf, sizeof(tbuf), "%a, %d %b %Y %T GMT", tm) )
        {
            log_debug("strftime() gave us NULL (%ld)", now);
            return NULL;
		}
	}

    return tbuf;
}
/****************************************************************
 *  Helper function to get current time in milliseconds
 ****************************************************************/
uint64_t cf_time_ms()
{
    struct timeval tv;

    if( (gettimeofday( &tv, NULL) == -1) )
        return 0;

    return tv.tv_sec * 1000 + (tv.tv_usec / 1000);
}
/****************************************************************
 *  Helper function convert milliseconds to timespec structure
 ****************************************************************/
void cf_ms2ts( struct timespec *ts, uint64_t ms )
{
    ts->tv_sec = ms / 1000;
    ts->tv_nsec = (ms % 1000) * 1000000;
}
/****************************************************************
 *  Helper function BASE64 encode binary buffer
 ****************************************************************/
int cf_base64_encode( uint8_t *data, size_t len, char **out )
{
    uint32_t b;
    struct cf_buf *res = NULL;
    size_t plen, idx;
    uint8_t n, *pdata;
    int	i, padding;

    if( (len % 3) != 0 )
    {
		padding = 3 - (len % 3);
		plen = len + padding;
        if( plen < len )
            cf_fatal("plen wrapped");

        pdata = mem_malloc(plen);
		memcpy(pdata, data, len);
		memset(pdata + len, 0, padding);
    }
    else
    {
		plen = len;
		padding = 0;
		pdata = data;
	}

    res = cf_buf_alloc(plen);

	i = 2;
	b = 0;

    for(idx = 0; idx < plen; idx++)
    {
		b |= (pdata[idx] << (i * 8));
        if( i-- == 0 )
        {
            for(i = 3; i >= 0; i--)
            {
				n = (b >> (6 * i)) & 0x3f;
                if (n >= sizeof(b64table))
                {
                    log_debug("unable to encode %d", n);
                    cf_buf_free(res);
                    return CF_RESULT_ERROR;
				}

                if( idx >= len && i < padding )
					break;

                cf_buf_append(res, &(b64table[n]), 1);
			}

			b = 0;
			i = 2;
		}
	}

    for( i = 0; i < padding; i++ )
        cf_buf_append(res, (uint8_t *)"=", 1);

    if( pdata != data )
        mem_free(pdata);

    pdata = cf_buf_release(res, &plen);
    if( (plen + 1) < plen )
        cf_fatal("plen wrapped");

    *out = mem_malloc(plen + 1);
    cf_strlcpy(*out, (char *)pdata, plen + 1);
    mem_free(pdata);

    return CF_RESULT_OK;
}
/****************************************************************
 *  Helper function BASE64 decode string to binary buffer
 ****************************************************************/
int cf_base64_decode( char *in, size_t ilen, uint8_t **out, size_t *olen )
{
    int	i, c;
    struct cf_buf *res;
    uint8_t d, n, o;
    uint32_t b, len, idx;

	i = 4;
	b = 0;
	d = 0;
	c = 0;

    len = ilen > 0? ilen: strlen(in);
    res = cf_buf_alloc(len);

    for( idx = 0; idx < len; idx++ )
    {
		c = in[idx];
        if( c == '=' )
			break;

        for( o = 0; o < sizeof(b64table); o++ )
        {
            if( b64table[o] == c )
            {
				d = o;
				break;
			}
		}

        if( o == sizeof(b64table) )
        {
			*out = NULL;
            cf_buf_free(res);
            return CF_RESULT_ERROR;
		}

		b |= (d & 0x3f) << ((i - 1) * 6);
		i--;

        if( i == 0 )
        {
            for( i = 2; i >= 0; i-- )
            {
				n = (b >> (8 * i));
                cf_buf_append(res, &n, 1);
			}

			b = 0;
			i = 4;
		}
	}

    if( c == '=' )
    {
        if( i > 2 )
        {
			*out = NULL;
            cf_buf_free(res);
            return CF_RESULT_ERROR;
		}

		o = i;
        for(i = 2; i >= o; i--)
        {
			n = (b >> (8 * i));
            cf_buf_append(res, &n, 1);
		}
	}

    *out = cf_buf_release(res, olen);
    return CF_RESULT_OK;
}

void* cf_mem_find(void *src, size_t slen, void *needle, size_t len)
{
    size_t pos = 0;

    for( pos = 0; pos < slen; pos++ )
    {
        if( *((uint8_t *)src + pos) != *(uint8_t *)needle )
			continue;

        if( (slen - pos) < len )
            return NULL;

        if( !memcmp((uint8_t *)src + pos, needle, len) )
            return ((uint8_t *)src + pos);
	}

    return NULL;
}

char* cf_text_trim( char* string, size_t len )
{
    char *end = NULL;

    if( len == 0 ) {
        return string;
    }

	end = (string + len) - 1;
    while( isspace(*string) && string < end )
		string++;

    while( isspace(*end) && end > string )
		*(end)-- = '\0';

    return string;
}
/****************************************************************
 *  Helper function to read line by line from file
 ****************************************************************/
char* cf_read_line( FILE *fp, char *in, size_t len )
{
    char *p = NULL;
    char* t = NULL;

    if( fgets(in, len, fp) == NULL ) {
        return NULL;
    }

	p = in;
	in[strcspn(in, "\n")] = '\0';

    while( isspace(*p) )
		p++;

    if( p[0] == '#' || p[0] == '\0' )
    {
		p[0] = '\0';
        return p;
	}

    for( t = p; *t != '\0'; t++ )
    {
		if (*t == '\t')
			*t = ' ';
	}

    return p;
}
/****************************************************************
 *  Helper function to log and exit from application with
 *  negative response code
 ****************************************************************/
void cf_fatal( const char *fmt, ... )
{
    va_list	args;
    char buf[2048];
    extern const char *__progname;

	va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

    if( !foreground )
        cf_log(LOG_ERR, "%s", buf);

#ifndef CF_NO_TLS
    if( worker != NULL && worker->id == CF_WORKER_KEYMGR )
        cf_keymgr_cleanup();
#endif

	printf("%s: %s\n", __progname, buf);
	exit(1);
}
/****************************************************************
 *  Helper function to get proc pid path
 ****************************************************************/
int cf_proc_pidpath( pid_t pid, void *buf, size_t len )
{
    if( getpid() != pid )
    {
        errno = EACCES;
        return CF_RESULT_ERROR;
    }

#ifdef __linux__
    ssize_t path_len = 0;

    path_len = readlink("/proc/self/exe", buf, len);

    if( path_len < 0 )
        return CF_RESULT_ERROR;

    if( path_len >= (ssize_t)len)
    {
        errno = EOVERFLOW;
        return CF_RESULT_ERROR;
    }

    ((char *)buf)[path_len] = '\0';
#elif __FreeBSD__
    size_t path_len = len;
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };

    if( sysctl(mib, N_ELEMENTS(mib), buf, &path_len, NULL, 0) < 0 )
        return CF_RESULT_ERROR;
#else

    // readlink("/proc/self/path/a.out", buf, bufsize) /* Solaris */

    errno = ENOSYS;
    return CF_RESULT_ERROR;
#endif

    return CF_RESULT_OK;
}
/****************************************************************
 *  Helper function ioctl call
 ****************************************************************/
int cf_cloexec_ioctl( int fd, int set )
{
#ifdef FIONCLEX
    int rc;

    do
        rc = ioctl(fd, set ? FIOCLEX : FIONCLEX);
    while( rc == -1 && errno == EINTR );

    if( rc )
        return CF_RESULT_ERROR;
#endif

    return CF_RESULT_OK;
}
/****************************************************************
 *  Helper function to get BACKLOG socket size
 ****************************************************************/
int cf_get_backlog_size(void)
{
#ifdef SOMAXCONN
    int backlog = SOMAXCONN;
#else
    int backlog = 128;
#endif
    FILE *somaxconn;

    somaxconn = fopen("/proc/sys/net/core/somaxconn", "re");
    if( somaxconn )
    {
        int tmp;
        if( fscanf(somaxconn, "%d", &tmp) == 1 )
            backlog = tmp;
        fclose( somaxconn );
    }

    return backlog;
}
/****************************************************************
 *  Helper function to get random buffer
 ****************************************************************/
size_t cf_random_buffer( unsigned char buffer[], size_t size, int nonblock )
{
    int fd = open(nonblock ? "/dev/urandom" : "/dev/random", O_RDONLY);
    size_t datalen = 0;

    while( datalen < size )
    {
        ssize_t result = read(fd, buffer + datalen, size - datalen);
        if( result < 0 )
            break;

        datalen += result;
    }

    /* Close file descriptor */
    close( fd );

    return datalen;
}
/****************************************************************
 *  Helper function to get file extension from file name
 ****************************************************************/
const char * cf_file_extension( const char *filename )
{
    const char *dot = strrchr(filename, '.');
    if( !dot || dot == filename )
        return NULL;

    return dot + 1;
}
/****************************************************************
 *  Helper function to generate UUID
 *
 *  (d9cbd727-49f4-4147-b31c-9416cc1d1329)
 *
 *  Sample request function:
 *          cf_uuid_buffer( char uuid[37], sizeof(uuid)-1 )
 ****************************************************************/
size_t cf_uuid_buffer( char buffer[], size_t size )
{
    int fd = -1;
    size_t data_bytes = 0;

#ifdef __linux__
    if( (fd = open("/proc/sys/kernel/random/uuid", O_RDONLY)) >= 0 )
    {
        while( data_bytes < size )
        {
            ssize_t r_bytes = read(fd, buffer + data_bytes, size - data_bytes);
            if( r_bytes < 0 )
                break;

            data_bytes += r_bytes;
        }

        /* Close file descriptor */
        close( fd );

        /* So we will use the pseudo random generator */
        if( data_bytes != size )
            fd = -1;
    }
#endif

    if( fd == -1 )
    {
        size_t i = 0;
        const char random_chars[]="0123456789abcdef-";

        for( i = 0; i < size; i++ ) {
            buffer[i] = random_chars[rand()%sizeof(random_chars)];
        }

        data_bytes = size;
    }

    /* Set end of string */
    buffer[data_bytes] = 0;

    return data_bytes;
}

