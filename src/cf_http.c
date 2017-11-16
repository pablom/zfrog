// cf_http.c

#include <sys/param.h>

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "zfrog.h"
#include "cf_http.h"

#ifdef CF_PGSQL
    #include "cf_pgsql.h"
#endif

#ifdef CF_TASKS
    #include "cf_tasks.h"
#endif

#ifdef CF_PYTHON
    #include "cf_python.h"
#endif

static int	http_body_recv(struct netbuf *);
static void	http_error_response(struct connection *, int);
static void	http_write_response_cookie(struct http_cookie *);
static void	http_argument_add(struct http_request *, char *, char *);
static void	http_response_normal(struct http_request *, struct connection *, int, const void *, size_t);
static void	multipart_add_field(struct http_request *, struct cf_buf *, char *, const char *, const int);
static void	multipart_file_add(struct http_request *, struct cf_buf *, const char *, const char *, const char *, const int);
static int	multipart_find_data(struct cf_buf *, struct cf_buf *, size_t *, struct http_request *, const void *, size_t);
static int	multipart_parse_headers(struct http_request *, struct cf_buf *, struct cf_buf *, const char *, const int);

static struct cf_buf    *header_buf;
static struct cf_buf	*ckhdr_buf;
static char             http_version[32];
static uint16_t         http_version_len;

static TAILQ_HEAD(, http_request)	http_requests;
static TAILQ_HEAD(, http_request)	http_requests_sleeping;
static struct cf_mem_pool http_request_pool;
static struct cf_mem_pool http_header_pool;
static struct cf_mem_pool http_cookie_pool;
static struct cf_mem_pool http_host_pool;
static struct cf_mem_pool http_path_pool;
static struct cf_mem_pool http_body_path;

int       http_request_count = 0;
uint32_t  http_request_limit = HTTP_REQUEST_LIMIT;
uint64_t  http_hsts_enable = HTTP_HSTS_ENABLE;
uint16_t  http_header_max = HTTP_HEADER_MAX_LEN;
uint16_t  http_keepalive_time = HTTP_KEEPALIVE_TIME;
uint64_t  http_body_max = HTTP_BODY_MAX_LEN;
uint64_t  http_body_disk_offload = HTTP_BODY_DISK_OFFLOAD;
char      *http_body_disk_path = HTTP_BODY_DISK_PATH;

/****************************************************************
 *  HTTP global init
 ****************************************************************/
void http_init( void )
{
    int	prealloc, l;

	TAILQ_INIT(&http_requests);
	TAILQ_INIT(&http_requests_sleeping);

    header_buf = cf_buf_alloc(HTTP_HEADER_BUFSIZE);
    ckhdr_buf = cf_buf_alloc(HTTP_COOKIE_BUFSIZE);

    l = snprintf(http_version, sizeof(http_version), "server: zfrog (%d.%d.%d-%s)\r\n", CF_VERSION_MAJOR, CF_VERSION_MINOR, CF_VERSION_PATCH, CF_VERSION_STATE);

    if( l == -1 || (size_t)l >= sizeof(http_version) )
		cf_fatal("http_init(): http_version buffer too small");

	http_version_len = l;

	prealloc = MIN((worker_max_connections / 10), 1000);
    cf_mem_pool_init(&http_request_pool, "http_request_pool", sizeof(struct http_request), prealloc);
    cf_mem_pool_init(&http_header_pool, "http_header_pool", sizeof(struct http_header), prealloc * HTTP_REQ_HEADER_MAX);
    cf_mem_pool_init(&http_cookie_pool, "http_cookie_pool", sizeof(struct http_cookie), prealloc * HTTP_MAX_COOKIES);
    cf_mem_pool_init(&http_host_pool, "http_host_pool", CF_DOMAINNAME_LEN, prealloc);
    cf_mem_pool_init(&http_path_pool, "http_path_pool", HTTP_URI_LEN, prealloc);
    cf_mem_pool_init(&http_body_path, "http_body_path", HTTP_BODY_PATH_MAX, prealloc);
}
/****************************************************************
 *  HTTP global cleanup
 ****************************************************************/
void http_cleanup(void)
{
    if( header_buf != NULL )
    {
        cf_buf_free(header_buf);
		header_buf = NULL;
	}

    if( ckhdr_buf != NULL )
    {
        cf_buf_free(ckhdr_buf);
        ckhdr_buf = NULL;
    }

    cf_mem_pool_cleanup( &http_request_pool );
    cf_mem_pool_cleanup( &http_header_pool );
    cf_mem_pool_cleanup( &http_cookie_pool );
    cf_mem_pool_cleanup( &http_host_pool );
    cf_mem_pool_cleanup( &http_path_pool );
    cf_mem_pool_cleanup( &http_body_path );
}
/****************************************************************
 *  Set HTTP server version string
 ****************************************************************/
void http_server_version( const char *version )
{
    int l = snprintf(http_version, sizeof(http_version), "server: %s\r\n", version);
    if( l == -1 || (size_t)l >= sizeof(http_version) )
        cf_fatal("http_server_version(): http_version buffer too small");

    http_version_len = l;
}
/****************************************************************
 *  Create new one request structure from incoming connection
 ****************************************************************/
int http_request_new( struct connection *c, const char *host,
                      const char *method, const char *path, const char *version,
                      struct http_request **out )
{
    char* p = NULL;
    char* hp = NULL;
    struct http_request *req = NULL;
    struct cf_module_handle	*hdlr = NULL;
    int	m, flags;
    size_t hostlen, pathlen, qsoff;

    log_debug("http_request_new(%p, %s, %s, %s, %s)", c, host, method, path, version);

    if( (hostlen = strlen(host)) >= CF_DOMAINNAME_LEN - 1)
    {
        http_error_response(c, 400);
        return CF_RESULT_ERROR;
    }

    if( (pathlen = strlen(path)) >= HTTP_URI_LEN - 1 )
    {
        http_error_response(c, 414);
        return CF_RESULT_ERROR;
    }

    if( strcasecmp(version, "http/1.1") )
    {
        http_error_response(c, 505);
        return CF_RESULT_ERROR;
    }

    if( (p = strchr(path, '?')) != NULL )
    {
        *p = '\0';
        qsoff = p - path;
    }
    else {
        qsoff = 0;
    }

    switch( c->addrtype )
    {
    case AF_INET6:
        if( *host == '[' )
        {
            if( (hp = strrchr(host, ']')) == NULL )
            {
                http_error_response(c, 400);
                return CF_RESULT_ERROR;
            }
            hp++;
            if( *hp == ':' )
                *hp = '\0';
            else
                hp = NULL;
        }
        break;
    default:
        if( (hp = strrchr(host, ':')) != NULL )
            *hp = '\0';
        break;
    }

    if( (hdlr = cf_module_handler_find(host, path)) == NULL )
    {
		http_error_response(c, 404);
        return CF_RESULT_ERROR;
	}

    if( hp != NULL )
        *hp = ':';

    if( p != NULL )
		*p = '?';

    if( !strcasecmp(method, "get") )
    {
		m = HTTP_METHOD_GET;
		flags = HTTP_REQUEST_COMPLETE;
    }
    else if( !strcasecmp(method, "delete") )
    {
		m = HTTP_METHOD_DELETE;
		flags = HTTP_REQUEST_COMPLETE;
    }
    else if( !strcasecmp(method, "post") )
    {
		m = HTTP_METHOD_POST;
		flags = HTTP_REQUEST_EXPECT_BODY;
    }
    else if( !strcasecmp(method, "put") )
    {
		m = HTTP_METHOD_PUT;
		flags = HTTP_REQUEST_EXPECT_BODY;
    }
    else if( !strcasecmp(method, "head") )
    {
		m = HTTP_METHOD_HEAD;
		flags = HTTP_REQUEST_COMPLETE;
    } 
    else if( !strcasecmp(method, "options") )
    {
        m = HTTP_METHOD_OPTIONS;
        flags = HTTP_REQUEST_COMPLETE;
    }
    else
    {
		http_error_response(c, 400);
        return CF_RESULT_ERROR;
	}

    req = cf_mem_pool_get(&http_request_pool);
	req->end = 0;
	req->total = 0;
	req->start = 0;
	req->owner = c;
	req->status = 0;
	req->method = m;
	req->hdlr = hdlr;
	req->agent = NULL;
	req->flags = flags;
	req->fsm_state = 0;
	req->http_body = NULL;
	req->http_body_fd = -1;
	req->hdlr_extra = NULL;
	req->query_string = NULL;
	req->http_body_length = 0;
	req->http_body_offset = 0;
	req->http_body_path = NULL;

#ifdef CF_PYTHON
    req->py_object = NULL;
#endif

    req->host = cf_mem_pool_get(&http_host_pool);
	memcpy(req->host, host, hostlen);
	req->host[hostlen] = '\0';

    req->path = cf_mem_pool_get(&http_path_pool);
	memcpy(req->path, path, pathlen);
	req->path[pathlen] = '\0';

    if( qsoff > 0 )
    {
		req->query_string = req->path + qsoff;
		*(req->query_string)++ = '\0';
    }
    else {
		req->query_string = NULL;
	}

	TAILQ_INIT(&(req->resp_headers));
	TAILQ_INIT(&(req->req_headers));
    TAILQ_INIT(&(req->resp_cookies));
    TAILQ_INIT(&(req->req_cookies));
	TAILQ_INIT(&(req->arguments));
	TAILQ_INIT(&(req->files));

#ifdef CF_TASKS
	LIST_INIT(&(req->tasks));
#endif

#ifdef CF_PGSQL
	LIST_INIT(&(req->pgsqls));
#endif

	http_request_count++;
	TAILQ_INSERT_HEAD(&http_requests, req, list);
	TAILQ_INSERT_TAIL(&(c->http_requests), req, olist);

    if( out != NULL )
		*out = req;

    return CF_RESULT_OK;
}
/****************************************************************
 *  Set HTTP request state as sleeping
 ****************************************************************/
void http_request_sleep( struct http_request *req )
{
    if( !(req->flags & HTTP_REQUEST_SLEEPING) )
    {
        log_debug("http_request_sleep: %p napping", req);

		req->flags |= HTTP_REQUEST_SLEEPING;
		TAILQ_REMOVE(&http_requests, req, list);
		TAILQ_INSERT_TAIL(&http_requests_sleeping, req, list);
	}
}
/****************************************************************
 *  Wakeup HTTP request from sleeping state
 ****************************************************************/
void http_request_wakeup( struct http_request *req )
{
    if( req->flags & HTTP_REQUEST_SLEEPING )
    {
        log_debug("http_request_wakeup: %p woke up", req);

		req->flags &= ~HTTP_REQUEST_SLEEPING;
		TAILQ_REMOVE(&http_requests_sleeping, req, list);
		TAILQ_INSERT_TAIL(&http_requests, req, list);
	}
}

void http_process( void )
{
    uint32_t count = 0;
    struct http_request *req, *next;

    for( req = TAILQ_FIRST(&http_requests); req != NULL; req = next )
    {
        if( count >= http_request_limit )
			break;

		next = TAILQ_NEXT(req, list);
        if( req->flags & HTTP_REQUEST_DELETE )
        {
			http_request_free(req);
			continue;
		}

        /* Sleeping requests should be in http_requests_sleeping */
        if( req->flags & HTTP_REQUEST_SLEEPING )
			cf_fatal("http_process: sleeping request on list");

        if( !(req->flags & HTTP_REQUEST_COMPLETE) )
			continue;

		count++;
		http_process_request(req);
	}
}

void http_process_request( struct http_request *req )
{
    int	r;

    log_debug("http_process_request: %p->%p (%s)", req->owner, req, req->path);

    if( req->flags & HTTP_REQUEST_DELETE || req->hdlr == NULL )
		return;

	req->start = cf_time_ms();

    if( req->hdlr->auth != NULL && !(req->flags & HTTP_REQUEST_AUTHED) )
        r = cf_auth_run(req, req->hdlr->auth);
	else
        r = CF_RESULT_OK;

    switch( r )
    {
    case CF_RESULT_OK:
        r = cf_runtime_http_request(req->hdlr->rcall, req);
		break;
    case CF_RESULT_RETRY:
		break;
    case CF_RESULT_ERROR:
		/*
         * Set r to CF_RESULT_OK so we can properly
         * flush the result from cf_auth_run()
		 */
        r = CF_RESULT_OK;
		break;
	default:
        cf_fatal("cf_auth() returned unknown %d", r);
	}
	req->end = cf_time_ms();
	req->total += req->end - req->start;

    switch( r )
    {
    case CF_RESULT_OK:
		r = net_send_flush(req->owner);
        if( r == CF_RESULT_ERROR )
            cf_connection_disconnect(req->owner);
		break;
    case CF_RESULT_ERROR:
        cf_connection_disconnect(req->owner);
		break;
    case CF_RESULT_RETRY:
		return;
	default:
		cf_fatal("A page handler returned an unknown result: %d", r);
	}

    if( req->hdlr->dom->accesslog != -1 ) {
        cf_accesslog(req);
    }

	req->flags |= HTTP_REQUEST_DELETE;
}

void http_response_header( struct http_request *req, const char *header, const char *value )
{
	struct http_header	*hdr;

    log_debug("http_response_header(%p, %s, %s)", req, header, value);

    hdr = cf_mem_pool_get(&http_header_pool);
	hdr->header = mem_strdup(header);
	hdr->value = mem_strdup(value);
	TAILQ_INSERT_TAIL(&(req->resp_headers), hdr, list);
}
/****************************************************************
 *  Delete HTTP request
 ****************************************************************/
void http_request_free( struct http_request *req )
{
#ifdef CF_TASKS
    struct cf_task	*t, *nt;
    int	pending_tasks;
#endif

#ifdef CF_PGSQL
    struct cf_pgsql	*pgsql;
#endif
    struct http_file *f, *fnext;
    struct http_arg	*q, *qnext;
    struct http_header *hdr, *next;
    struct http_cookie *ck, *cknext;

#ifdef CF_TASKS
	pending_tasks = 0;    
    for( t = LIST_FIRST(&(req->tasks)); t != NULL; t = nt )
    {
		nt = LIST_NEXT(t, rlist);
        if( !cf_task_finished(t) )
			pending_tasks++;
        else
            cf_task_destroy(t);
	}

    if (pending_tasks)
    {
        log_debug("http_request_free %d pending tasks", pending_tasks);
		return;
	}
#endif

#ifdef CF_PYTHON
    Py_XDECREF( req->py_object );
#endif

#ifdef CF_PGSQL
    while( !LIST_EMPTY(&(req->pgsqls)) )
    {
		pgsql = LIST_FIRST(&(req->pgsqls));
        cf_pgsql_cleanup(pgsql);
	}
#endif

    log_debug("http_request_free: %p->%p", req->owner, req);

    cf_mem_pool_put(&http_host_pool, req->host);
    cf_mem_pool_put(&http_path_pool, req->path);

	req->host = NULL;
	req->path = NULL;

	TAILQ_REMOVE(&http_requests, req, list);

    if( req->owner != NULL )
        TAILQ_REMOVE(&(req->owner->http_requests), req, olist);

    for( hdr = TAILQ_FIRST(&(req->resp_headers)); hdr != NULL; hdr = next )
    {
		next = TAILQ_NEXT(hdr, list);

		TAILQ_REMOVE(&(req->resp_headers), hdr, list);
		mem_free(hdr->header);
		mem_free(hdr->value);
        cf_mem_pool_put(&http_header_pool, hdr);
	}

    for( hdr = TAILQ_FIRST(&(req->req_headers)); hdr != NULL; hdr = next )
    {
		next = TAILQ_NEXT(hdr, list);

		TAILQ_REMOVE(&(req->req_headers), hdr, list);
		mem_free(hdr->header);
		mem_free(hdr->value);
        cf_mem_pool_put(&http_header_pool, hdr);
	}

    for( ck = TAILQ_FIRST(&(req->resp_cookies)); ck != NULL; ck = cknext )
    {
        cknext = TAILQ_NEXT(ck, list);

        TAILQ_REMOVE(&(req->resp_cookies), ck, list);
        mem_free(ck->name);
        mem_free(ck->value);
        mem_free(ck->path);
        mem_free(ck->domain);
        cf_mem_pool_put(&http_cookie_pool, ck);
    }

    for( ck = TAILQ_FIRST(&(req->req_cookies)); ck != NULL; ck = cknext )
    {
        cknext = TAILQ_NEXT(ck, list);

        TAILQ_REMOVE(&(req->req_cookies), ck, list);
        mem_free(ck->name);
        mem_free(ck->value);
        cf_mem_pool_put(&http_cookie_pool, ck);
    }

    for( q = TAILQ_FIRST(&(req->arguments)); q != NULL; q = qnext )
    {
		qnext = TAILQ_NEXT(q, list);

		TAILQ_REMOVE(&(req->arguments), q, list);
		mem_free(q->name);
        if( q->s_value != NULL )
			mem_free(q->s_value);
		mem_free(q);
	}

    for( f = TAILQ_FIRST(&(req->files)); f != NULL; f = fnext )
    {
		fnext = TAILQ_NEXT(f, list);
		TAILQ_REMOVE(&(req->files), f, list);

		mem_free(f->filename);
		mem_free(f->name);
		mem_free(f);
	}

    if( req->http_body != NULL )
        cf_buf_free(req->http_body);

    if( req->http_body_fd != -1 )
		(void)close(req->http_body_fd);

    if( req->http_body_path != NULL )
    {
        if( unlink(req->http_body_path) == -1 && errno != ENOENT )
        {
            cf_log(LOG_NOTICE, "failed to unlink %s: %s",
			    req->http_body_path, errno_s);
		}

        cf_mem_pool_put(&http_body_path, req->http_body_path);
	}

    if( req->hdlr_extra != NULL && !(req->flags & HTTP_REQUEST_RETAIN_EXTRA) ) {
        mem_free( req->hdlr_extra );
    }

    cf_mem_pool_put(&http_request_pool, req);
	http_request_count--;
}

void http_serveable( struct http_request *req, const void *data, size_t len, const char *etag, const char *type )
{
    char *match = NULL;

    if( req->method != HTTP_METHOD_GET )
    {
        http_response_header(req, "allow", "get");
        http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
        return;
    }

    if( http_request_header(req, "if-none-match", &match) )
    {
        if( !strcmp(match, etag) )
        {
            http_response(req, HTTP_STATUS_NOT_MODIFIED, NULL, 0);
            return;
        }
    }

    http_response_header(req, "etag", etag);
    http_response_header(req, "content-type", type);
    http_response(req, HTTP_STATUS_OK, data, len);
}

void http_response( struct http_request *req, int status, const void *d, size_t l )
{
    log_debug("http_response(%p, %d, %p, %zu)", req, status, d, l);

    if( req->owner == NULL ) {
        return;
    }

	req->status = status;

    switch( req->owner->proto )
    {
	case CONN_PROTO_HTTP:
	case CONN_PROTO_WEBSOCKET:
		http_response_normal(req, req->owner, status, d, l);
		break;
	default:
		cf_fatal("http_response() bad proto %d", req->owner->proto);
        /* NOTREACHED */
	}
}

void http_response_stream(struct http_request *req, int status, void *base, size_t len, int (*cb)(struct netbuf *), void *arg)
{
    struct netbuf *nb = NULL;

    if( req->owner == NULL ) {
        return;
    }

	req->status = status;

    switch( req->owner->proto )
    {
	case CONN_PROTO_HTTP:
		http_response_normal(req, req->owner, status, NULL, len);
		break;
	default:
		cf_fatal("http_response_stream() bad proto %d", req->owner->proto);
        /* NOTREACHED */
	}

    if( req->method != HTTP_METHOD_HEAD )
    {
		net_send_stream(req->owner, base, len, cb, &nb);
		nb->extra = arg;
	}
}

int http_request_header(struct http_request *req, const char *header, char **out)
{
    struct http_header *hdr = NULL;

    TAILQ_FOREACH(hdr, &(req->req_headers), list)
    {
        if( !strcasecmp(hdr->header, header) )
        {
			*out = hdr->value;
            return CF_RESULT_OK;
		}
	}

    if( !strcasecmp(header, "host") )
    {
        *out = req->host;
        return CF_RESULT_OK;
    }

    return CF_RESULT_ERROR;
}

int http_request_cookie( struct http_request *req, const char *cookie, char **out )
{
    struct http_cookie *ck = NULL;

    TAILQ_FOREACH(ck, &(req->req_cookies), list)
    {
        if( !strcasecmp(ck->name, cookie) )
        {
            *out = ck->value;
            return CF_RESULT_OK;
        }
    }

    return CF_RESULT_ERROR;
}
/****************************************************************
 *  Read HTTP headers from input buffer
 ****************************************************************/
int http_header_recv( struct netbuf *nb )
{
    size_t len;
    ssize_t ret;
    struct http_header	*hdr = NULL;
    struct http_request	*req = NULL;
    uint64_t bytes_left;
    uint8_t *end_headers = NULL;
    int	 h, i, v, skip, l;
    char *request[4], *host, *hbuf;
    char *p, *headers[HTTP_REQ_HEADER_MAX];
    struct connection *c = (struct connection *)nb->owner;

    log_debug("http_header_recv(%p)", nb);

    if( nb->b_len < 4 ) {
        return CF_RESULT_OK;
    }

	skip = 4;
	end_headers = cf_mem_find(nb->buf, nb->s_off, "\r\n\r\n", 4);
    if( end_headers == NULL )
    {
		end_headers = cf_mem_find(nb->buf, nb->s_off, "\n\n", 2);
        if( end_headers == NULL )
            return CF_RESULT_OK;
		skip = 2;
	}

	*end_headers = '\0';
	end_headers += skip;
	len = end_headers - nb->buf;
	hbuf = (char *)nb->buf;

	h = cf_split_string(hbuf, "\r\n", headers, HTTP_REQ_HEADER_MAX);
    if( h < 2 )
    {
		http_error_response(c, 400);
        return CF_RESULT_OK;
	}

	v = cf_split_string(headers[0], " ", request, 4);
    if( v != 3 )
    {
		http_error_response(c, 400);
        return CF_RESULT_OK;
	}

	skip = 0;
    host = NULL;

    for( i = 0; i < h; i++ )
    {
        if( strncasecmp(headers[i], "host", 4) )
			continue;

        if( (host = strchr(headers[i], ':')) == NULL )
        {
			http_error_response(c, 400);
            return CF_RESULT_OK;
		}

        *(host)++ = '\0';

        if( *host == '\0' )
        {
			http_error_response(c, 400);
            return CF_RESULT_OK;
		}

        host++;
		skip = i;
		break;
	}

    if( host == NULL )
    {
		http_error_response(c, 400);
        return CF_RESULT_OK;
	}

    if( !http_request_new(c, host, request[0], request[1], request[2], &req) )
        return CF_RESULT_OK;

    for( i = 1; i < h; i++ )
    {
        if( i == skip )
			continue;

		p = strchr(headers[i], ':');
        if( p == NULL ) {
            log_debug("malformed header: '%s'", headers[i]);
			continue;
		}

		*(p++) = '\0';
		if (*p == ' ')
			p++;
        hdr = cf_mem_pool_get(&http_header_pool);
		hdr->header = mem_strdup(headers[i]);
		hdr->value = mem_strdup(p);
		TAILQ_INSERT_TAIL(&(req->req_headers), hdr, list);

        if( req->agent == NULL &&
		    !strcasecmp(hdr->header, "user-agent"))
			req->agent = hdr->value;
	}

    if( req->flags & HTTP_REQUEST_EXPECT_BODY )
    {
        if( http_body_max == 0 )
        {
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner, 405);
            return CF_RESULT_OK;
		}

        if( !http_request_header(req, "content-length", &p) )
        {
            log_debug("expected body but no content-length");
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner, 411);
            return CF_RESULT_OK;
		}

		req->content_length = cf_strtonum(p, 10, 0, LONG_MAX, &v);
        if( v == CF_RESULT_ERROR )
        {
            log_debug("content-length invalid: %s", p);
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner, 411);
            return CF_RESULT_OK;
		}

        if( req->content_length == 0 )
        {
			req->flags |= HTTP_REQUEST_COMPLETE;
			req->flags &= ~HTTP_REQUEST_EXPECT_BODY;
            return CF_RESULT_OK;
		}

        if( req->content_length > http_body_max )
        {
            cf_log(LOG_NOTICE, "body too large (%ld > %ld)", req->content_length, http_body_max);
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner, 413);
            return CF_RESULT_OK;
		}

		req->http_body_length = req->content_length;

        if( http_body_disk_offload > 0 && req->content_length > http_body_disk_offload )
        {
            req->http_body_path = cf_mem_pool_get(&http_body_path);
            l = snprintf(req->http_body_path, HTTP_BODY_PATH_MAX, "%s/http_body.XXXXXX", http_body_disk_path);

            if( l == -1 || (size_t)l >= HTTP_BODY_PATH_MAX )
            {
				req->flags |= HTTP_REQUEST_DELETE;
				http_error_response(req->owner, 500);
                return CF_RESULT_ERROR;
			}

			req->http_body = NULL;
			req->http_body_fd = mkstemp(req->http_body_path);

            if( req->http_body_fd == -1 )
            {
				req->flags |= HTTP_REQUEST_DELETE;
				http_error_response(req->owner, 500);
                return CF_RESULT_OK;
			}

            ret = write(req->http_body_fd, end_headers, (nb->s_off - len));
            if( ret == -1 || (size_t)ret != (nb->s_off - len) )
            {
				req->flags |= HTTP_REQUEST_DELETE;
				http_error_response(req->owner, 500);
                return CF_RESULT_OK;
			}
        }
        else
        {
			req->http_body_fd = -1;
            req->http_body = cf_buf_alloc(req->content_length);
            cf_buf_append(req->http_body, end_headers, (nb->s_off - len));
		}

		bytes_left = req->content_length - (nb->s_off - len);

        if( bytes_left > 0 )
        {
            log_debug("%ld/%ld (%ld - %ld) more bytes for body", bytes_left, req->content_length, nb->s_off, len);
            net_recv_reset( c, MIN(bytes_left, NETBUF_SEND_PAYLOAD_MAX), http_body_recv );
			c->rnb->extra = req;
            http_request_sleep( req );
			req->content_length = bytes_left;
        }
        else if( bytes_left == 0 )
        {
			req->flags |= HTTP_REQUEST_COMPLETE;
			req->flags &= ~HTTP_REQUEST_EXPECT_BODY;
            if( !http_body_rewind(req) )
            {
				req->flags |= HTTP_REQUEST_DELETE;
				http_error_response(req->owner, 500);
                return CF_RESULT_OK;
			}
        }
        else {
			http_error_response(req->owner, 500);
		}
	}

    return CF_RESULT_OK;
}

int http_argument_get(struct http_request *req, const char *name, void **out, void *nout, int type)
{
    struct http_arg	*q = NULL;

    TAILQ_FOREACH(q, &(req->arguments), list)
    {
        if( strcmp(q->name, name) )
			continue;

        switch( type )
        {
		case HTTP_ARG_TYPE_RAW:
			*out = q->s_value;
            return CF_RESULT_OK;
		case HTTP_ARG_TYPE_BYTE:
            COPY_ARG_TYPE(*(uint8_t *)q->s_value, uint8_t);
            return CF_RESULT_OK;
		case HTTP_ARG_TYPE_INT16:
			COPY_AS_INTTYPE(SHRT_MIN, SHRT_MAX, int16_t);
            return CF_RESULT_OK;
		case HTTP_ARG_TYPE_UINT16:
            COPY_AS_INTTYPE(0, USHRT_MAX, uint16_t);
            return CF_RESULT_OK;
		case HTTP_ARG_TYPE_INT32:
			COPY_AS_INTTYPE(INT_MIN, INT_MAX, int32_t);
            return CF_RESULT_OK;
		case HTTP_ARG_TYPE_UINT32:
            COPY_AS_INTTYPE(0, UINT_MAX, uint32_t);
            return CF_RESULT_OK;
		case HTTP_ARG_TYPE_INT64:
			COPY_AS_INTTYPE_64(int64_t, 1);
            return CF_RESULT_OK;
		case HTTP_ARG_TYPE_UINT64:
            COPY_AS_INTTYPE_64(uint64_t, 0);
            return CF_RESULT_OK;
		case HTTP_ARG_TYPE_STRING:
			*out = q->s_value;
            return CF_RESULT_OK;
		default:
			break;
		}

        return CF_RESULT_ERROR;
	}

    return CF_RESULT_ERROR;
}
/****************************************************************
 *  Helper function to url HTTP decode argument
 ****************************************************************/
int http_argument_urldecode( char *arg )
{
    uint8_t	v;
    int	err;
    size_t len = strlen(arg);
    char *p = arg;
    char *in = arg;
    char h[5];

    while( *p != '\0' && p < (arg + len) )
    {
        if( *p == '+' )
			*p = ' ';
        if( *p != '%' )
        {
			*in++ = *p++;
			continue;
		}

        if( (p + 2) >= (arg + len) )
        {
            log_debug("overflow in '%s'", arg);
            return CF_RESULT_ERROR;
		}

        if( !isxdigit(*(p + 1)) || !isxdigit(*(p + 2)) )
        {
			*in++ = *p++;
			continue;
		}

		h[0] = '0';
		h[1] = 'x';
		h[2] = *(p + 1);
		h[3] = *(p + 2);
		h[4] = '\0';

		v = cf_strtonum(h, 16, 0, 255, &err);
        if( err != CF_RESULT_OK )
            return err;

		*in++ = (char)v;
		p += 3;
	}

	*in = '\0';
    return CF_RESULT_OK;
}

struct http_file* http_file_lookup(struct http_request *req, const char *name)
{
    struct http_file *f = NULL;

    TAILQ_FOREACH(f, &(req->files), list)
    {
        if( !strcmp(f->name, name) )
            return f;
	}

    return NULL;
}

ssize_t http_file_read(struct http_file *file, void *buf, size_t len)
{
    ssize_t	ret;
    size_t toread, off;

    if( file->length < file->offset )
        return -1;

    if( (file->offset + len) < file->offset )
        return -1;

    if( (file->position + file->offset) < file->position ) {
        return -1;
    }

	off = file->position + file->offset;
	toread = MIN(len, (file->length - file->offset));
    if( toread == 0 )
        return 0;

    if( file->req->http_body_fd != -1 )
    {
        if( lseek(file->req->http_body_fd, off, SEEK_SET) == -1 )
        {
            cf_log(LOG_ERR, "http_file_read: lseek(%s): %s", file->req->http_body_path, errno_s);
            return -1;
		}

        for(;;)
        {
			ret = read(file->req->http_body_fd, buf, toread);
            if( ret == -1 )
            {
                if( errno == EINTR )
					continue;

                cf_log(LOG_ERR, "failed to read %s: %s",file->req->http_body_path, errno_s);
                return -1;
			}

            if( ret == 0 )
                return 0;
			break;
		}
    }
    else if( file->req->http_body != NULL )
    {
        if( off > file->req->http_body->length )
            return 0;
		memcpy(buf, file->req->http_body->data + off, toread);
		ret = toread;
    }
    else
    {
        cf_log(LOG_ERR, "http_file_read: called without body");
        return -1;
	}

	file->offset += (size_t)ret;
    return ret;
}

void http_file_rewind( struct http_file *file )
{
	file->offset = 0;
}

void http_response_cookie(struct http_request *req, const char *name,
                           const char *val, const char *path, time_t expires, uint32_t maxage,
                           struct http_cookie **out )
{
    struct http_cookie *ck = NULL;

    if( name == NULL || val == NULL )
        cf_fatal("http_response_cookie: invalid parameters");

    ck = cf_mem_pool_get(&http_cookie_pool);

    ck->maxage = maxage;
    ck->expires = expires;
    ck->name = mem_strdup(name);
    ck->value = mem_strdup(val);
    ck->domain = mem_strdup(req->host);
    ck->flags = HTTP_COOKIE_HTTPONLY | HTTP_COOKIE_SECURE;

    if (path != NULL)
        ck->path = mem_strdup(path);
    else
        ck->path = NULL;

    TAILQ_INSERT_TAIL(&(req->resp_cookies), ck, list);

    if( out != NULL )
        *out = ck;
}

void http_populate_cookies(struct http_request *req)
{
    struct http_cookie *ck = NULL;
    int i, v, n;
    char *c, *header, *pair[3];
    char *cookies[HTTP_MAX_COOKIES];

    if( !http_request_header(req, "cookie", &c) )
        return;

    header = mem_strdup(c);
    v = cf_split_string(header, ";", cookies, HTTP_MAX_COOKIES);
    for( i = 0; i < v; i++ )
    {
        for(c = cookies[i]; isspace(*(unsigned char *)c); c++)
            ;

        n = cf_split_string(c, "=", pair, 3);
        if (n != 2)
            continue;

        ck = cf_mem_pool_get(&http_cookie_pool);
        ck->name = mem_strdup(pair[0]);
        ck->value = mem_strdup(pair[1]);
        TAILQ_INSERT_TAIL(&(req->req_cookies), ck, list);
    }

    mem_free(header);
}
/****************************************************************
 *  Helper function to parse (populate) POSt options
 ****************************************************************/
void http_populate_post( struct http_request *req )
{
    ssize_t ret;
    int i, v;
    struct cf_buf		*body;
    char data[BUFSIZ];
    char *args[HTTP_MAX_QUERY_ARGS], *val[3], *string;

    if( req->method != HTTP_METHOD_POST )
		return;

    if( req->http_body != NULL )
    {
		body = NULL;
		req->http_body->offset = req->content_length;
        string = cf_buf_stringify(req->http_body, NULL);
    }
    else
    {
        body = cf_buf_alloc(128);
        for(;;)
        {
            if( (ret = http_body_read(req, data, sizeof(data))) == -1 )
            {
                if( body != NULL )
                    cf_buf_free(body);
                return;
            }

            if( ret == 0 )
				break;
            cf_buf_append(body, data, ret);
		}
        string = cf_buf_stringify(body, NULL);
	}

	v = cf_split_string(string, "&", args, HTTP_MAX_QUERY_ARGS);

    for( i = 0; i < v; i++ )
    {
		cf_split_string(args[i], "=", val, 3);
        if( val[0] != NULL && val[1] != NULL )
			http_argument_add(req, val[0], val[1]);
	}

    if( body != NULL )
        cf_buf_free(body);
}
/****************************************************************
 *  Helper function to parse GET options
 ****************************************************************/
void http_populate_get( struct http_request *req )
{
    int	i, v;
    char *query, *args[HTTP_MAX_QUERY_ARGS], *val[3];

    if( req->method != HTTP_METHOD_GET || req->query_string == NULL )
		return;

	query = mem_strdup(req->query_string);
	v = cf_split_string(query, "&", args, HTTP_MAX_QUERY_ARGS);

    for( i = 0; i < v; i++ )
    {
		cf_split_string(args[i], "=", val, 3);

        if( val[0] != NULL && val[1] != NULL )
			http_argument_add(req, val[0], val[1]);
	}

	mem_free(query);
}

void http_populate_multipart_form( struct http_request *req )
{
    int	h, blen;
    struct cf_buf *in, *out;
    char *type, *val, *args[3];
    char boundary[HTTP_BOUNDARY_MAX];

    if( req->method != HTTP_METHOD_POST )
		return;

    if( !http_request_header(req, "content-type", &type) )
		return;

	h = cf_split_string(type, ";", args, 3);
    if( h != 2 )
		return;

    if( strcasecmp(args[0], "multipart/form-data") )
		return;

    if( (val = strchr(args[1], '=')) == NULL )
		return;

	val++;
	blen = snprintf(boundary, sizeof(boundary), "--%s", val);
    if( blen == -1 || (size_t)blen >= sizeof(boundary) )
		return;

    in = cf_buf_alloc(128);
    out = cf_buf_alloc(128);

    if( !multipart_find_data(in, NULL, NULL, req, boundary, blen) )
    {
        cf_buf_free(in);
        cf_buf_free(out);
        return;
    }

    for(;;)
    {
        if( !multipart_find_data(in, NULL, NULL, req, "\r\n", 2) )
			break;
        if( in->offset < 4 && req->http_body_length == 0 )
			break;
        if( !multipart_find_data(in, out, NULL, req, "\r\n\r\n", 4) )
			break;
        if( !multipart_parse_headers(req, in, out, boundary, blen) )
			break;

        cf_buf_reset(out);
	}

    cf_buf_free(in);
    cf_buf_free(out);
}

int http_body_rewind( struct http_request *req )
{
    if( req->http_body_fd != -1 )
    {

        if( lseek(req->http_body_fd, 0, SEEK_SET) == -1)
        {
            cf_log(LOG_ERR, "lseek(%s) failed: %s", req->http_body_path, errno_s);
            return CF_RESULT_ERROR;
        }
    }
    else {
        cf_buf_reset(req->http_body);
    }

    req->http_body_offset = 0;
    req->http_body_length = req->content_length;

    return CF_RESULT_OK;
}

ssize_t http_body_read( struct http_request *req, void *out, size_t len )
{
    ssize_t ret;
    size_t toread;

	toread = MIN(req->http_body_length, len);
    if( toread == 0 )
        return 0;

    if( req->http_body_fd != -1 )
    {
        for(;;)
        {
			ret = read(req->http_body_fd, out, toread);
            if( ret == -1 )
            {
                if( errno == EINTR )
					continue;

                cf_log(LOG_ERR, "failed to read %s: %s", req->http_body_path, errno_s);
                return -1;
			}

            if( ret == 0 )
                return 0;
			break;
		}
    }
    else if( req->http_body != NULL )
    {
        memcpy( out, (req->http_body->data + req->http_body->offset), toread );
		req->http_body->offset += toread;
		ret = toread;
    }
    else
    {
        cf_log(LOG_ERR, "http_body_read: called without body");
        return -1;
	}

	req->http_body_length -= (size_t)ret;
	req->http_body_offset += (size_t)ret;

    return ret;
}

int http_state_run( struct http_state *states, uint8_t elm, struct http_request *req )
{
    int	r = 0;
    int done = 0;

    while( !done )
    {
        if( req->fsm_state >= elm ) {
            cf_fatal("http_state_run: fsm_state > elm (%d/%d)", req->fsm_state, elm);
		}

        log_debug("http_state_run: running %s", states[req->fsm_state].name);

		r = states[req->fsm_state].cb(req);

        switch( r )
        {
		case HTTP_STATE_ERROR:
            return CF_RESULT_OK;
		case HTTP_STATE_RETRY:
            return CF_RESULT_RETRY;
		case HTTP_STATE_CONTINUE:
			break;
		case HTTP_STATE_COMPLETE:
			done = 1;
			break;
		default:
			cf_fatal("http_state_run: unknown return value %d", r);
		}
	}

	req->fsm_state = 0;
    log_debug("http_state_run(%p): done", req);

    return CF_RESULT_OK;
}

int http_state_exists( struct http_request *req )
{
    return (req->hdlr_extra != NULL);
}

void* http_state_create(struct http_request *req, size_t len)
{
    if( req->hdlr_extra != NULL )
    {
        if( req->state_len != len )
            cf_fatal("http_state_create: state already set");
    }
    else
    {
        req->state_len = len;
        req->hdlr_extra = mem_calloc(1, len);
    }

    return req->hdlr_extra;
}

void * http_state_get( struct http_request *req )
{
    return req->hdlr_extra;
}

void http_state_cleanup( struct http_request *req )
{
    mem_free(req->hdlr_extra);
    req->hdlr_extra = NULL;
}

static int multipart_find_data(struct cf_buf *in, struct cf_buf *out, size_t *olen, struct http_request *req, const void *needle, size_t len)
{
    ssize_t	ret;
    size_t left;
    uint8_t *p, first, data[4096];

    if( olen != NULL )
		*olen = 0;

    first = *(const uint8_t *)needle;
    for(;;)
    {
        if( in->offset < len )
        {
			ret = http_body_read(req, data, sizeof(data));
            if( ret == -1 )
                return CF_RESULT_ERROR;
            if( ret == 0 )
                return CF_RESULT_ERROR;

            cf_buf_append(in, data, ret);
			continue;
		}

		p = cf_mem_find(in->data, in->offset, &first, 1);
        if( p == NULL )
        {
            if( out != NULL )
                cf_buf_append(out, in->data, in->offset);
            if( olen != NULL )
				*olen += in->offset;
            cf_buf_reset(in);
			continue;
		}

		left = in->offset - (p - in->data);
        if( left < len )
        {
            if( out != NULL )
                cf_buf_append(out, in->data, (p - in->data));
            if( olen != NULL )
				*olen += (p - in->data);
			memmove(in->data, p, left);
			in->offset = left;
			continue;
		}

        if( !memcmp(p, needle, len) )
        {
            if( out != NULL )
                cf_buf_append(out, in->data, p - in->data);
            if( olen != NULL )
				*olen += (p - in->data);

			in->offset = left - len;
            if( in->offset > 0 )
                memmove(in->data, p + len, in->offset);
            return CF_RESULT_OK;
		}

        if( out != NULL )
            cf_buf_append(out, in->data, (p - in->data) + 1);

        if( olen != NULL )
			*olen += (p - in->data) + 1;

		in->offset = left - 1;
        if( in->offset > 0 )
			memmove(in->data, p + 1, in->offset);
	}

    return CF_RESULT_ERROR;
}

static int multipart_parse_headers(struct http_request *req, struct cf_buf *in, struct cf_buf *hbuf, const char *boundary, const int blen)
{
    int	h, c, i;
    char *headers[5], *args[5], *opt[5];
    char *d, *val, *name, *fname, *string;

    string = cf_buf_stringify(hbuf, NULL);
	h = cf_split_string(string, "\r\n", headers, 5);
    for( i = 0; i < h; i++ )
    {
		c = cf_split_string(headers[i], ":", args, 5);
        if( c != 2 )
			continue;

        /* Ignore other headers for now */
        if( strcasecmp(args[0], "content-disposition") )
			continue;

        for( d = args[1]; isspace(*d); d++ )
			;

		c = cf_split_string(d, ";", opt, 5);
        if( c < 2 )
			continue;

        if( strcasecmp(opt[0], "form-data") )
			continue;

        if( (val = strchr(opt[1], '=')) == NULL )
			continue;
        if( strlen(val) < 3 )
			continue;

		val++;
		cf_strip_chars(val, '"', &name);

        if( opt[2] == NULL )
        {
			multipart_add_field(req, in, name, boundary, blen);
			mem_free(name);
			continue;
		}

        for( d = opt[2]; isspace(*d); d++ )
			;

        if( !strncasecmp(d, "filename=", 9) )
        {
            if( (val = strchr(d, '=')) == NULL )
            {
				mem_free(name);
				continue;
			}

			val++;
			cf_strip_chars(val, '"', &fname);
            if( strlen(fname) > 0 ) {
                multipart_file_add(req, in, name, fname, boundary, blen);
			}
			mem_free(fname);
        }
        else {
            log_debug("got unknown: %s", opt[2]);
		}

		mem_free(name);
	}

    return CF_RESULT_OK;
}

static void multipart_add_field(struct http_request *req, struct cf_buf *in, char *name, const char *boundary, const int blen)
{
    struct cf_buf	*data = NULL;
    char *string = NULL;

    data = cf_buf_alloc(128);

    if( !multipart_find_data(in, data, NULL, req, boundary, blen) )
    {
        cf_buf_free(data);
		return;
	}

    if( data->offset < 3 )
    {
        cf_buf_free(data);
		return;
	}

	data->offset -= 2;
    string = cf_buf_stringify(data, NULL);
	http_argument_add(req, name, string);
    cf_buf_free(data);
}

static void multipart_file_add(struct http_request *req, struct cf_buf *in, const char *name, const char *fname, const char *boundary, const int blen)
{
    struct http_file *f = NULL;
    size_t position, len;

	position= req->http_body_offset - in->offset;
    if( !multipart_find_data(in, NULL, &len, req, boundary, blen) )
		return;

    if( len < 3 )
		return;
	len -= 2;

	f = mem_malloc(sizeof(struct http_file));
	f->req = req;
	f->offset = 0;
	f->length = len;
	f->position = position;
	f->name = mem_strdup(name);
	f->filename = mem_strdup(fname);

	TAILQ_INSERT_TAIL(&(req->files), f, list);
}

static void http_argument_add( struct http_request *req, char *name, char *value )
{
    struct http_arg	*q = NULL;
    struct cf_handler_params *p = NULL;

    http_argument_urldecode(name);

    TAILQ_FOREACH(p, &(req->hdlr->params), list)
    {
        if( p->method != req->method )
			continue;
        if( strcmp(p->name, name) )
			continue;

		http_argument_urldecode(value);
        if( !cf_validator_check(req, p->validator, value) )
			break;

		q = mem_malloc(sizeof(struct http_arg));
		q->name = mem_strdup(name);
		q->s_value = mem_strdup(value);
		TAILQ_INSERT_TAIL(&(req->arguments), q, list);
		break;
	}
}

static int http_body_recv(struct netbuf *nb)
{
    ssize_t ret;
    uint64_t bytes_left;
	struct http_request	*req = (struct http_request *)nb->extra;

    if( req->http_body_fd != -1 )
    {
		ret = write(req->http_body_fd, nb->buf, nb->s_off);
        if( ret == -1 || (size_t)ret != nb->s_off )
        {
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner, 500);
            return CF_RESULT_ERROR;
		}
    }
    else if( req->http_body != NULL )
    {
        cf_buf_append(req->http_body, nb->buf, nb->s_off);
    }
    else
    {
		req->flags |= HTTP_REQUEST_DELETE;
		http_error_response(req->owner, 500);
        return CF_RESULT_ERROR;
	}

	req->content_length -= nb->s_off;

    if( req->content_length == 0 )
    {
		nb->extra = NULL;
		http_request_wakeup(req);
		req->flags |= HTTP_REQUEST_COMPLETE;
		req->flags &= ~HTTP_REQUEST_EXPECT_BODY;
		req->content_length = req->http_body_length;

        if( !http_body_rewind(req) )
        {
			req->flags |= HTTP_REQUEST_DELETE;
			http_error_response(req->owner, 500);
            return CF_RESULT_ERROR;
		}

		net_recv_reset(nb->owner, http_header_max, http_header_recv);
    }
    else
    {
		bytes_left = req->content_length;
        net_recv_reset(nb->owner, MIN(bytes_left, NETBUF_SEND_PAYLOAD_MAX), http_body_recv);
	}

    return CF_RESULT_OK;
}

static void http_error_response(struct connection *c, int status)
{
    log_debug("http_error_response(%p, %d)", c, status);

    c->flags |= CONN_CLOSE_EMPTY;

    switch( c->proto )
    {
	case CONN_PROTO_HTTP:
		http_response_normal(NULL, c, status, NULL, 0);
		break;
	default:
        cf_fatal("http_error_response() bad protocol %d", c->proto);
		/* NOTREACHED. */
	}

    if( !net_send_flush(c) )
        cf_connection_disconnect(c);

}

static void http_response_normal( struct http_request *req, struct connection *c, int status, const void *d, size_t len )
{
    struct http_header *hdr = NULL;
    struct http_cookie *ck = NULL;
    char *conn = NULL;
    int connection_close;

    cf_buf_reset(header_buf);

    cf_buf_appendf(header_buf, "HTTP/1.1 %d %s\r\n", status, http_status_text(status));
    cf_buf_append(header_buf, http_version, http_version_len);

    if( c->flags & CONN_CLOSE_EMPTY )
		connection_close = 1;
	else
		connection_close = 0;

    if( connection_close == 0 && req != NULL )
    {
        if( http_request_header(req, "connection", &conn) )
        {
            if( (*conn == 'c' || *conn == 'C') && !strcasecmp(conn, "close") )
				connection_close = 1;
		}
	}

    /* Note that req CAN be NULL */
    if( req == NULL || req->owner->proto != CONN_PROTO_WEBSOCKET )
    {
        if( http_keepalive_time && connection_close == 0 )
        {
            cf_buf_appendf(header_buf, "connection: keep-alive\r\n");
            cf_buf_appendf(header_buf, "keep-alive: timeout=%d\r\n", http_keepalive_time);
        }
        else
        {
			c->flags |= CONN_CLOSE_EMPTY;
            cf_buf_appendf(header_buf, "connection: close\r\n");
		}
	}

    if( http_hsts_enable )
    {
        cf_buf_appendf(header_buf, "strict-transport-security: ");
        cf_buf_appendf(header_buf, "max-age=%" PRIu64 "; includeSubDomains\r\n", http_hsts_enable);
	}

    if( req != NULL )
    {
        TAILQ_FOREACH(ck, &(req->resp_cookies), list)
            http_write_response_cookie(ck);

        TAILQ_FOREACH(hdr, &(req->resp_headers), list)
        {
            cf_buf_appendf(header_buf, "%s: %s\r\n", hdr->header, hdr->value);
		}

        if( status != 204 && status >= 200 && !(req->flags & HTTP_REQUEST_NO_CONTENT_LENGTH))
        {
            cf_buf_appendf(header_buf,"content-length: %zu\r\n", len);
		}
    }
    else
    {
        if( status != 204 && status >= 200 ) {
            cf_buf_appendf(header_buf,"content-length: %zu\r\n", len);
		}
	}

    cf_buf_append(header_buf, "\r\n", 2);
	net_send_queue(c, header_buf->data, header_buf->offset);

    if( d != NULL && req != NULL && req->method != HTTP_METHOD_HEAD )
		net_send_queue(c, d, len);

    if( !(c->flags & CONN_CLOSE_EMPTY) )
		net_recv_reset(c, http_header_max, http_header_recv);
}
/***************************************************************
 *  Helper function return response cookies
 ****************************************************************/
static void http_write_response_cookie( struct http_cookie *ck )
{
    struct tm tm;
    char expires[HTTP_DATE_MAXSIZE];

    cf_buf_reset(ckhdr_buf);
    cf_buf_appendf(ckhdr_buf, "%s=%s", ck->name, ck->value);

    if( ck->path != NULL )
        cf_buf_appendf(ckhdr_buf, "; Path=%s", ck->path);
    if (ck->domain != NULL)
        cf_buf_appendf(ckhdr_buf, "; Domain=%s", ck->domain);

    if( ck->expires > 0 )
    {
        if( gmtime_r(&ck->expires, &tm) == NULL )
        {
            cf_log(LOG_ERR, "gmtime_r(): %s", errno_s);
            return;
        }

        if( strftime(expires, sizeof(expires),"%a, %d %b %y %H:%M:%S GMT", &tm) == 0 )
        {
            cf_log(LOG_ERR, "strftime(): %s", errno_s);
            return;
        }

        cf_buf_appendf(ckhdr_buf, "; Expires=%s", expires);
    }

    if( ck->maxage > 0 )
        cf_buf_appendf(ckhdr_buf, "; Max-Age=%d", ck->maxage);

    if( ck->flags & HTTP_COOKIE_HTTPONLY )
        cf_buf_appendf(ckhdr_buf, "; HttpOnly");
    if( ck->flags & HTTP_COOKIE_SECURE)
        cf_buf_appendf(ckhdr_buf, "; Secure");

    cf_buf_appendf(header_buf, "set-cookie: %s\r\n", cf_buf_stringify(ckhdr_buf, NULL));
}
/****************************************************************
 *  Helper function return HTTP status as text
 ****************************************************************/
const char* http_status_text( int status )
{
    const char *r = NULL;

    switch( status )
    {
	case HTTP_STATUS_CONTINUE:
		r = "Continue";
		break;
	case HTTP_STATUS_SWITCHING_PROTOCOLS:
		r = "Switching Protocols";
		break;
	case HTTP_STATUS_OK:
		r = "OK";
		break;
	case HTTP_STATUS_CREATED:
		r = "Created";
		break;
	case HTTP_STATUS_ACCEPTED:
		r = "Accepted";
		break;
	case HTTP_STATUS_NON_AUTHORITATIVE:
		r = "Non-Authoritative Information";
		break;
	case HTTP_STATUS_NO_CONTENT:
		r = "No Content";
		break;
	case HTTP_STATUS_RESET_CONTENT:
		r = "Reset Content";
		break;
	case HTTP_STATUS_PARTIAL_CONTENT:
		r = "Partial Content";
		break;
	case HTTP_STATUS_MULTIPLE_CHOICES:
		r = "Multiple Choices";
		break;
	case HTTP_STATUS_MOVED_PERMANENTLY:
		r = "Moved Permanently";
		break;
	case HTTP_STATUS_FOUND:
		r = "Found";
		break;
	case HTTP_STATUS_SEE_OTHER:
		r = "See Other";
		break;
	case HTTP_STATUS_NOT_MODIFIED:
		r = "Not Modified";
		break;
	case HTTP_STATUS_USE_PROXY:
		r = "Use Proxy";
		break;
	case HTTP_STATUS_TEMPORARY_REDIRECT:
		r = "Temporary Redirect";
		break;
	case HTTP_STATUS_BAD_REQUEST:
		r = "Bad Request";
		break;
	case HTTP_STATUS_UNAUTHORIZED:
		r = "Unauthorized";
		break;
	case HTTP_STATUS_PAYMENT_REQUIRED:
		r = "Payment Required";
		break;
	case HTTP_STATUS_FORBIDDEN:
		r = "Forbidden";
		break;
	case HTTP_STATUS_NOT_FOUND:
		r = "Not Found";
		break;
	case HTTP_STATUS_METHOD_NOT_ALLOWED:
		r = "Method Not Allowed";
		break;
	case HTTP_STATUS_NOT_ACCEPTABLE:
		r = "Not Acceptable";
		break;
	case HTTP_STATUS_PROXY_AUTH_REQUIRED:
		r = "Proxy Authentication Required";
		break;
	case HTTP_STATUS_REQUEST_TIMEOUT:
		r = "Request Time-out";
		break;
	case HTTP_STATUS_CONFLICT:
		r = "Conflict";
		break;
	case HTTP_STATUS_GONE:
		r = "Gone";
		break;
	case HTTP_STATUS_LENGTH_REQUIRED:
		r = "Length Required";
		break;
	case HTTP_STATUS_PRECONDITION_FAILED:
		r = "Precondition Failed";
		break;
	case HTTP_STATUS_REQUEST_ENTITY_TOO_LARGE:
		r = "Request Entity Too Large";
		break;
	case HTTP_STATUS_REQUEST_URI_TOO_LARGE:
		r = "Request-URI Too Large";
		break;
	case HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE:
		r = "Unsupported Media Type";
		break;
	case HTTP_STATUS_REQUEST_RANGE_INVALID:
		r = "Requested range not satisfiable";
		break;
	case HTTP_STATUS_EXPECTATION_FAILED:
		r = "Expectation Failed";
		break;
	case HTTP_STATUS_INTERNAL_ERROR:
		r = "Internal Server Error";
		break;
	case HTTP_STATUS_NOT_IMPLEMENTED:
		r = "Not Implemented";
		break;
	case HTTP_STATUS_BAD_GATEWAY:
		r = "Bad Gateway";
		break;
	case HTTP_STATUS_SERVICE_UNAVAILABLE:
		r = "Service Unavailable";
		break;
	case HTTP_STATUS_GATEWAY_TIMEOUT:
		r = "Gateway Time-out";
		break;
	case HTTP_STATUS_BAD_VERSION:
		r = "HTTP Version not supported";
		break;
	default:
		r = "";
		break;
	}

    return r;
}
/****************************************************************
 *  Helper function return HTTP method as text
 ****************************************************************/
const char* http_method_text( int method )
{
    char *r = NULL;

    switch( method )
    {
	case HTTP_METHOD_GET:
		r = "GET";
		break;
	case HTTP_METHOD_POST:
		r = "POST";
		break;
	case HTTP_METHOD_PUT:
		r = "PUT";
		break;
	case HTTP_METHOD_DELETE:
		r = "DELETE";
		break;
	case HTTP_METHOD_HEAD:
		r = "HEAD";
		break;
    case HTTP_METHOD_OPTIONS:
        r = "OPTIONS";
        break;
	default:
		r = "";
		break;
	}

    return r;
}
/****************************************************************
 *  Helper function return remote client address
 ****************************************************************/
char* http_remote_addr( struct http_request *request )
{
    static char astr[INET6_ADDRSTRLEN];
    char *real_ip = NULL;

    http_request_header(request, "x-forwarded-for", &real_ip);
    if( real_ip )
        return real_ip;

    http_request_header(request, "x-real-ip", &real_ip);
    if( real_ip )
        return real_ip;

    switch( request->owner->addrtype )
    {
        case AF_INET:
            inet_ntop(AF_INET, &(request->owner->addr.ipv4.sin_addr), astr, INET_ADDRSTRLEN);
            break;
        case AF_INET6:
            inet_ntop(AF_INET6, &(request->owner->addr.ipv6.sin6_addr), astr, INET6_ADDRSTRLEN);
            break;
        default:
            return NULL;

    }

    return astr;
}
/****************************************************************
 *  Helper function get cookie by name
 ****************************************************************/
const char* http_get_cookie( struct http_request *request, const char *name )
{
    char *pch = NULL;
    char iskey = 1;
    char isfound = 0;
    char *cookies = NULL;

    http_request_header(request, "cookie", &cookies);
    if( cookies == NULL )
        return NULL;

    pch = strtok(cookies, " ;=");
    while( pch != NULL )
    {
        if( iskey )
        {
            if( !strcmp(pch, name) )
                isfound = 1;
            iskey = 0;
        }
        else
        {
            if( isfound )
                return pch;
            iskey = 1;
        }

        pch = strtok(NULL, " ;=");
    }

    return NULL;
}
