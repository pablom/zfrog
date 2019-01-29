// cf_accesslog.c

#include <sys/socket.h>
#include <poll.h>
#include <time.h>
#include <signal.h>

#include "zfrog.h"
#include "cf_http.h"


/*
 * The worker will write accesslogs to its worker data structure which is
 * held in shared memory.
 *
 * Each accesslog is prefixed with the internal domain ID (2 bytes) and
 * the length of the log entry (2 bytes) (packed in kore_alog_header).
 *
 * The parent will every 10ms fetch the produced accesslogs from the workers
 * and copy them to its own log buffer. Once this log buffer becomes full
 * or 1 second has passed the parent will parse the logs and append them
 * to the correct domain logbuffer which is eventually flushed to disk.
 */

#define LOGBUF_SIZE                 (CF_ACCESSLOG_BUFLEN * server.worker_count)
#define DOMAIN_LOGBUF_LEN           (1024 * 1024)
#define LOG_ENTRY_MINSIZE_GUESS		90

static void	accesslog_lock(struct cf_worker*);
static void	accesslog_unlock(struct cf_worker*);
static void	accesslog_flush_cb(struct cf_domain*);
static void	accesslog_flush(struct cf_domain*, uint64_t, int);

static uint64_t	time_cache = 0;
static char		tbuf[128] = { '\0' };

#ifndef CF_NO_TLS
    char cnbuf[1024] = { '\0' };
#endif

static struct cf_buf* logbuf = NULL;

void cf_accesslog_worker_init(void)
{
    cf_domain_closelogs();
}

void cf_accesslog(struct http_request *req)
{
    struct timespec ts;
    struct tm* tm;
    uint64_t now;
    struct cf_alog_header* hdr = NULL;
    size_t  avail;
    time_t  curtime;
    int	len, attempts;
    char addr[INET6_ADDRSTRLEN];
    const char  *ptr, *method, *cn, *referer;

    switch( req->method )
    {
    case HTTP_METHOD_GET:
        method = "GET";
        break;
    case HTTP_METHOD_POST:
        method = "POST";
        break;
    case HTTP_METHOD_PUT:
        method = "PUT";
        break;
    case HTTP_METHOD_DELETE:
        method = "DELETE";
        break;
    case HTTP_METHOD_HEAD:
        method = "HEAD";
        break;
    case HTTP_METHOD_PATCH:
        method = "PATCH";
        break;
    default:
        method = "UNKNOWN";
        break;
    }

    if( req->referer != NULL )
        referer = req->referer;
    else
        referer = "-";

    cn = "-";
#ifndef CF_NO_TLS
    if( req->owner->cert != NULL )
    {
        if( X509_GET_CN(req->owner->cert, cnbuf, sizeof(cnbuf)) != -1 )
            cn = cnbuf;
    }
#endif

    switch( req->owner->family )
    {
    case AF_INET:
        ptr = inet_ntop(req->owner->family,
            &(req->owner->addr.ipv4.sin_addr), addr, sizeof(addr));
        break;
    case AF_INET6:
        ptr = inet_ntop(req->owner->family,
            &(req->owner->addr.ipv6.sin6_addr), addr, sizeof(addr));
        break;
    case AF_UNIX:
        ptr = NULL;
        break;
    default:
        cf_fatal("unknown family %d", req->owner->family);
    }

    if( ptr == NULL )
    {
        addr[0] = '-';
        addr[1] = '\0';
    }

    now = cf_time_ms();
    if( (now - time_cache) >= 1000 )
    {
        time(&curtime);
        tm = localtime(&curtime);
        strftime(tbuf, sizeof(tbuf), "%d/%b/%Y:%H:%M:%S %z", tm);
        time_cache = now;
    }

    attempts = 0;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000;

    for(;;)
    {
        if( attempts++ > 1000 )
        {
            if( getppid() == 1 )
            {
                if( kill(server.worker->pid, SIGQUIT) == -1 )
                    cf_fatal("failed to shutdown");
                return;
            }

            attempts = 0;
        }

        accesslog_lock(server.worker);

        avail = CF_ACCESSLOG_BUFLEN - server.worker->lb.offset;
        if( avail < sizeof(*hdr) + LOG_ENTRY_MINSIZE_GUESS )
        {
            accesslog_unlock(server.worker);
            nanosleep(&ts, NULL);
            continue;
        }

        hdr = (struct cf_alog_header *)(server.worker->lb.buf + server.worker->lb.offset);
        server.worker->lb.offset += sizeof(*hdr);

        len = snprintf(server.worker->lb.buf + server.worker->lb.offset, avail,
            "%s - %s [%s] \"%s %s HTTP/1.1\" %d %zu \"%s\" \"%s\"\n",
            addr, cn, tbuf, method, req->path, req->status,
            req->content_length, referer, req->agent);

        if( len == -1 )
            cf_fatal("failed to create log entry");

        if( (size_t)len >= avail )
        {
            server.worker->lb.offset -= sizeof(*hdr);
            accesslog_unlock(server.worker);
            nanosleep(&ts, NULL);
            continue;
        }

        if( (size_t)len > USHRT_MAX )
        {
            cf_log(LOG_WARNING,"log entry length exceeds limit (%d)", len);
            server.worker->lb.offset -= sizeof(*hdr);
            break;
        }

        hdr->loglen = len;
        hdr->domain = req->hdlr->dom->id;

        server.worker->lb.offset += (size_t)len;
        break;
    }

    accesslog_unlock( server.worker );
}

void cf_accesslog_gather( void* arg, uint64_t now, int force )
{
    int id;
    struct cf_worker* kw = NULL;
    struct cf_alog_header* hdr = NULL;
    struct cf_domain* dom = NULL;
    size_t  off, remain;

    if( logbuf == NULL )
        logbuf = cf_buf_alloc(LOGBUF_SIZE);

    for( id = 0; id < server.worker_count; id++ )
    {
        kw = cf_worker_data(id);

        accesslog_lock(kw);

        if( force || kw->lb.offset >= CF_ACCESSLOG_SYNC )
        {
            cf_buf_append(logbuf, kw->lb.buf, kw->lb.offset);
            kw->lb.offset = 0;
        }

        accesslog_unlock(kw);
    }

    if( force || logbuf->offset >= LOGBUF_SIZE )
    {
        off = 0;
        remain = logbuf->offset;

        while( remain > 0 )
        {
            if( remain < sizeof(*hdr) )
            {
                cf_log(LOG_ERR,"invalid log buffer: (%zu remain)", remain);
                break;
            }

            hdr = (struct cf_alog_header *)(logbuf->data + off);
            off += sizeof(*hdr);
            remain -= sizeof(*hdr);

            if( hdr->loglen > remain )
            {
                cf_log(LOG_ERR, "invalid log header: %u (%zu remain)", hdr->loglen, remain);
                break;
            }

            if( (dom = cf_domain_byid(hdr->domain)) == NULL )
                cf_fatal("unknown domain id %u", hdr->domain);

            if( dom->logbuf == NULL )
                dom->logbuf = cf_buf_alloc(DOMAIN_LOGBUF_LEN);

            cf_buf_append(dom->logbuf, &logbuf->data[off], hdr->loglen);

            off += hdr->loglen;
            remain -= hdr->loglen;

            accesslog_flush(dom, now, force);
        }

        cf_buf_reset(logbuf);
    }

    if( force )
        cf_domain_callback(accesslog_flush_cb);
}

void cf_accesslog_run( void *arg, uint64_t now )
{
    static int  ticks = 0;

    cf_accesslog_gather(arg, now, ticks++ % 100 ? 0 : 1);
}

static void accesslog_flush_cb(struct cf_domain *dom)
{
    accesslog_flush(dom, 0, 1);
}

static void accesslog_flush( struct cf_domain *dom, uint64_t now, int force )
{
    ssize_t written;

    if( force && dom->logbuf == NULL )
        return;

    if( force || dom->logbuf->offset >= DOMAIN_LOGBUF_LEN )
    {
        if( (written = write(dom->accesslog, dom->logbuf->data,dom->logbuf->offset)) == -1 )
        {
            if( errno == EINTR )
                return;

            if( dom->logwarn == 0 || errno != dom->logerr )
            {
                cf_log(LOG_NOTICE, "error writing log for %s (%s)", dom->domain, errno_s);
                dom->logwarn = now;
                dom->logerr = errno;
            }
            cf_buf_reset(dom->logbuf);
            return;
        }

        if( (size_t)written != dom->logbuf->offset )
        {
            cf_log(LOG_ERR, "partial accesslog write for %s", dom->domain);
        }

        cf_buf_reset(dom->logbuf);
    }
}

static void accesslog_lock(struct cf_worker *kw)
{
    for(;;)
    {
        if( __sync_bool_compare_and_swap(&kw->lb.lock, 0, 1) )
            break;
    }
}

static void accesslog_unlock(struct cf_worker *kw)
{
    if( !__sync_bool_compare_and_swap(&kw->lb.lock, 1, 0) )
        cf_fatal("accesslog_unlock: failed to release");
}


#ifdef MMM

struct cf_log_packet
{
    uint8_t     method;
    int         status;
    size_t		length;
    uint16_t	time_req;
    uint16_t	worker_id;
    uint16_t	worker_cpu;
    int		    family;
    uint8_t     addr[sizeof(struct in6_addr)];
    char		host[CF_DOMAINNAME_LEN];
	char		path[HTTP_URI_LEN];
	char		agent[HTTP_USERAGENT_LEN];
    char		referer[HTTP_REFERER_LEN];
#ifndef CF_NO_TLS
    char        cn[X509_CN_LENGTH];
#endif
};

void cf_accesslog_init( void )
{
}

void cf_accesslog_worker_init( void )
{
	cf_domain_closelogs();
}

int cf_accesslog_write( const void *data, uint32_t len )
{
    int	l;
    time_t now;
    struct tm* tm = NULL;
    ssize_t sent;
    struct cf_domain *dom = NULL;
    struct cf_log_packet logpacket;
    char addr[INET6_ADDRSTRLEN];
    char *method = NULL;
    char *buf = NULL;
    char *cn = NULL;

    char tbuf[128];

    if( len != sizeof(struct cf_log_packet) )
        return CF_RESULT_ERROR;

    memcpy(&logpacket, data, sizeof(logpacket));

    if( (dom = cf_domain_lookup(logpacket.host)) == NULL )
    {
        cf_log(LOG_WARNING, "got accesslog packet for unknown domain: %s", logpacket.host);
        return CF_RESULT_OK;
	}

    switch( logpacket.method )
    {
	case HTTP_METHOD_GET:
		method = "GET";
		break;
	case HTTP_METHOD_POST:
		method = "POST";
		break;
	case HTTP_METHOD_PUT:
		method = "PUT";
		break;
	case HTTP_METHOD_DELETE:
		method = "DELETE";
		break;
	case HTTP_METHOD_HEAD:
		method = "HEAD";
		break;
    case HTTP_METHOD_PATCH:
        method = "PATCH";
        break;
	default:
		method = "UNKNOWN";
		break;
	}

    cn = "-";

#ifndef CF_NO_TLS
    if( logpacket.cn[0] != '\0' )
		cn = logpacket.cn;
#endif

    if( logpacket.family != AF_UNIX )
    {
        if( inet_ntop(logpacket.family, &(logpacket.addr), addr, sizeof(addr)) == NULL ) {
            cf_strlcpy(addr, "-", sizeof(addr));
        }
    }
    else {
        cf_strlcpy(addr, "unix-socket", sizeof(addr));
    }

    time( &now );
    tm = localtime( &now );
    strftime(tbuf, sizeof(tbuf), "%d/%b/%Y:%H:%M:%S %z", tm);

    l = asprintf(&buf,
        "%s - %s [%s] \"%s %s HTTP/1.1\" %d %zu \"%s\" \"%s\" (w#%d) (%dms)\n",
        addr, cn, tbuf, method, logpacket.path, logpacket.status,
        logpacket.length, logpacket.referer, logpacket.agent, logpacket.worker_id, logpacket.time_req);

    if( l == -1 )
    {
        cf_log(LOG_WARNING,"cf_accesslog_write(): asprintf() == -1");
        return CF_RESULT_ERROR;
	}

    if( (sent = write(dom->accesslog, buf, l)) == -1 )
    {
        free( buf );
        cf_log(LOG_WARNING, "cf_accesslog_write(): write(): %s", errno_s);
        return CF_RESULT_ERROR;
	}

    if( sent != l )
        cf_log(LOG_NOTICE, "accesslog: %s", buf);

    free( buf );
    return CF_RESULT_OK;
}
/****************************************************************
 *  Add to access log HTTP request information
 ****************************************************************/
void cf_accesslog( struct http_request *req )
{
    struct cf_log_packet logpacket;

    logpacket.family = req->owner->family;

    if( logpacket.family == AF_INET ) {
        memcpy( logpacket.addr, &(req->owner->addr.ipv4.sin_addr), sizeof(req->owner->addr.ipv4.sin_addr));
    }
    else if( logpacket.family == AF_INET6 ) {
        memcpy( logpacket.addr, &(req->owner->addr.ipv6.sin6_addr), sizeof(req->owner->addr.ipv6.sin6_addr));
    }

	logpacket.status = req->status;
	logpacket.method = req->method;
    logpacket.length = req->content_length;
    logpacket.time_req = req->total;         /* Total request time */

    logpacket.worker_id = server.worker->id;
    logpacket.worker_cpu = server.worker->cpu;

    if( cf_strlcpy(logpacket.host, req->host, sizeof(logpacket.host)) >= sizeof(logpacket.host) )
        cf_log(LOG_NOTICE, "cf_accesslog: host truncated");

    if( cf_strlcpy(logpacket.path, req->path, sizeof(logpacket.path)) >= sizeof(logpacket.path))
        cf_log(LOG_NOTICE, "cf_accesslog: path truncated");

    if( req->agent != NULL )
    {
        if( cf_strlcpy(logpacket.agent, req->agent,sizeof(logpacket.agent)) >= sizeof(logpacket.agent) )
            cf_log(LOG_NOTICE, "cf_accesslog: agent truncated");
    }
    else
        cf_strlcpy(logpacket.agent, "unknown", sizeof(logpacket.agent));

    if( req->referer != NULL )
    {
        if( cf_strlcpy(logpacket.referer, req->referer,sizeof(logpacket.referer)) >= sizeof(logpacket.referer))
            cf_log(LOG_NOTICE,"cf_accesslog: referer truncated");
    }
    else
        cf_strlcpy(logpacket.referer, "-", sizeof(logpacket.referer));

#ifndef CF_NO_TLS
	memset(logpacket.cn, '\0', sizeof(logpacket.cn));

    if( req->owner->cert != NULL )
    {
        if( X509_GET_CN(req->owner->cert, logpacket.cn, sizeof(logpacket.cn)) == -1 ) {
            cf_log(LOG_WARNING, "client cert without a CN?");
		}
	}
#endif

    cf_msg_send(CF_MSG_PARENT, CF_MSG_ACCESSLOG, &logpacket, sizeof(logpacket));
}


#endif
