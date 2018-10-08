// cf_accesslog.c

#include <sys/socket.h>
#include <poll.h>
#include <time.h>

#include "zfrog.h"
#include "cf_http.h"

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
