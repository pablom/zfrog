
#include <sys/socket.h>

#include <zfrog.h>
#include <cf_http.h>

#include <limits.h>

/*
 * zTunnel shows how zfrog exposes its net internals to its libraries
 * and how we can "abuse" these internals to create a "anything"
 * over HTTPS tunnel.
 */

int open_connection(struct http_request *);

static int	ztunnel_pipe_data(struct netbuf *);
static void	ztunnel_pipe_disconnect(struct connection *);
static int	ztunnel_pipe_create(struct connection *, const char *, const char *);

/*
 * Receive a request to open a new connection
 */
int open_connection( struct http_request *req )
{
	char *host, *port;

	/* Make sure its HTTP */
	if( req->owner->proto != CONN_PROTO_HTTP ) 
	{
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return CF_RESULT_OK;
	}

	/* Parse the query string and grab our arguments */
	http_populate_get(req);
	
	if( !http_argument_get_string(req, "host", &host) ||
	    !http_argument_get_string(req, "port", &port)) 
	{
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return CF_RESULT_OK;
	}

	/* Create our tunnel */
    if( !ztunnel_pipe_create(req->owner, host, port) )
	{
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		return CF_RESULT_OK;
	}

	/*
	 * Hack so http_response() doesn't end up queueing a new
	 * netbuf for receiving more HTTP requests on the same connection.
	 */
	req->owner->flags |= CONN_CLOSE_EMPTY;

	/* Respond to the client now that we're good to go */
	http_response(req, HTTP_STATUS_OK, NULL, 0);

	/* Unset this so we don't disconnect after returning */
	req->owner->flags &= ~CONN_CLOSE_EMPTY;

	return CF_RESULT_OK;
}

/*
 * Connect to our target host:port and attach it to a struct connection that
 * zfrog understands. We set the disconnect method so we get a callback
 * whenever either of the connections will go away so we can cleanup the
 * one it is attached to.
 */
static int ztunnel_pipe_create( struct connection *c, const char *host, const char *port )
{
	struct sockaddr_in	sin;
	struct connection	*cpipe;
	uint16_t nport;
	int	fd, err;

	nport = cf_strtonum(port, 10, 1, SHRT_MAX, &err);
	if( err == CF_RESULT_ERROR ) 
	{
		cf_log(LOG_ERR, "invalid port given %s", port);
		return CF_RESULT_ERROR;
	}

	if( (fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ) 
	{
		cf_log(LOG_ERR, "socket(): %s", errno_s);
		return CF_RESULT_ERROR;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(nport);
	sin.sin_addr.s_addr = inet_addr(host);

	cf_log(LOG_NOTICE, "Attempting to connect to %s:%s", host, port);

	if( connect(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1 ) 
	{
		close(fd);
		cf_log(LOG_ERR, "connect(): %s", errno_s);
		return CF_RESULT_ERROR;
	}

    if( !cf_socket_nonblock(fd, 1) )
	{
		close(fd);
		return CF_RESULT_ERROR;
	}

	cpipe = cf_connection_new(c);

	cpipe->fd = fd;
	cpipe->addr.ipv4 = sin;
	cpipe->read = net_read;
	cpipe->write = net_write;
	cpipe->addrtype = AF_INET;
	cpipe->proto = CONN_PROTO_UNKNOWN;
	cpipe->state = CONN_STATE_ESTABLISHED;

	/* Don't let these connections timeout any time soon */
	cpipe->idle_timer.length = 10000000000;
	c->idle_timer.length = 10000000000;

	c->hdlr_extra = cpipe;
	cpipe->hdlr_extra = c;
    c->disconnect = ztunnel_pipe_disconnect;
    cpipe->disconnect = ztunnel_pipe_disconnect;

    connection_add_backend( cpipe );

	cf_platform_event_all(cpipe->fd, cpipe);

    net_recv_reset(c, NETBUF_SEND_PAYLOAD_MAX, ztunnel_pipe_data);
    net_recv_queue(cpipe, NETBUF_SEND_PAYLOAD_MAX, NETBUF_CALL_CB_ALWAYS, ztunnel_pipe_data);

	printf("connection started to %s (%p -> %p)\n", host, c, cpipe);
	return CF_RESULT_OK;
}

/*
 * Called everytime new data is read from any of the connections
 * that are part of a pipe
 */
static int ztunnel_pipe_data(struct netbuf *nb)
{
	struct connection	*src = nb->owner;
	struct connection	*dst = src->hdlr_extra;

	printf("received %zu bytes on pipe %p (-> %p)\n", nb->s_off, src, dst);

	net_send_queue(dst, nb->buf, nb->s_off);
	net_send_flush(dst);
    net_recv_reset(src, NETBUF_SEND_PAYLOAD_MAX, ztunnel_pipe_data);

	return CF_RESULT_OK;
}

/*
 * Called when either part of the pipe disconnects
 */
static void ztunnel_pipe_disconnect( struct connection *c )
{
    struct connection *cpipe = c->hdlr_extra;

    printf("ztunnel_pipe_disconnect(%p)->%p\n", c, cpipe);

	if( cpipe != NULL ) 
	{
		/* Prevent zfrog from calling mem_free() on hdlr_extra */
		c->hdlr_extra = NULL;
		cf_connection_disconnect(cpipe);
	}
}
