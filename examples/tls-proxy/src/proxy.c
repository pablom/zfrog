
#include <sys/param.h>
#include <sys/socket.h>

#include <zfrog.h>

/*
 * In this example zfrog acts as a TLS proxy shuffling data between
 * an encrypted connection and a plain text backend.
 *
 * It will look at the TLS SNI extension to figure out what backend
 * to use for the connection when it comes in.
 *
 * Add your backends to the data structure below
 */

/* Default timeouts, 5 seconds for connecting, 15 seconds otherwise. */
#define PROXY_TIMEOUT			(15 * 1000)
#define PROXY_CONNECT_TIMEOUT	(5 * 1000)

/* All domains and their backends */
struct 
{
	const char		*name;
	const char		*ip;
    const uint16_t	port;
} backends[] = {
	{ "localhost",	"127.0.0.1",	8080 },
	{ NULL,		NULL,		0 }
};

int	client_handle(struct connection *);
void client_setup(struct connection *);

void disconnect(struct connection *);
int	pipe_data(struct netbuf *);

int	backend_handle_connect(struct connection *);
int	backend_handle_default(struct connection *);

/*
 * Called for every new connection on a certain ip/port. Which one is
 * configured in the TLS proxy its configuration file.
 */
void client_setup( struct connection *c )
{
	int			i, fd;
	struct connection	*backend;

	if( c->ssl->session == NULL || c->ssl->session->tlsext_hostname == NULL ) 
	{
		cf_connection_disconnect(c);
		return;
	}

	/* Figure out what backend to use */
	for( i = 0; backends[i].name != NULL; i++ ) 
	{
		if( !strcasecmp(backends[i].name, c->ssl->session->tlsext_hostname) )
			break;
	}

	/* If we don't have any backends, we just disconnect the client */
    if( backends[i].name == NULL )
	{
		cf_connection_disconnect(c);
		return;
	}

	/* Create new socket for the backend connection */
	if( (fd = socket(AF_INET, SOCK_STREAM, 0)) == -1 ) 
	{
		cf_log(LOG_ERR, "socket(): %s", errno_s);
		cf_connection_disconnect(c);
		return;
	}

	/* Set it to non blocking as well */
	if( !cf_connection_nonblock(fd, 1) ) 
	{
		close(fd);
		cf_connection_disconnect(c);
		return;
	}

    /* Grab a new connection from zfrog to hook backend into */
	backend = cf_connection_new(NULL);

	/* Prepare our connection. */
	backend->addrtype = AF_INET;
	backend->addr.ipv4.sin_family = AF_INET;
	backend->addr.ipv4.sin_port = htons(backends[i].port);
	backend->addr.ipv4.sin_addr.s_addr = inet_addr(backends[i].ip);

	/* Set the file descriptor for the backend */
	backend->fd = fd;

	/* Default write/read callbacks for backend */
	backend->read = net_read;
	backend->write = net_write;

    /* Connection type (unknown to zfrog) */
	backend->proto = CONN_PROTO_UNKNOWN;
	backend->state = CONN_STATE_ESTABLISHED;

	/* The backend idle timer is set first to connection timeout. */
	backend->idle_timer.length = PROXY_CONNECT_TIMEOUT;

	/* The client idle timer is set to default idle time. */
	c->idle_timer.length = PROXY_TIMEOUT;

	/* Now link both the client and the backend connection together. */
	c->hdlr_extra = backend;
	backend->hdlr_extra = c;

	/*
	 * The handle function pointer for the backend is set to the
	 * backend_handle_connect() while connecting
	 */
	c->handle = client_handle;
	backend->handle = backend_handle_connect;

	/* Set the disconnect method for both connections */
	c->disconnect = disconnect;
	backend->disconnect = disconnect;

	/* Queue write events for the backend connection for now */
	cf_platform_schedule_write(backend->fd, backend);

    /* Insert the backend into the list of zfrog connections */
    connection_add_backend( backend );

	/* Set our client connection to established. */
	c->state = CONN_STATE_ESTABLISHED;

    /* Kick off connecting */
	backend->flags |= CONN_WRITE_POSSIBLE;
	backend->handle(backend);
}

/*
 * This function is called for backends while they are connecting.
 * In here we check for write events and attempt to connect() to the
 * backend.
 *
 * Once a connection is established we set the backend handle function
 * pointer to the backend_handle_default() callback and setup the reads
 * for both the backend and the client connection we received.
 */
int backend_handle_connect( struct connection *c )
{
	int ret;
	struct connection	*src;

	/* We will get a write notification when we can progress. */
	if( !(c->flags & CONN_WRITE_POSSIBLE) )
		return CF_RESULT_OK;

	cf_connection_stop_idletimer(c);

	/* Attempt connecting */
	ret = connect(c->fd, (struct sockaddr *)&c->addr.ipv4, sizeof(c->addr.ipv4));

	/* If we failed check why, we are non blocking */
	if( ret == -1 ) 
	{
		/* If we got a real error, disconnect */
		if( errno != EALREADY && errno != EINPROGRESS && errno != EISCONN )
		{
			cf_log(LOG_ERR, "connect(): %s", errno_s);
			return CF_RESULT_ERROR;
		}

		/* Clean the write flag, we'll be called later */
        if( errno != EISCONN )
		{
			c->flags &= ~CONN_WRITE_POSSIBLE;
			cf_connection_start_idletimer(c);
			return CF_RESULT_OK;
		}
	}

	/* The connection to the backend succeeded */
	c->handle = backend_handle_default;

	/* Setup read calls for both backend and its client */
	net_recv_queue(c, NETBUF_SEND_PAYLOAD_MAX, NETBUF_CALL_CB_ALWAYS, pipe_data);
	net_recv_queue(c->hdlr_extra, NETBUF_SEND_PAYLOAD_MAX, NETBUF_CALL_CB_ALWAYS, pipe_data);

	/* Allow for all events now */
    cf_connection_start_idletimer( c );
	cf_platform_event_all(c->fd, c);

	/* Allow events from source now */
	src = c->hdlr_extra;
	cf_platform_event_all(src->fd, src);

	/* Now lets start */
	return c->handle(c);
}

/*
 * Called for connection activity on a backend, just forwards
 * to the default zfrog connection handling for now.
 */
int backend_handle_default( struct connection *c )
{
	return cf_connection_handle(c);
}

/*
 * Called for connection activity on a client, just forwards
 * to the default zfrog connection handling for now
 */
int client_handle(struct connection *c)
{
	return cf_connection_handle(c);
}

/*
 * Called whenever a client or its backend have disconnected.
 * This will disconnect the matching paired connection as well
 */
void disconnect( struct connection *c )
{
	struct connection *pair = c->hdlr_extra;

	c->hdlr_extra = NULL;

	if( pair != NULL ) 
	{
		pair->hdlr_extra = NULL;
		cf_connection_disconnect(pair);
	}
}

/*
 * Called whenever data is available that must be piped through
 * to the paired connection. (client<>backend or backend<>client)
 */
int pipe_data(struct netbuf *nb)
{
	struct connection	*src = nb->owner;
	struct connection	*dst = src->hdlr_extra;

	/* Flush data out towards destination. */
	net_send_queue(dst, nb->buf, nb->s_off);
	net_send_flush(dst);

	/* Reset read for source. */
	net_recv_reset(src, NETBUF_SEND_PAYLOAD_MAX, pipe_data);

	return CF_RESULT_OK;
}
