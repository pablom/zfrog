/*
 * Example of using zfrog as a network application server.
 *
 * We will get called for every new connection that has been established.
 * For TLS connections we will get called after the TLS handshake completed.
 *
 * From the setup we can queue up our own read commands and do whatever we
 * like with the newly connected client.
 */

#include <zfrog.h>

void connection_setup(struct connection *);
int connection_handle(struct connection *);
int connection_recv_data(struct netbuf *);

void connection_setup( struct connection *c )
{
	cf_log(LOG_NOTICE, "%p: new connection", c);

	/*
	 * Setup a read command that will read up to 128 bytes and will
	 * always call the callback connection_recv_data even if not all
	 * 128 bytes were read.
	 */
    net_recv_queue(c, NETBUF_SEND_PAYLOAD_MAX, NETBUF_CALL_CB_ALWAYS, connection_recv_data);

    /* We are responsible for setting the connection state */
	c->state = CONN_STATE_ESTABLISHED;

    /* Override the handle function, called when new events occur */
	c->handle = connection_handle;
}

/*
 * This function is called everytime a new event is triggered on the
 * connection. In this demo we just use it as a stub for the normal
 * callback cf_connection_handle().
 *
 * In this callback you would generally look at the state of the connection
 * in c->state and perform the required actions like writing / reading using
 * net_send_flush() or net_recv_flush() if CONN_SEND_POSSIBLE or
 * CONN_READ_POSSIBLE are set respectively. Returning CF_RESULT_ERROR from
 * this callback will disconnect the connection alltogether
 */
int connection_handle( struct connection *c )
{
	cf_log(LOG_NOTICE, "connection_handle: %p", c);
	return cf_connection_handle(c);
}

/*
 * This function is called everytime we get up to 128 bytes of data
 * The connection can be found under nb->owner
 * The data received can be found under nb->buf
 * The length of the received data can be found under s_off
 */
int connection_recv_data( struct netbuf *nb )
{
	struct connection *c = (struct connection *)nb->owner;

	cf_log(LOG_NOTICE, "%p: received %zu bytes", (void *)c, nb->s_off);

	/* We will just dump these back to the client */
	net_send_queue(c, nb->buf, nb->s_off);
	net_send_flush(c);

	/* Now reset the receive command for the next one */
    net_recv_reset(c, NETBUF_SEND_PAYLOAD_MAX, connection_recv_data);

	return CF_RESULT_OK;
}
