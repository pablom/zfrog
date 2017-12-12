// cf_msg.c

#include <sys/socket.h>
#include <signal.h>
#include "zfrog.h"
#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

struct msg_type
{
    uint8_t id;
    void (*cb)(struct cf_msg*, const void*);
    TAILQ_ENTRY(msg_type) list;
};

TAILQ_HEAD(, msg_type)	msg_types;

static struct msg_type	*msg_type_lookup(uint8_t);
static int msg_recv_packet(struct netbuf*);
static int msg_recv_data(struct netbuf*);
static void msg_disconnected_parent(struct connection*, int);
static void msg_disconnected_worker(struct connection*, int);
static void msg_type_shutdown(struct cf_msg*, const void*);

#ifndef CF_NO_HTTP
    static void	msg_type_accesslog(struct cf_msg*, const void*);
    static void	msg_type_websocket(struct cf_msg*, const void*);
#endif /* CF_NO_HTTP */

void cf_msg_init( void )
{
	TAILQ_INIT(&msg_types);
}

void cf_msg_parent_init( void )
{
    uint8_t i = 0;
    struct cf_worker* kw = NULL;

    for( i = 0; i < server.worker_count; i++ )
    {
        kw = cf_worker_data(i);
        cf_msg_parent_add(kw);
	}

    cf_msg_register(CF_MSG_SHUTDOWN, msg_type_shutdown);

#ifndef CF_NO_HTTP
    cf_msg_register(CF_MSG_ACCESSLOG, msg_type_accesslog);
#endif
}

void cf_msg_parent_add( struct cf_worker *kw )
{
    kw->msg[0] = cf_connection_new( NULL, CF_TYPE_CLIENT );
	kw->msg[0]->fd = kw->pipe[0];
	kw->msg[0]->read = net_read;
	kw->msg[0]->write = net_write;
	kw->msg[0]->proto = CONN_PROTO_MSG;
	kw->msg[0]->state = CONN_STATE_ESTABLISHED;
	kw->msg[0]->hdlr_extra = &kw->id;
	kw->msg[0]->disconnect = msg_disconnected_worker;
    kw->msg[0]->handle = cf_connection_handle;

	TAILQ_INSERT_TAIL(&connections, kw->msg[0], list);
    cf_platform_event_all(kw->msg[0]->fd, kw->msg[0]);

	net_recv_queue(kw->msg[0], sizeof(struct cf_msg), 0, msg_recv_packet);
}

void cf_msg_parent_remove( struct cf_worker *kw )
{
    cf_connection_disconnect(kw->msg[0]);
    cf_connection_prune(CF_CONNECTION_PRUNE_DISCONNECT);
    close( kw->pipe[1] );
}

void cf_msg_worker_init(void)
{
#ifndef CF_NO_HTTP
    cf_msg_register(CF_MSG_WEBSOCKET, msg_type_websocket);
#endif

    server.worker->msg[1] = cf_connection_new( NULL, CF_TYPE_CLIENT );
    server.worker->msg[1]->fd = server.worker->pipe[1];
    server.worker->msg[1]->read = net_read;
    server.worker->msg[1]->write = net_write;
    server.worker->msg[1]->proto = CONN_PROTO_MSG;
    server.worker->msg[1]->state = CONN_STATE_ESTABLISHED;
    server.worker->msg[1]->disconnect = msg_disconnected_parent;
    server.worker->msg[1]->handle = cf_connection_handle;

    TAILQ_INSERT_TAIL(&connections, server.worker->msg[1], list);
    cf_platform_event_all(server.worker->msg[1]->fd, server.worker->msg[1]);

    net_recv_queue( server.worker->msg[1],sizeof(struct cf_msg), 0, msg_recv_packet );
}
/****************************************************************
 *  Register new one message
 ****************************************************************/
int cf_msg_register( uint8_t id, void (*cb)(struct cf_msg *, const void *) )
{
    struct msg_type	*type = NULL;

    if( (type = msg_type_lookup(id)) != NULL ) {
        return CF_RESULT_ERROR;
    }

	type = mem_malloc(sizeof(*type));
	type->id = id;
	type->cb = cb;
	TAILQ_INSERT_TAIL(&msg_types, type, list);

    return CF_RESULT_OK;
}
/****************************************************************
 *  Helper function to send message
 ****************************************************************/
void cf_msg_send( uint16_t dst, uint8_t id, const void *data, uint32_t len )
{
    struct cf_msg m;

	m.id = id;
	m.dst = dst;
	m.length = len;
    m.src = server.worker->id;

    net_send_queue(server.worker->msg[1], &m, sizeof(m));

    if( data != NULL && len > 0 )
        net_send_queue(server.worker->msg[1], data, len);

    net_send_flush( server.worker->msg[1] );
}

static int msg_recv_packet( struct netbuf *nb )
{
    struct cf_msg *msg = (struct cf_msg *)nb->buf;

    if( msg->length > 0 )
    {
        net_recv_expand(nb->owner, msg->length, msg_recv_data);
        return CF_RESULT_OK;
    }

    return msg_recv_data( nb );
}

static int msg_recv_data( struct netbuf *nb )
{
    struct connection *c = NULL;
    struct msg_type *type = NULL;
    uint16_t destination;
    struct cf_msg *msg = (struct cf_msg *)nb->buf;

    if( (type = msg_type_lookup(msg->id)) != NULL )
    {
        if( server.worker == NULL && msg->dst != CF_MSG_PARENT )
			cf_fatal("received parent msg for non parent dst");
        if( server.worker != NULL && msg->dst != server.worker->id )
			cf_fatal("received message for incorrect worker");

        if( msg->length > 0 )
            type->cb(msg, nb->buf + sizeof(*msg));
        else
            type->cb(msg, NULL);
	}

    if( server.worker == NULL && type == NULL )
    {
		destination = msg->dst;
        TAILQ_FOREACH(c, &connections, list)
        {
            if( c == nb->owner )
				continue;
            if( c->proto != CONN_PROTO_MSG || c->hdlr_extra == NULL )
				continue;

            if( destination != CF_MSG_WORKER_ALL && *(uint8_t *)c->hdlr_extra != destination )
				continue;

			/* This allows the worker to receive the correct id. */
            msg->dst = *(uint8_t *)c->hdlr_extra;

			net_send_queue(c, nb->buf, nb->s_off);
			net_send_flush(c);
		}
	}

	net_recv_reset(nb->owner, sizeof(struct cf_msg), msg_recv_packet);
    return CF_RESULT_OK;
}

static void msg_disconnected_parent( struct connection *c, int err )
{
    cf_log(LOG_ERR, "parent gone, shutting down");
    if( kill(server.worker->pid, SIGQUIT) == -1 )
        cf_log(LOG_ERR, "failed to send SIGQUIT: %s", errno_s);
}

static void msg_disconnected_worker( struct connection *c, int err )
{
	c->hdlr_extra = NULL;
}

static void msg_type_shutdown( struct cf_msg *msg, const void *data )
{
    cf_log(LOG_NOTICE, "worker requested shutdown");
    cf_signal(SIGQUIT);
}

#ifndef CF_NO_HTTP
static void msg_type_accesslog( struct cf_msg *msg, const void *data )
{
    if( cf_accesslog_write(data, msg->length) == -1 )
        cf_log(LOG_WARNING, "failed to write to accesslog");
}

static void msg_type_websocket(struct cf_msg *msg, const void *data)
{
    struct connection *c = NULL;

    TAILQ_FOREACH(c, &connections, list)
    {
        if( c->proto == CONN_PROTO_WEBSOCKET )
        {
			net_send_queue(c, data, msg->length);
			net_send_flush(c);
		}
	}
}
#endif /* CF_NO_HTTP */

static struct msg_type* msg_type_lookup( uint8_t id )
{
    struct msg_type *type = NULL;

    TAILQ_FOREACH(type, &msg_types, list)
    {
        if( type->id == id )
            return type;
	}

    return NULL;
}
