// cf_connection.c

#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <fcntl.h>

#include "zfrog.h"

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

#ifdef CF_REDIS
    #include "cf_redis.h"
#endif

/* Forward function declaration */


struct cf_mem_pool		connection_mem_pool;
struct connection_list	connections;
struct connection_list	disconnected;

/****************************************************************
 *  Helper function to init all global connection's parameters
 ****************************************************************/
void connection_init( void )
{
    TAILQ_INIT( &connections );
    TAILQ_INIT( &disconnected );

    cf_mem_pool_init(&connection_mem_pool, "connection_pool", sizeof(struct connection), worker_max_connections);
}
/****************************************************************
 *  Helper function clean all global connection's parameters
 ****************************************************************/
void connection_cleanup( void )
{
    log_debug("connection_cleanup()");

	/* Drop all connections */
    cf_connection_prune(CF_CONNECTION_PRUNE_ALL);
    cf_mem_pool_cleanup( &connection_mem_pool );
}
/****************************************************************
 *  Create new one connection structure
 ****************************************************************/
struct connection* cf_connection_new( void *owner, uint8_t type )
{
    struct connection *c = cf_mem_pool_get( &connection_mem_pool );

#ifndef CF_NO_TLS
	c->ssl = NULL;
	c->cert = NULL;
	c->tls_reneg = 0;
#endif
	c->flags = 0;
	c->rnb = NULL;
	c->snb = NULL;
    c->owner = owner;
	c->handle = NULL;
	c->disconnect = NULL;
	c->hdlr_extra = NULL;
	c->proto = CONN_PROTO_UNKNOWN;
    c->type = type;
	c->idle_timer.start = 0;
    c->idle_timer.length = CF_IDLE_TIMER_MAX;

#ifndef CF_NO_HTTP
    c->ws_connect = NULL;
    c->ws_message = NULL;
    c->ws_disconnect = NULL;
	TAILQ_INIT(&(c->http_requests));
#endif

	TAILQ_INIT(&(c->send_queue));

    return c;
}
/****************************************************************
 *  Helper function to accept incoming connection
 ****************************************************************/
int connection_accept( struct listener *listener, struct connection **out )
{
    struct connection *c = NULL;
    struct sockaddr	*addr = NULL;
    socklen_t len;

    log_debug("connection_accept(%p)", listener);

    /* Init out parameter */
	*out = NULL;
    c = cf_connection_new( listener, CF_TYPE_CLIENT );

	c->addrtype = listener->addrtype;

    if( c->addrtype == AF_INET )
    {
		len = sizeof(struct sockaddr_in);
        addr = (struct sockaddr *)&(c->addr.ipv4);
    }
    else
    {
		len = sizeof(struct sockaddr_in6);
        addr = (struct sockaddr *)&(c->addr.ipv6);
	}

    if( (c->fd = accept(listener->fd, addr, &len)) == -1 )
    {
        cf_mem_pool_put( &connection_mem_pool, c );
        log_debug("accept(): %s", errno_s);
        return CF_RESULT_ERROR;
	}

    if( !cf_socket_nonblock(c->fd, 1) )
    {
		close(c->fd);
        cf_mem_pool_put( &connection_mem_pool, c );
        return CF_RESULT_ERROR;
	}

    c->handle = cf_connection_handle;
	TAILQ_INSERT_TAIL(&connections, c, list);

#ifndef CF_NO_TLS
    c->state = CONN_STATE_SSL_IN_SHAKE;
    c->write = net_write_tls;
    c->read = net_read_tls;
#else
	c->state = CONN_STATE_ESTABLISHED;
	c->write = net_write;
	c->read = net_read;

    if( listener->connect != NULL )
        cf_runtime_connect(listener->connect, c);
    else
    {
#ifndef CF_NO_HTTP
		c->proto = CONN_PROTO_HTTP;
        if( http_keepalive_time != 0 )
			c->idle_timer.length = http_keepalive_time * 1000;
        net_recv_queue(c, http_header_max, NETBUF_CALL_CB_ALWAYS, http_header_recv);
#endif /* CF_NO_HTTP */
	}
#endif /* CF_NO_TLS */

    cf_connection_start_idletimer(c);

    /* Increment count of worker active connections */
	worker_active_connections++;

	*out = c;
    return CF_RESULT_OK;
}
/****************************************************************
 *  Helper function to add backend transaction
 ****************************************************************/
int connection_add_backend( struct connection *c )
{
    /* Insert the backend into the list of zfrog connections */
    TAILQ_INSERT_TAIL(&connections, c, list);
    /* Start idle timer for the backend */
    cf_connection_start_idletimer( c );
    /* Increment count of worker active connections */
    worker_active_connections++;

    return CF_RESULT_OK;
}
/****************************************************************
 *  Helper function to check connection timeout
 ****************************************************************/
void cf_connection_check_timeout( void )
{
    struct connection *c = NULL;
    uint64_t now = cf_time_ms();

    TAILQ_FOREACH(c, &connections, list)
    {
        if( c->proto == CONN_PROTO_MSG )
			continue;
        if( !(c->flags & CONN_IDLE_TIMER_ACT) )
			continue;
        cf_connection_check_idletimer(now, c);
	}
}
/****************************************************************
 *  Helper function to prune (drop) all connection
 ****************************************************************/
void cf_connection_prune( int all )
{
    struct connection *c, *cnext;

    if( all )
    {
        for( c = TAILQ_FIRST(&connections); c != NULL; c = cnext )
        {
			cnext = TAILQ_NEXT(c, list);
			net_send_flush(c);
            cf_connection_disconnect(c);
		}
	}

    for( c = TAILQ_FIRST(&disconnected); c != NULL; c = cnext )
    {
		cnext = TAILQ_NEXT(c, list);
		TAILQ_REMOVE(&disconnected, c, list);
        cf_connection_remove(c);
	}
}
/****************************************************************
 *  Disconnect connection client helper function
 ****************************************************************/
void cf_connection_disconnect( struct connection *c )
{
    if( c->state != CONN_STATE_DISCONNECTING )
    {
        log_debug("preparing %p for disconnection", c);
		c->state = CONN_STATE_DISCONNECTING;
        if( c->disconnect )
            c->disconnect(c, 0);

		TAILQ_REMOVE(&connections, c, list);
		TAILQ_INSERT_TAIL(&disconnected, c, list);
	}
}
/****************************************************************
 *  Disconnect connection client helper function
 ****************************************************************/
void cf_connection_backend_error( struct connection *c )
{
    if( c->state != CONN_STATE_ERROR )
    {
        if( c->disconnect )
            c->disconnect(c, 1);

        /* Set error state */
        c->state = CONN_STATE_ERROR;

        TAILQ_REMOVE(&connections, c, list);
        TAILQ_INSERT_TAIL(&disconnected, c, list);
    }
}
/****************************************************************
 *  Connection listener (client connection) handle function
 ****************************************************************/
int cf_connection_handle( struct connection *c )
{
#ifndef CF_NO_TLS
    int	r;
    struct listener	*listener = NULL;
    char cn[X509_CN_LENGTH];
#endif

    log_debug("cf_connection_handle(%p) -> %d", c, c->state);
    cf_connection_stop_idletimer(c);

    switch( c->state )
    {
#ifndef CF_NO_TLS
    case CONN_STATE_SSL_IN_SHAKE:
        if( c->ssl == NULL )
        {
            c->ssl = SSL_new( primary_dom->ssl_ctx );

            if( c->ssl == NULL )
            {
                log_debug("SSL_new(): %s", ssl_errno_s);
                return CF_RESULT_ERROR;
			}

			SSL_set_fd(c->ssl, c->fd);
			SSL_set_accept_state(c->ssl);
			SSL_set_app_data(c->ssl, c);
		}

        /* Clear SSL errors */
        ERR_clear_error();

        r = SSL_accept( c->ssl );

        if( r <= 0 )
        {
			r = SSL_get_error(c->ssl, r);

            switch( r )
            {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
                return CF_RESULT_OK;
			default:
                log_debug("SSL_accept(): %s", ssl_errno_s);
                return CF_RESULT_ERROR;
			}
		}

        if( SSL_get_verify_mode(c->ssl) & SSL_VERIFY_PEER )
        {
			c->cert = SSL_get_peer_certificate(c->ssl);
            if( c->cert == NULL )
            {
                cf_log(LOG_NOTICE, "no client certificate presented?");
                return CF_RESULT_ERROR;
			}

            if( X509_GET_CN(c->cert, cn, sizeof(cn)) == -1 )
            {
                cf_log(LOG_NOTICE,"no CN found in client certificate");
                return CF_RESULT_ERROR;
			}
        }
        else {
			c->cert = NULL;
		}

		r = SSL_get_verify_result(c->ssl);

        if( r != X509_V_OK )
        {
            log_debug("SSL_get_verify_result(): %d, %s", r, ssl_errno_s);
            return CF_RESULT_ERROR;
		}

        if( c->owner != NULL )
        {
			listener = (struct listener *)c->owner;
            if( listener->connect != NULL )
            {
                cf_runtime_connect(listener->connect, c);
                return CF_RESULT_OK;
			}
		}

#ifndef CF_NO_HTTP
		c->proto = CONN_PROTO_HTTP;

        if( http_keepalive_time != 0 )
        {
            c->idle_timer.length = http_keepalive_time * 1000;
		}

        net_recv_queue(c, http_header_max, NETBUF_CALL_CB_ALWAYS, http_header_recv);
#endif

		c->state = CONN_STATE_ESTABLISHED;
		/* FALLTHROUGH */
#endif /* CF_NO_TLS */
	case CONN_STATE_ESTABLISHED:
        if( c->flags & CONN_READ_POSSIBLE )
        {
            if( !net_recv_flush(c) )
                return CF_RESULT_ERROR;
		}

        if( c->flags & CONN_WRITE_POSSIBLE )
        {
            if( !net_send_flush(c) )
                return CF_RESULT_ERROR;
        }
		break;

    /* connecting to backend server */
    case CONN_STATE_CONNECTING:
        /* We will get a write notification when we can progress */
        if( c->flags & CONN_WRITE_POSSIBLE )
        {
            /* Try to server connect, if we failed check why, we are non blocking */
            if( cf_connection_connect_toaddr( c ) == -1 )
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
                    break;
                }
            }

            /* The connection to the backend server succeeded */
            c->state = CONN_STATE_ESTABLISHED;

#ifdef CF_REDIS
            if( c->proto == CONN_PROTO_REDIS )
            {
              //  net_recv_queue(c, NETBUF_SEND_PAYLOAD_MAX, NETBUF_CALL_CB_ALWAYS, redis_recv);
            }
#endif

            /* Catch all epoll events */
            cf_platform_event_all(c->fd, c);
        }
        break;
	case CONN_STATE_DISCONNECTING:
    case CONN_STATE_ERROR:
		break;
	default:
        log_debug("unknown state on %d (%d)", c->fd, c->state);
		break;
	}

    /* Start idle timer */
    cf_connection_start_idletimer(c);

    return CF_RESULT_OK;
}
/****************************************************************
 *  Helper function remove connection
 ****************************************************************/
void cf_connection_remove( struct connection *c )
{
    struct netbuf *nb, *next;
#ifndef CF_NO_HTTP
	struct http_request	*req, *rnext;
#endif

    log_debug("cf_connection_remove(%p)", c);

#ifndef CF_NO_TLS
    if( c->ssl != NULL )
    {
		SSL_shutdown(c->ssl);
		SSL_free(c->ssl);
	}

    if( c->cert != NULL )
		X509_free(c->cert);
#endif

    close( c->fd );

    if( c->hdlr_extra != NULL )
		mem_free(c->hdlr_extra);

#ifndef CF_NO_HTTP
    for( req = TAILQ_FIRST(&(c->http_requests)); req != NULL; req = rnext )
    {
		rnext = TAILQ_NEXT(req, olist);
		TAILQ_REMOVE(&(c->http_requests), req, olist);
        req->owner = NULL;
		req->flags |= HTTP_REQUEST_DELETE;
		http_request_wakeup(req);
	}

    mem_free(c->ws_connect);
    mem_free(c->ws_message);
    mem_free(c->ws_disconnect);
#endif

    for( nb = TAILQ_FIRST(&(c->send_queue)); nb != NULL; nb = next )
    {
		next = TAILQ_NEXT(nb, list);
		TAILQ_REMOVE(&(c->send_queue), nb, list);

        if( !(nb->flags & NETBUF_IS_STREAM) )
			mem_free(nb->buf);
        else if( nb->cb != NULL )
            nb->cb(nb);

        cf_mem_pool_put(&nb_pool, nb);
	}

    if( c->rnb != NULL )
    {
		mem_free(c->rnb->buf);
        cf_mem_pool_put(&nb_pool, c->rnb);
	}

    /* Move back memory to pool */
    cf_mem_pool_put( &connection_mem_pool, c );
    /* Decrement count of working connections */
	worker_active_connections--;
}
/****************************************************************
 *  Helper function check idle timer connection
 ****************************************************************/
void cf_connection_check_idletimer(uint64_t now, struct connection *c)
{
    uint64_t d;

	d = now - c->idle_timer.start;

    if( d >= c->idle_timer.length )
    {
        log_debug("%p idle for %d ms, expiring", c, d);
        cf_connection_disconnect(c);
	}
}
/****************************************************************
 *  Helper function start idle timer connection
 ****************************************************************/
void cf_connection_start_idletimer( struct connection *c )
{
    log_debug("cf_connection_start_idletimer(%p)", c);

	c->flags |= CONN_IDLE_TIMER_ACT;
	c->idle_timer.start = cf_time_ms();
}
/****************************************************************
 *  Helper function stop idle timer connection
 ****************************************************************/
void cf_connection_stop_idletimer( struct connection *c )
{
    log_debug("cf_connection_stop_idletimer(%p)", c);

	c->flags &= ~CONN_IDLE_TIMER_ACT;
	c->idle_timer.start = 0;
}
/****************************************************************
 *  Helper function connect to server by address
 ****************************************************************/
int cf_connection_connect_toaddr( struct connection *c )
{
    /* Attempt connecting */
    if( c->addrtype == AF_INET )
        return connect(c->fd, (struct sockaddr *)&c->addr.ipv4, sizeof(c->addr.ipv4));
    else if( c->addrtype == AF_INET6 )
        return connect(c->fd, (struct sockaddr *)&c->addr.ipv6, sizeof(c->addr.ipv6));

    return -1;
}


