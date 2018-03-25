// cf_websocket.c

#include <sys/param.h>

#include <openssl/sha.h>

#include <limits.h>
#include <string.h>

#include "zfrog.h"
#include "cf_http.h"

#define WEBSOCKET_FRAME_HDR         2
#define WEBSOCKET_MASK_LEN          4
#define WEBSOCKET_FRAME_MAXLEN		16384
#define WEBSOCKET_PAYLOAD_SINGLE	125
#define WEBSOCKET_PAYLOAD_EXTEND_1	126
#define WEBSOCKET_PAYLOAD_EXTEND_2	127
#define WEBSOCKET_OPCODE_MASK		0x0f
#define WEBSOCKET_FRAME_LENGTH(x)	((x) & ~(1 << 7))
#define WEBSOCKET_HAS_MASK(x)		((x) & (1 << 7))
#define WEBSOCKET_HAS_FINFLAG(x)	((x) & (1 << 7))
#define WEBSOCKET_RSV(x, i)         ((x) & (1 << (7 - i)))

#define WEBSOCKET_SERVER_RESPONSE	"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static int	websocket_recv_frame(struct netbuf *);
static int	websocket_recv_opcode(struct netbuf *);
static void	websocket_disconnect(struct connection *, int);
static void	websocket_frame_build(struct cf_buf *, uint8_t, const void *, size_t);

void cf_websocket_handshake( struct http_request *req,
                             const char *onconnect, const char *onmessage, const char *ondisconnect )
{
    SHA_CTX	sctx;
    struct cf_buf *buf = NULL;
    char *base64 = NULL;
    const char	*key, *version;
    uint8_t digest[SHA_DIGEST_LENGTH];

    if( !http_request_header(req, "sec-websocket-key", &key) )
    {
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return;
	}

    if( !http_request_header(req, "sec-websocket-version", &version) )
    {
		http_response_header(req, "sec-websocket-version", "13");
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return;
	}

    if( strcmp(version, "13") )
    {
		http_response_header(req, "sec-websocket-version", "13");
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return;
	}

    buf = cf_buf_alloc(128);
    cf_buf_appendf(buf, "%s%s", key, WEBSOCKET_SERVER_RESPONSE);

    SHA1_Init(&sctx);
    SHA1_Update(&sctx, buf->data, buf->offset);
    SHA1_Final(digest, &sctx);

    cf_buf_free(buf);

    if( !cf_base64_encode(digest, sizeof(digest), &base64) )
    {
        log_debug("failed to base64 encode digest");
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		return;
	}

	http_response_header(req, "upgrade", "websocket");
	http_response_header(req, "connection", "upgrade");
	http_response_header(req, "sec-websocket-accept", base64);
    mem_free(base64);

    log_debug("%p: new websocket connection", req->owner);

	req->owner->proto = CONN_PROTO_WEBSOCKET;
	http_response(req, HTTP_STATUS_SWITCHING_PROTOCOLS, NULL, 0);
	net_recv_reset(req->owner, WEBSOCKET_FRAME_HDR, websocket_recv_opcode);

	req->owner->disconnect = websocket_disconnect;
	req->owner->rnb->flags &= ~NETBUF_CALL_CB_ALWAYS;

    req->owner->idle_timer.start = cf_time_ms();
    req->owner->idle_timer.length = server.websocket_timeout;

    if( onconnect != NULL )
    {
        req->owner->ws_connect = cf_runtime_getcall(onconnect);
        if( req->owner->ws_connect == NULL )
            cf_fatal("no symbol '%s' for ws_connect", onconnect);
    }
    else {
		req->owner->ws_connect = NULL;
	}

    if( onmessage != NULL )
    {
        req->owner->ws_message = cf_runtime_getcall(onmessage);
		if (req->owner->ws_message == NULL)
            cf_fatal("no symbol '%s' for ws_message", onmessage);
    }
    else
		req->owner->ws_message = NULL;

    if( ondisconnect != NULL )
    {
        req->owner->ws_disconnect = cf_runtime_getcall(ondisconnect);
        if( req->owner->ws_disconnect == NULL )
            cf_fatal("no symbol '%s' for ws_disconnect", ondisconnect);
    }
    else
		req->owner->ws_disconnect = NULL;

	if (req->owner->ws_connect != NULL)
        cf_runtime_wsconnect(req->owner->ws_connect, req->owner);
}

void cf_websocket_send(struct connection *c, uint8_t op, const void *data, size_t len)
{
    struct cf_buf frame;

    cf_buf_init(&frame, len);
    websocket_frame_build(&frame, op, data, len);
    /* net_send_stream() takes over the buffer data pointer */
    net_send_stream(c, frame.data, frame.offset, NULL, NULL);
    frame.data = NULL;
    cf_buf_cleanup( &frame );

	net_send_flush(c);
}

void cf_websocket_broadcast(struct connection *src, uint8_t op, const void *data, size_t len, int scope)
{
    struct connection *c = NULL;
    struct cf_buf *frame = NULL;

    frame = cf_buf_alloc(len);
	websocket_frame_build(frame, op, data, len);

    TAILQ_FOREACH(c, &connections, list)
    {
        if( c != src && c->proto == CONN_PROTO_WEBSOCKET )
        {
			net_send_queue(c, frame->data, frame->offset);
			net_send_flush(c);
		}
	}

    if( scope == WEBSOCKET_BROADCAST_GLOBAL ) {
        cf_msg_send(CF_MSG_WORKER_ALL, CF_MSG_WEBSOCKET, frame->data, frame->offset);
	}

    cf_buf_free(frame);
}

static void websocket_frame_build(struct cf_buf *frame, uint8_t op, const void *data, size_t len)
{
    uint8_t		len_1;
    uint16_t	len16;
    uint64_t	len64;

    if( len > WEBSOCKET_PAYLOAD_SINGLE)
    {
        if( len <= USHRT_MAX )
			len_1 = WEBSOCKET_PAYLOAD_EXTEND_1;
		else
			len_1 = WEBSOCKET_PAYLOAD_EXTEND_2;
    }
    else
		len_1 = len;

	op |= (1 << 7);
    cf_buf_append(frame, &op, sizeof(op));

	len_1 &= ~(1 << 7);
    cf_buf_append(frame, &len_1, sizeof(len_1));

    if( len_1 > WEBSOCKET_PAYLOAD_SINGLE )
    {
        switch( len_1 )
        {
		case WEBSOCKET_PAYLOAD_EXTEND_1:
            net_write16((uint8_t *)&len16, len);
            cf_buf_append(frame, &len16, sizeof(len16));
			break;
		case WEBSOCKET_PAYLOAD_EXTEND_2:
            net_write64((uint8_t *)&len64, len);
            cf_buf_append(frame, &len64, sizeof(len64));
			break;
		}
	}

    if (data != NULL && len > 0)
        cf_buf_append(frame, data, len);
}

static int websocket_recv_opcode( struct netbuf* nb )
{
    uint8_t op, len;
    struct connection *c = nb->owner;

    if( !WEBSOCKET_HAS_MASK(nb->buf[1]) )
    {
        log_debug("%p: frame did not have a mask set", c);
        return CF_RESULT_ERROR;
	}

    if( WEBSOCKET_RSV(nb->buf[0], 1) || WEBSOCKET_RSV(nb->buf[0], 2) ||
        WEBSOCKET_RSV(nb->buf[0], 3))
    {
        log_debug("%p: RSV bits are not zero", c);
        return CF_RESULT_ERROR;
	}

	len = WEBSOCKET_FRAME_LENGTH(nb->buf[1]);

	op = nb->buf[0] & WEBSOCKET_OPCODE_MASK;

    switch( op )
    {
	case WEBSOCKET_OP_CONT:
	case WEBSOCKET_OP_TEXT:
	case WEBSOCKET_OP_BINARY:
		break;
	case WEBSOCKET_OP_CLOSE:
	case WEBSOCKET_OP_PING:
	case WEBSOCKET_OP_PONG:
        if( len > WEBSOCKET_PAYLOAD_SINGLE ||
            !WEBSOCKET_HAS_FINFLAG(nb->buf[0]))
        {
            log_debug("%p: large or fragmented control frame", c);
            return CF_RESULT_ERROR;
		}
		break;
	default:
        log_debug("%p: bad websocket op %d", c, op);
        return CF_RESULT_ERROR;
	}

    switch( len )
    {
	case WEBSOCKET_PAYLOAD_EXTEND_1:
        len += sizeof(uint16_t);
		break;
	case WEBSOCKET_PAYLOAD_EXTEND_2:
        len += sizeof(uint64_t);
		break;
	}

	len += WEBSOCKET_MASK_LEN;
	net_recv_expand(c, len, websocket_recv_frame);

    return CF_RESULT_OK;
}

static int websocket_recv_frame( struct netbuf* nb )
{
    struct connection *c = NULL;
    int	ret;
    uint64_t len, i, total;
    uint8_t	op, moff, extra;

	c = nb->owner;

	op = nb->buf[0] & WEBSOCKET_OPCODE_MASK;
	len = WEBSOCKET_FRAME_LENGTH(nb->buf[1]);

    switch( len )
    {
	case WEBSOCKET_PAYLOAD_EXTEND_1:
		moff = 4;
        extra = sizeof(uint16_t);
		len = net_read16(&nb->buf[2]);
		break;
	case WEBSOCKET_PAYLOAD_EXTEND_2:
		moff = 10;
        extra = sizeof(uint64_t);
		len = net_read64(&nb->buf[2]);
		break;
	default:
		extra = 0;
		moff = 2;
		break;
	}

    if( len > server.websocket_maxframe )
    {
        log_debug("%p: frame too big", c);
        return CF_RESULT_ERROR;
	}

	extra += WEBSOCKET_FRAME_HDR;
	total = len + extra + WEBSOCKET_MASK_LEN;

    if( total > nb->b_len )
    {
		total -= nb->b_len;
		net_recv_expand(c, total, websocket_recv_frame);
        return CF_RESULT_OK;
	}

    if( total != nb->b_len )
        return CF_RESULT_ERROR;

    for( i = 0; i < len; i++ )
		nb->buf[moff + 4 + i] ^= nb->buf[moff + (i % 4)];

    ret = CF_RESULT_OK;

    switch( op )
    {
	case WEBSOCKET_OP_PONG:
		break;
	case WEBSOCKET_OP_CONT:
        ret = CF_RESULT_ERROR;
        cf_log(LOG_ERR, "%p: we do not support op 0x%02x yet", (void *)c, op);
		break;
	case WEBSOCKET_OP_TEXT:
	case WEBSOCKET_OP_BINARY:
        if( c->ws_message != NULL )
        {
            cf_runtime_wsmessage(c->ws_message,c, op, &nb->buf[moff + 4], len);
		}
		break;
	case WEBSOCKET_OP_CLOSE:
		c->flags &= ~CONN_READ_POSSIBLE;
        if( !(c->flags & CONN_WS_CLOSE_SENT) )
        {
			c->flags |= CONN_WS_CLOSE_SENT;
            cf_websocket_send(c, WEBSOCKET_OP_CLOSE, NULL, 0);
		}
        cf_connection_disconnect(c);
		break;
	case WEBSOCKET_OP_PING:
        cf_websocket_send(c, WEBSOCKET_OP_PONG, &nb->buf[moff + 4], len);
		break;
	default:
        log_debug("%p: bad websocket op %d", c, op);
        return CF_RESULT_ERROR;
	}

	net_recv_reset(c, WEBSOCKET_FRAME_HDR, websocket_recv_opcode);

    return ret;
}

static void websocket_disconnect(struct connection *c, int err)
{
    if( c->ws_disconnect != NULL )
        cf_runtime_wsdisconnect(c->ws_disconnect, c);

    if( !(c->flags & CONN_WS_CLOSE_SENT) )
    {
		c->flags &= ~CONN_READ_POSSIBLE;
		c->flags |= CONN_WS_CLOSE_SENT;
        cf_websocket_send(c, WEBSOCKET_OP_CLOSE, NULL, 0);
	}
}
