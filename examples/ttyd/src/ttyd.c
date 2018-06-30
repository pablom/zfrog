
#include <zfrog.h>
#include <cf_http.h>

#include "assets.h"

int	page(struct http_request *);
int	page_ws_connect(struct http_request *);

void websocket_connect(struct connection *);
void websocket_disconnect(struct connection *);
void websocket_message(struct connection *, uint8_t, void *, size_t);

/* Called whenever we get a new websocket connection */
void websocket_connect( struct connection *c )
{
	cf_log(LOG_NOTICE, "%p: connected", c);
}

void websocket_message( struct connection *c, uint8_t op, void *data, size_t len )
{
	cf_websocket_broadcast(c, op, data, len, WEBSOCKET_BROADCAST_GLOBAL);
}

void websocket_disconnect( struct connection *c )
{
	cf_log(LOG_NOTICE, "%p: disconnecting", c);
}

int page( struct http_request *req )
{
	http_response_header(req, "content-type", "text/html");
	http_response(req, 200, asset_frontend_html, asset_len_frontend_html);

	return CF_RESULT_OK;
}

int page_ws_connect( struct http_request *req )
{
	/* Perform the websocket handshake, passing our callbacks */
	cf_websocket_handshake(req, "websocket_connect", "websocket_message", "websocket_disconnect");

	return CF_RESULT_OK;
}
