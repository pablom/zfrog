
#include <zfrog.h>
#include <cf_http.h>

/*
 * This example demonstrates how to use the messaging framework
 * in zFrog. This framework allows you to send messages between
 * your workers with custom callbacks defined per message ID.
 */

/* Your code shouldn't use IDs < 100 */
#define MY_MESSAGE_ID		100

int	init(int);
int	page(struct http_request *);
int	page_shutdown(struct http_request *req);
void received_message(struct cf_msg *, const void *);

/* Initialization callback. */
int init( int state )
{
	if( state == CF_MODULE_UNLOAD )
		return CF_RESULT_OK;

	/*
	 * Register our message callback when the module is initialized.
	 * cf_msg_register() fails if the message ID already exists,
	 * but in our case that is OK.
	 */
	cf_msg_register(MY_MESSAGE_ID, received_message);

	return CF_RESULT_OK;
}

/*
 * Callback for receiving a message MY_MESSAGE_ID.
 */
void received_message(struct cf_msg *msg, const void *data)
{
	cf_log(LOG_INFO, "got message from %u (%d bytes): %.*s", msg->src, msg->length, msg->length, (const char *)data);
}

/*
 * Page request which will send a message to all other workers
 * with the ID set to MY_MESSAGE_ID and a payload of "hello"
 */
int page( struct http_request *req )
{
	/* Send to all workers first */
	cf_msg_send(CF_MSG_WORKER_ALL, MY_MESSAGE_ID, "hello", 5);

	/* Now send something to worker number #2 only. */
	cf_msg_send(2, MY_MESSAGE_ID, "hello number 2", 14);

	http_response(req, 200, NULL, 0);
	return CF_RESULT_OK;
}

/*
 * Page request which will send a message to the parent
 * requesting process shutdown.
 */
int page_shutdown(struct http_request *req)
{
	/* Send shutdown request to parent */
	cf_msg_send(CF_MSG_PARENT, CF_MSG_SHUTDOWN, "1", 1);

	http_response(req, 200, NULL, 0);
	return CF_RESULT_OK;
}
