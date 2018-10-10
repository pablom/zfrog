
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <zfrog.h>
#include <cf_http.h>
#include <cf_tasks.h>

#include <fcntl.h>
#include <unistd.h>

#include "assets.h"

int	init(int);
int	page(struct http_request *);
int	page_ws_connect(struct http_request *);

void websocket_connect(struct connection *);
void websocket_disconnect(struct connection *);
void websocket_message(struct connection *, uint8_t, void *, size_t);

int	pipe_reader(struct cf_task *);
void pipe_data_available(struct cf_task *);

/* Our pipe reader */
struct cf_task	pipe_task;

/* Module init function (see config) */
int init( int state )
{
	/* Do not allow reload */
	if( state == CF_MODULE_UNLOAD )
		return CF_RESULT_ERROR;

	/* Only do this on a dedicated worker */
    if( server.worker->id != 1 )
		return CF_RESULT_OK;

	/* Create our task */
	cf_task_create(&pipe_task, pipe_reader);

	/* Bind a callback whenever data is available from task */
	cf_task_bind_callback(&pipe_task, pipe_data_available);

	/* Start the task */
	cf_task_run(&pipe_task);

	return CF_RESULT_OK;
}

/* Called whenever we get a new websocket connection */
void websocket_connect( struct connection *c )
{
	cf_log(LOG_NOTICE, "%p: connected", c);
}

/* Called whenever we receive a websocket message from a client */
void websocket_message(struct connection *c, uint8_t op, void *data, size_t len)
{
	/* Not doing anything with this. */
}

/* Called whenever a websocket goes away */
void websocket_disconnect(struct connection *c)
{
	cf_log(LOG_NOTICE, "%p: disconnecting", c);
}

/* The / page */
int page(struct http_request *req)
{
	http_response_header(req, "content-type", "text/html");
	http_response(req, 200, asset_frontend_html, asset_len_frontend_html);

	return CF_RESULT_OK;
}

/* The /connect page */
int page_ws_connect(struct http_request *req)
{
	cf_websocket_handshake(req, "websocket_connect", "websocket_message", "websocket_disconnect");
	return CF_RESULT_OK;
}

/*
 * The pipe reader task. This task simply waits for a writer end
 * on a named pipe and reads from it. The bytes read are written
 * on the task channel because the task does not own any connection
 * data structures and shouldn't reference them directly.
 */
int pipe_reader( struct cf_task *t )
{
	int	fd;
	ssize_t ret;
	uint8_t	buf[BUFSIZ];

	fd = -1;

	cf_log(LOG_INFO, "pipe_reader starting");

	/* Just run forever */
	for( ;; ) 
	{
		/* Attempt to open the pipe if needed */
		if( fd == -1 ) 
		{
			cf_log(LOG_NOTICE, "waiting for writer");

			if( (fd = open("/tmp/pipe", O_RDONLY)) == -1 ) 
			{
				cf_log(LOG_NOTICE, "failed to open pipe");
				sleep(1);
				continue;
			}

			cf_log(LOG_NOTICE, "writer connected");
		}

		/* Got a writer on the other end so start reading */
		ret = read(fd, buf, sizeof(buf));
		if( ret == -1 ) 
		{
			cf_log(LOG_ERR, "read error on pipe");
			close(fd);
			fd = -1;
			continue;
		}

        if( ret == 0 )
		{
			cf_log(LOG_NOTICE, "writer disconnected");
			close(fd);
			fd = -1;
			continue;
		}

		cf_log(LOG_NOTICE, "got %ld bytes from pipe", ret);

		/*
		 * Write data on the task channel so our main event loop
		 * will call the registered callback
		 */
		cf_task_channel_write(t, buf, ret);
	}

	return CF_RESULT_OK;
}

/* Called on the main event loop whenever a task event fires */
void pipe_data_available(struct cf_task *t)
{
	size_t	len;
	uint8_t buf[BUFSIZ];

	/* Deal with the task finishing, we could restart it from here */
	if( cf_task_finished(t) ) 
	{
		cf_log(LOG_WARNING, "task finished");
		return;
	}

	/* Read data from the task channel. */
	len = cf_task_channel_read(t, buf, sizeof(buf));
	if( len > sizeof(buf) )
		cf_log(LOG_WARNING, "truncated data from task");

	/* Broadcast it to all connected websocket clients. */
	cf_log(LOG_NOTICE, "got %zu bytes from task", len);

	cf_websocket_broadcast(NULL, WEBSOCKET_OP_TEXT,buf, len, WEBSOCKET_BROADCAST_GLOBAL);
}
