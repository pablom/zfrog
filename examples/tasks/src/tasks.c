// tasks.c

#include <curl/curl.h>

#include <zfrog.h>
#include <cf_http.h>
#include <cf_tasks.h>

int	run_curl(struct cf_task *);
int	post_back(struct http_request *);
int	page_handler(struct http_request *);
size_t curl_write_cb(char *, size_t, size_t, void *);

struct rstate {
	struct cf_task	task;
};

int page_handler( struct http_request *req )
{
	uint32_t len = 0;
	struct rstate *state = NULL;
	char *user, result[64];

	/*
	 * Lets check if a task has been created yet, this is important
	 * as we only want to fire this off once and we will be called
     * again once it has been created
	 *
     * In this example, we'll store our state with our task in hdlr_extra
	 */
	if( req->hdlr_extra == NULL ) 
	{
		/* Grab the user argument */
		http_populate_get(req);
		if( !http_argument_get_string(req, "user", &user) ) 
		{
			http_response(req, 500, "ERROR\n", 6);
			return CF_RESULT_OK;
		}

		/*
		 * Allocate rstate and bind it to the hdlr_extra field.
		 * zfrog automatically frees this when freeing the result
		 */
		state = mem_malloc(sizeof(*state));
		req->hdlr_extra = state;

		/*
		 * Create a new task that will execute the run_curl()
		 * function and bind it to our request.
		 *
		 * Binding a task to a request means zfrog will reschedule
		 * the page handler for that request to refire after the
		 * task has completed or when it writes on the task channel.
		 */
		cf_task_create(&state->task, run_curl);
		cf_task_bind_request(&state->task, req);

		/*
		 * Start the task and write the user we received in our
		 * GET request to its channel.
		 */
		cf_task_run(&state->task);
		cf_task_channel_write(&state->task, user, strlen(user));

		/*
		 * Tell zfrog to retry us later
		 */
		return CF_RESULT_RETRY;
	} 
	else {
		state = req->hdlr_extra;
	}

	/*
	 * Our page handler is scheduled to be called when either the
	 * task finishes or has written data onto the channel.
	 *
	 * In order to distinguish between the two we can inspect the
	 * state of the task.
	 */
	if( cf_task_state(&state->task) != CF_TASK_STATE_FINISHED ) 
	{
		http_request_sleep(req);
		return CF_RESULT_RETRY;
	}

	/*
	 * Task is finished, check the result.
	 */
	if( cf_task_result(&state->task) != CF_RESULT_OK ) 
	{
		cf_task_destroy(&state->task);
		http_response(req, 500, NULL, 0);
		return CF_RESULT_OK;
	}

	/*
     * Lets read what our task has written to the channel
	 *
	 * cf_task_channel_read() will return the amount of bytes
	 * that it received for that read. If the returned bytes is
	 * larger then the buffer you passed this is a sign of truncation
	 * and should be treated carefully.
	 */
	len = cf_task_channel_read(&state->task, result, sizeof(result));
	if( len > sizeof(result) ) 
	{
		http_response(req, 500, NULL, 0);
	} 
    else
    {
		http_response(req, 200, result, len);
	}

    /* Destroy the task */
    cf_task_destroy( &state->task );

	return CF_RESULT_OK;
}

int post_back(struct http_request *req)
{
	char *user = NULL;

	if( req->method != HTTP_METHOD_POST ) 
	{
		http_response(req, 500, NULL, 0);
		return CF_RESULT_OK;
	}

	http_populate_post(req);
	if( !http_argument_get_string(req, "user", &user) ) 
	{
		http_response(req, 500, NULL, 0);
		return CF_RESULT_OK;
	}

	/* Simply echo the supplied user argument back */
	http_response(req, 200, user, strlen(user));

	return CF_RESULT_OK;
}
/*
 * This is the function that is executed by our task which is created
 * in the page_handler() callback.
 *
 * It sets up a CURL POST request to /post_back passing along the
 * user argument which it receives from its channel from page_handler().
 */
int run_curl( struct cf_task *t )
{
	struct cf_buf *b = NULL;
	uint32_t len = 0;
	CURLcode res;
	uint8_t	*data = NULL;
	CURL *curl = NULL;
	char user[64], fields[128];

	/*
	 * Read the channel in order to obtain the user argument
     * that was written to it by page_handler()
	 */
	len = cf_task_channel_read(t, user, sizeof(user));
	if( len > sizeof(user) )
		return CF_RESULT_ERROR;

	if( !cf_snprintf(fields, sizeof(fields), NULL, "user=%.*s", len, user) )
		return CF_RESULT_ERROR;

	if( (curl = curl_easy_init()) == NULL )
		return CF_RESULT_ERROR;

	b = cf_buf_alloc(128);

	/* Do CURL magic */
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, b);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
#if !defined(CF_NO_TLS)
	curl_easy_setopt(curl, CURLOPT_URL, "https://127.0.0.1:8888/post_back");
#else
	curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8888/post_back");
#endif

	res = curl_easy_perform(curl);
	if( res != CURLE_OK ) 
	{
		cf_buf_free(b);
		curl_easy_cleanup(curl);
		return CF_RESULT_ERROR;
	}

	/*
	 * Grab the response from the CURL request and write the
     * result back to the task channel
	 */
	data = cf_buf_release(b, &len);
	cf_task_channel_write(t, data, len);
	mem_free(data);

	return CF_RESULT_OK;
}

size_t curl_write_cb(char *ptr, size_t size, size_t nmemb, void *udata)
{
	struct cf_buf *b = udata;

	cf_buf_append(b, ptr, size * nmemb);
	return (size * nmemb);
}
