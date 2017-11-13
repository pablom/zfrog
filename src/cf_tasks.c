// cf_tasks.c

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "zfrog.h"

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

#include "cf_tasks.h"

/* Global variables */
static uint8_t threads;
static TAILQ_HEAD(, cf_task_thread)	task_threads;

uint16_t cf_task_threads = CF_TASK_THREADS;

/* Forward function declaration */
static void	*task_thread(void *arg);
static void	task_channel_read(int fd, void *out, uint32_t len);
static void	task_channel_write(int fd, void *data, uint32_t len);
static void	task_thread_spawn(struct cf_task_thread **out);

/* Helper macros */
#define THREAD_FD_ASSIGN(t, f, i, o) \
    do {							 \
        if (pthread_self() == t) {	 \
            f = i;					 \
        } else {					 \
            f = o;					 \
        }						     \
	} while (0);


/****************************************************************
 *  Init tasks parameters
 ****************************************************************/
void cf_task_init(void)
{
	threads = 0;
    TAILQ_INIT( &task_threads );
}
/****************************************************************
 *  Create task thread
 ****************************************************************/
void cf_task_create( struct cf_task *t, int (*entry)(struct cf_task *) )
{
	t->cb = NULL;
#ifndef CF_NO_HTTP
	t->req = NULL;
#endif
	t->entry = entry;
    t->type = CF_TYPE_TASK;
    t->state = CF_TASK_STATE_CREATED;
	pthread_rwlock_init(&(t->lock), NULL);

    if( socketpair(AF_UNIX, SOCK_STREAM, 0, t->fds) == -1 )
        cf_fatal("cf_task_create: socketpair() %s", errno_s);
}
/****************************************************************
 *  Run task
 ****************************************************************/
void cf_task_run( struct cf_task *t )
{
    struct cf_task_thread *tt;

    cf_platform_schedule_read( t->fds[0], t);

    if( threads < cf_task_threads )
    {
        /* task_thread_spawn() will lock tt->lock for us */
        task_thread_spawn( &tt );
    }
    else
    {
        /* Cycle task around */
        if( (tt = TAILQ_FIRST(&task_threads)) == NULL )
            cf_fatal("no available tasks threads?");
		pthread_mutex_lock(&(tt->lock));
		TAILQ_REMOVE(&task_threads, tt, list);
		TAILQ_INSERT_TAIL(&task_threads, tt, list);
	}

	t->thread = tt;
    TAILQ_INSERT_TAIL( &(tt->tasks), t, list);

    pthread_mutex_unlock( &(tt->lock) );
    pthread_cond_signal( &(tt->cond) );
}

#ifndef CF_NO_HTTP
void cf_task_bind_request( struct cf_task *t, struct http_request *req )
{
    log_debug("cf_task_bind_request: %p bound to %p", req, t);

    if( t->cb != NULL ) {
        cf_fatal("cannot bind cbs and requests at the same time");
    }

	t->req = req;
    LIST_INSERT_HEAD( &(req->tasks), t, rlist);

    http_request_sleep( req );
}
#endif

void cf_task_bind_callback( struct cf_task *t, void (*cb)(struct cf_task *) )
{
#ifndef CF_NO_HTTP
    if( t->req != NULL )
        cf_fatal("cannot bind requests and cbs at the same time");
#endif
	t->cb = cb;
}
/****************************************************************
 *  Destroy task parameters
 ****************************************************************/
void cf_task_destroy(struct cf_task *t)
{
    log_debug("cf_task_destroy: %p", t);

#ifndef CF_NO_HTTP
    if( t->req != NULL )
    {
		t->req = NULL;
		LIST_REMOVE(t, rlist);
	}
#endif

    pthread_rwlock_wrlock( &(t->lock) );

    if( t->fds[0] != -1 )
    {
        close(t->fds[0]);
		t->fds[0] = -1;
	}

    if( t->fds[1] != -1 )
    {
        close(t->fds[1]);
		t->fds[1] = -1;
	}

	pthread_rwlock_unlock(&(t->lock));
	pthread_rwlock_destroy(&(t->lock));
}
/****************************************************************
 *  Get task as boolean result finished or not
 ****************************************************************/
int cf_task_finished( struct cf_task *t )
{
    return ((cf_task_state(t) == CF_TASK_STATE_FINISHED));
}
/****************************************************************
 *  Task finished function
 ****************************************************************/
void cf_task_finish( struct cf_task *t )
{
    log_debug("cf_task_finished: %p (%d)", t, t->result);

	pthread_rwlock_wrlock(&(t->lock));

    if( t->fds[1] != -1 )
    {
        close(t->fds[1]);
		t->fds[1] = -1;
	}

	pthread_rwlock_unlock(&(t->lock));
}

void cf_task_channel_write(struct cf_task *t, void *data, uint32_t len)
{
    int	fd;

    log_debug("cf_task_channel_write: %p <- %p (%ld)", t, data, len);
	THREAD_FD_ASSIGN(t->thread->tid, fd, t->fds[1], t->fds[0]);
	task_channel_write(fd, &len, sizeof(len));
	task_channel_write(fd, data, len);
}

uint32_t cf_task_channel_read(struct cf_task *t, void *out, uint32_t len)
{
    int	fd;
    uint32_t	dlen, bytes;

    log_debug("cf_task_channel_read: %p -> %p (%ld)", t, out, len);

	THREAD_FD_ASSIGN(t->thread->tid, fd, t->fds[1], t->fds[0]);
	task_channel_read(fd, &dlen, sizeof(dlen));

    if( dlen > len )
		bytes = len;
	else
		bytes = dlen;

	task_channel_read(fd, out, bytes);

    return dlen;
}

void cf_task_handle( struct cf_task *t, int finished )
{
    log_debug("cf_task_handle: %p, %d", t, finished);

#ifndef CF_NO_HTTP
    if( t->req != NULL )
		http_request_wakeup(t->req);
#endif

    if( finished )
    {
        cf_platform_disable_read(t->fds[0]);
        cf_task_set_state(t, CF_TASK_STATE_FINISHED);
#ifndef CF_NO_HTTP
        if( t->req != NULL )
        {
            if( t->req->flags & HTTP_REQUEST_DELETE )
                cf_task_destroy(t);
		}
#endif
	}

    /* Call callback function */
    if( t->cb != NULL )
        t->cb( t );
}
/****************************************************************
 *  Get task state function
 ****************************************************************/
int cf_task_state( struct cf_task *t )
{
	int	s;

	pthread_rwlock_rdlock(&(t->lock));
	s = t->state;
	pthread_rwlock_unlock(&(t->lock));

    return s;
}
/****************************************************************
 *  Set task state function
 ****************************************************************/
void cf_task_set_state(struct cf_task *t, int state)
{
	pthread_rwlock_wrlock(&(t->lock));
	t->state = state;
	pthread_rwlock_unlock(&(t->lock));
}
/****************************************************************
 *  Get task result function
 ****************************************************************/
int cf_task_result(struct cf_task *t)
{
	int	r;

	pthread_rwlock_rdlock(&(t->lock));
	r = t->result;
	pthread_rwlock_unlock(&(t->lock));

    return r;
}
/****************************************************************
 *  Set task result function
 ****************************************************************/
void cf_task_set_result(struct cf_task *t, int result)
{
	pthread_rwlock_wrlock(&(t->lock));
	t->result = result;
	pthread_rwlock_unlock(&(t->lock));
}
/****************************************************************
 *  Internal helper function
 ****************************************************************/
static void task_channel_write(int fd, void *data, uint32_t len)
{
    ssize_t	r;
    uint8_t *d = data;
    uint32_t offset = 0;

    while( offset != len )
    {
		r = write(fd, d + offset, len - offset);
        if( r == -1 && errno == EINTR )
			continue;
        if( r == -1 )
            cf_fatal("task_channel_write: %s", errno_s);
		offset += r;
	}
}
/****************************************************************
 *  Internal helper function
 ****************************************************************/
static void task_channel_read(int fd, void *out, uint32_t len)
{
    ssize_t	r;
    uint8_t *d = out;
    uint32_t offset = 0;

    while( offset != len )
    {
		r = read(fd, d + offset, len - offset);
		if (r == -1 && errno == EINTR)
			continue;
		if (r == -1)
            cf_fatal("task_channel_read: %s", errno_s);
		if (r == 0)
            cf_fatal("task_channel_read: unexpected eof");

		offset += r;
	}
}
/****************************************************************
 *  Internal helper function
 ****************************************************************/
static void task_thread_spawn( struct cf_task_thread **out )
{
    struct cf_task_thread	*tt = NULL;

	tt = mem_malloc(sizeof(*tt));
	tt->idx = threads++;

	TAILQ_INIT(&(tt->tasks));
	pthread_cond_init(&(tt->cond), NULL);
	pthread_mutex_init(&(tt->lock), NULL);
	pthread_mutex_lock(&(tt->lock));
	TAILQ_INSERT_TAIL(&task_threads, tt, list);

    if( pthread_create(&(tt->tid), NULL, task_thread, tt) != 0 ) {
        cf_fatal("pthread_create: %s", errno_s);
    }

	*out = tt;
}
/****************************************************************
 *  Internal helper function
 ****************************************************************/
static void * task_thread( void *arg )
{
    struct cf_task *t = NULL;
    struct cf_task_thread *tt = arg;

	log_debug("task_thread: #%d starting", tt->idx);

	pthread_mutex_lock(&(tt->lock));

    for(;;)
    {
        if( TAILQ_EMPTY(&(tt->tasks)) )
			pthread_cond_wait(&(tt->cond), &(tt->lock));

		log_debug("task_thread#%d: woke up", tt->idx);

		t = TAILQ_FIRST(&(tt->tasks));
		TAILQ_REMOVE(&(tt->tasks), t, list);
		pthread_mutex_unlock(&(tt->lock));

		log_debug("task_thread#%d: executing %p", tt->idx, t);

        cf_task_set_state(t, CF_TASK_STATE_RUNNING);
        cf_task_set_result(t, t->entry(t));
        cf_task_finish(t);

		pthread_mutex_lock(&(tt->lock));
	}

	pthread_exit(NULL);

	/* NOTREACHED */
    return NULL;
}
