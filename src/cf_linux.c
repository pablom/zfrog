// cf_linux.c

#include <sys/param.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/sendfile.h>
#include <sched.h>
#include "zfrog.h"

#ifdef CF_PGSQL
    #include "cf_pgsql.h"
#endif

#ifdef CF_TASKS
    #include "cf_tasks.h"
#endif

#ifdef CF_ORACLE
    #include "cf_oci.h"
#endif

static int efd = -1;
static uint32_t event_count = 0;
static struct epoll_event *events = NULL;

/****************************************************************
 *  Init platform function
 ****************************************************************/
void cf_platform_init( void )
{
    long n;

    if( (n = sysconf(_SC_NPROCESSORS_ONLN)) == -1 )
    {
        log_debug("could not get number of cpu's falling back to 1");
        server.cpu_count = 1;
    }
    else {
        server.cpu_count = (uint16_t)n;
	}
}
/****************************************************************
 *  Move worker to cpu core
 ****************************************************************/
void cf_platform_worker_setcpu(struct cf_worker *kw)
{
    cpu_set_t cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(kw->cpu, &cpuset);

    if( sched_setaffinity(0, sizeof(cpu_set_t), &cpuset) == -1){
        log_debug("cf_worker_setcpu(): %s", errno_s);
    }
    else{
        log_debug("cf_worker_setcpu(): worker %d on cpu %d", kw->id, kw->cpu);
	}
}
/****************************************************************
 *  Event platform init function
 ****************************************************************/
void cf_platform_event_init( void )
{
    if( efd != -1 )
        close(efd);

    if( events != NULL )
        mem_free( events );

    if( (efd = epoll_create(10000)) == -1 )
		cf_fatal("epoll_create(): %s", errno_s);

    event_count = server.worker_max_connections + server.nlisteners;
    events = mem_calloc(event_count, sizeof(struct epoll_event));
}
/****************************************************************
 *  Cleanup event platform init function
 ****************************************************************/
void cf_platform_event_cleanup( void )
{
    if( efd != -1 )
    {
        close( efd );
		efd = -1;
	}

    if( events != NULL )
    {
        mem_free(events);
		events = NULL;
	}
}
/****************************************************************
 *  Event platform wait function
 ****************************************************************/
void cf_platform_event_wait( uint64_t timer )
{
    uint32_t r = 0;
    struct cf_event	*evt = NULL;
    int	n, i;

    /* Wait events */
	n = epoll_wait(efd, events, event_count, timer);

    if( n == -1 )
    {
        if( errno == EINTR )
            return;
		cf_fatal("epoll_wait(): %s", errno_s);
	}

    if( n > 0 ) {
        log_debug("cf_platform_event_wait(): %d sockets available", n);
	}

    /* Iterate over all events */
    for( i = 0; i < n; i++ )
    {
        if( events[i].data.ptr == NULL )
			cf_fatal("events[%d].data.ptr == NULL", i);

        /* Reinit return value */
        r = 0;

        evt = (struct cf_event *)events[i].data.ptr;

        if( events[i].events & EPOLLIN )
            evt->flags |= CF_EVENT_READ;

        if( events[i].events & EPOLLOUT )
            evt->flags |= CF_EVENT_WRITE;

        if( events[i].events & EPOLLERR || events[i].events & EPOLLHUP || events[i].events & EPOLLRDHUP )
            r = 1;

        evt->handle(events[i].data.ptr, r);
    }
}
/****************************************************************
 *  Helper function add file descriptor to catch
 *  all available events to scheduler
 ****************************************************************/
void cf_platform_event_all( int fd, void *c )
{
    cf_platform_event_schedule(fd, EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, 0, c);
}
/****************************************************************
 *  Helper function add file descriptor to event scheduler
 ****************************************************************/
void cf_platform_event_schedule( int fd, int type, int flags, void *udata )
{
	struct epoll_event	evt;

    log_debug("cf_platform_event_schedule(%d, %d, %d, %p)", fd, type, flags, udata);

	evt.events = type;
	evt.data.ptr = udata;

    if( epoll_ctl(efd, EPOLL_CTL_ADD, fd, &evt) == -1 )
    {
        if( errno == EEXIST )
        {
            if( epoll_ctl(efd, EPOLL_CTL_MOD, fd, &evt) == -1 )
				cf_fatal("epoll_ctl() MOD: %s", errno_s);
        }
        else
			cf_fatal("epoll_ctl() ADD: %s", errno_s);
	}
}
/****************************************************************
 *  Helper function add file descriptor to catch
 *  only incoming data available events to scheduler
 ****************************************************************/
void cf_platform_schedule_read( int fd, void *data )
{
    cf_platform_event_schedule(fd, EPOLLIN | EPOLLET, 0, data);
}
/****************************************************************
 *  Helper function add file descriptor to catch
 *  only outgoing data available events to scheduler
 ****************************************************************/
void cf_platform_schedule_write( int fd, void *data )
{
    cf_platform_event_schedule(fd, EPOLLOUT | EPOLLET, 0, data);
}
/****************************************************************
 *  Helper function add file descriptor to disable
 *  catch incoming data events
 ****************************************************************/
void cf_platform_disable_read( int fd )
{
    if( epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL) == -1 )
        cf_fatal("cf_platform_disable_events(): %s", errno_s);
}
/****************************************************************
 *  Add all listeners to event scheduler
 ****************************************************************/
void cf_platform_enable_accept( void )
{
    struct listener	*l = NULL;

    log_debug("cf_platform_enable_accept()");

    LIST_FOREACH(l, &server.listeners, list)
        cf_platform_event_schedule(l->fd, EPOLLIN, 0, l);
}
/****************************************************************
 *  Remove all listeners from event scheduler
 ****************************************************************/
void cf_platform_disable_accept( void )
{
    struct listener	*l = NULL;

    log_debug("cf_platform_disable_accept()");

    LIST_FOREACH(l, &server.listeners, list)
    {
        if( epoll_ctl(efd, EPOLL_CTL_DEL, l->fd, NULL) == -1 )
            cf_fatal("cf_platform_disable_accept: %s", errno_s);
	}
}
/****************************************************************
 *  Set proc title function
 ****************************************************************/
void cf_platform_proctitle( char *title )
{
    if( prctl(PR_SET_NAME, title) == -1 )
        log_debug("prctl(): %s", errno_s);
}

#ifndef CF_NO_SENDFILE
int cf_platform_sendfile( struct connection* c, struct netbuf* nb )
{
    ssize_t	sent = 0;
    off_t	smin = nb->fd_len - nb->fd_off;
    size_t  prevoff = nb->fd_off;
    size_t	len = MIN(SENDFILE_PAYLOAD_MAX, smin);

    do
    {
        if( (sent = sendfile(c->fd, nb->file_ref->fd, &nb->fd_off, len)) == -1 )
        {
            if( errno == EAGAIN )
            {
                c->evt.flags &= ~CF_EVENT_WRITE;
                return CF_RESULT_OK;
            }

            if( errno == EINTR )
                return CF_RESULT_OK;

            return CF_RESULT_ERROR;
        }
    }
    while( nb->fd_off - prevoff != (size_t)len );

    if( sent == 0 || nb->fd_off == nb->fd_len )
    {
        net_remove_netbuf(c, nb);
        c->snb = NULL;
    }

    return CF_RESULT_OK;
}
#endif /* CF_NO_SENDFILE */

