// cf_linux.c

// http://pic.dhe.ibm.com/infocenter/aix/v7r1/topic/com.ibm.aix.basetechref/doc/basetrf1/pollset.htm?resultof=%22poll%22%20

#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sched.h>

#include "zfrog.h"

#ifdef CF_PGSQL
    #include "cf_pgsql.h"
#endif

#ifdef CF_TASKS
    #include "cf_tasks.h"
#endif

static int efd = -1;
static uint32_t event_count = 0;
static struct epoll_event *events = NULL;

/****************************************************************
 *  Init platform function
 ****************************************************************/
void cf_platform_init()
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
void cf_platform_event_init()
{
    if( (efd = epoll_create(10000)) == -1 )
		cf_fatal("epoll_create(): %s", errno_s);

    event_count = worker_max_connections + server.nlisteners;
    events = mem_calloc(event_count, sizeof(struct epoll_event));
}
/****************************************************************
 *  Cleanup event platform init function
 ****************************************************************/
void cf_platform_event_cleanup()
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
int cf_platform_event_wait( uint64_t timer )
{
    uint32_t r = 0; /* return value */
    struct connection *c = NULL;
    struct listener	*l = NULL;
    uint8_t type;
    int	n, i;

	n = epoll_wait(efd, events, event_count, timer);

    if( n == -1 )
    {
        if( errno == EINTR )
            return 0;
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

        type = *(uint8_t *)events[i].data.ptr;

        if( events[i].events & EPOLLERR || events[i].events & EPOLLHUP )
        {
            switch (type)
            {
            case CF_TYPE_LISTENER:
				cf_fatal("failed on listener socket");
				/* NOTREACHED */
#ifdef CF_PGSQL
            case CF_TYPE_PGSQL_CONN:
                cf_pgsql_handle(events[i].data.ptr, 1);
				break;
#endif
#ifdef CF_TASKS
            case CF_TYPE_TASK:
                cf_task_handle(events[i].data.ptr, 1);
				break;
#endif
			default:
				c = (struct connection *)events[i].data.ptr;
                cf_connection_disconnect(c);
				break;
			}

			continue;
		}

        switch( type )
        {
        case CF_TYPE_LISTENER:
			l = (struct listener *)events[i].data.ptr;

            while( server.worker_active_connections < server.worker_max_connections )
            {
                if( server.worker_accept_threshold != 0 && r >= server.worker_accept_threshold )
					break;

                if( !cf_connection_accept(l, &c) )
                {
					r = 1;
					break;
				}

				if (c == NULL)
					break;

				r++;
                cf_platform_event_all(c->fd, c);
			}
			break;

        case CF_TYPE_CLIENT:
			c = (struct connection *)events[i].data.ptr;

            if( events[i].events & EPOLLIN && !(c->flags & CONN_READ_BLOCK) )
				c->flags |= CONN_READ_POSSIBLE;

            if( events[i].events & EPOLLOUT && !(c->flags & CONN_WRITE_BLOCK) )
				c->flags |= CONN_WRITE_POSSIBLE;

            if( c->handle != NULL && !c->handle(c) )
                cf_connection_disconnect(c);

            break;
#ifdef CF_PGSQL
        case CF_TYPE_PGSQL_CONN:
            cf_pgsql_handle(events[i].data.ptr, 0);
			break;
#endif
#ifdef CF_TASKS
        case CF_TYPE_TASK:
            cf_task_handle(events[i].data.ptr, 0);
			break;
#endif
		default:
			cf_fatal("wrong type in event %d", type);
		}
	}

    return r;
}

void cf_platform_event_all(int fd, void *c)
{
    cf_platform_event_schedule(fd, EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, 0, c);
}
/****************************************************************
 *  Helper function add file descriptor to event scheduler
 ****************************************************************/
void cf_platform_event_schedule(int fd, int type, int flags, void *udata)
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

void cf_platform_schedule_read(int fd, void *data)
{
    cf_platform_event_schedule(fd, EPOLLIN, 0, data);
}

void cf_platform_schedule_write(int fd, void *data)
{
    cf_platform_event_schedule(fd, EPOLLOUT, 0, data);
}

void cf_platform_disable_events(int fd)
{
    if( epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL) == -1 )
        cf_fatal("cf_platform_disable_events: %s", errno_s);
}
/****************************************************************
 *  Add all listeners to event scheduler
 ****************************************************************/
void cf_platform_enable_accept()
{
    struct listener	*l = NULL;

    log_debug("cf_platform_enable_accept()");

	LIST_FOREACH(l, &listeners, list)
        cf_platform_event_schedule(l->fd, EPOLLIN, 0, l);
}
/****************************************************************
 *  Remove all listeners from event scheduler
 ****************************************************************/
void cf_platform_disable_accept()
{
    struct listener	*l = NULL;

    log_debug("cf_platform_disable_accept()");

    LIST_FOREACH(l, &listeners, list)
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

}
#endif
