// cf_bsd.c

#include <sys/param.h>
#include <sys/event.h>
#include <sys/sysctl.h>

#if defined(__FreeBSD_version)
    #include <sys/cpuset.h>
#endif

#include <errno.h>
#include <string.h>

#include "zfrog.h"

#ifdef CF_PGSQL
    #include "cf_pgsql.h"
#endif

#ifdef CF_TASKS
    #include "cf_tasks.h"
#endif

static int kfd = -1;
static struct kevent *events = NULL;
static uint32_t event_count = 0;

/****************************************************************
 *  Init platform function
 ****************************************************************/
void cf_platform_init()
{
#if defined(__MACH__) || defined(__FreeBSD_version)
	long	n;
	size_t	len = sizeof(n);
	int	mib[] = { CTL_HW, HW_NCPU };

    if( sysctl(mib, 2, &n, &len, NULL, 0) == -1 )
    {
        log_debug("cf_platform_init(): sysctl %s", errno_s);
        server.cpu_count = 1;
    }
    else {
        server.cpu_count = (uint16_t)n;
	}
#else
    server.cpu_count = 0;
#endif /* __MACH__ || __FreeBSD_version */
}
/****************************************************************
 *  Move worker to cpu core
 ****************************************************************/
void cf_platform_worker_setcpu( struct cf_worker *kw )
{
#if defined(__FreeBSD_version)
	cpuset_t	cpuset;

	CPU_ZERO(&cpuset);
	CPU_SET(kw->cpu, &cpuset);
    if( cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof(cpuset), &cpuset) == -1 ) {
		cf_fatal("failed: %s", errno_s);
	}

#endif /* __FreeBSD_version */
}
/****************************************************************
 *  Event platform init function
 ****************************************************************/
void cf_platform_event_init()
{
    struct listener	*l = NULL;

    if( (kfd = kqueue()) == -1 )
		cf_fatal("kqueue(): %s", errno_s);

    event_count = server.worker_max_connections + server.nlisteners;
    events = mem_calloc(event_count, sizeof(struct kevent));

    /* Hack to check if we're running under the parent or not */
    if( server.worker != NULL )
    {
        LIST_FOREACH(l, &server.listeners, list)
        {
            cf_platform_event_schedule(l->fd, EVFILT_READ, EV_ADD | EV_DISABLE, l);
		}
	}
}
/****************************************************************
 *  Cleanup event platform init function
 ****************************************************************/
void cf_platform_event_cleanup()
{
    if( kfd != -1 )
    {
		close(kfd);
		kfd = -1;
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
int cf_platform_event_wait(uint64_t timer)
{
    uint32_t r;
    struct listener *l = NULL;
    struct connection *c = NULL;
    uint8_t type;
    struct timespec timeo;
    int	n, i;

	timeo.tv_sec = timer / 1000;
	timeo.tv_nsec = (timer % 1000) * 1000000;
	n = kevent(kfd, NULL, 0, events, event_count, &timeo);

    if( n == -1 )
    {
        if( errno == EINTR )
            return 0;
		cf_fatal("kevent(): %s", errno_s);
	}

    if( n > 0 )
        log_debug("main(): %d sockets available", n);

	r = 0;
    for(i = 0; i < n; i++)
    {
        if( events[i].udata == NULL )
			cf_fatal("events[%d].udata == NULL", i);

        type = *(uint8_t *)events[i].udata;

        if( events[i].flags & EV_EOF || events[i].flags & EV_ERROR )
        {
            switch( type )
            {
            case CF_TYPE_LISTENER:
				cf_fatal("error on server socket");
				/* NOTREACHED */
#ifdef CF_PGSQL
            case CF_TYPE_PGSQL_CONN:
                cf_pgsql_handle(events[i].udata, 1);
				break;
#endif
#ifdef CF_TASKS
            case CF_TYPE_TASK:
                cf_task_handle(events[i].udata, 1);
				break;
#endif
			default:
				c = (struct connection *)events[i].udata;
                cf_connection_disconnect(c);
				break;
			}

			continue;
		}

        switch( type )
        {
        case CF_TYPE_LISTENER:
			l = (struct listener *)events[i].udata;

            while( server.worker_active_connections < server.worker_max_connections )
            {
                if( server.worker_accept_threshold != 0 && r >= server.worker_accept_threshold )
					break;

                if( !connection_accept(l, &c) )
                {
					r = 1;
					break;
				}

                if( c == NULL )
					break;

				r++;
                cf_platform_event_all(c->fd, c);
			}
			break;
        case CF_TYPE_CLIENT:
			c = (struct connection *)events[i].udata;
            if( events[i].filter == EVFILT_READ && !(c->flags & CONN_READ_BLOCK) )
				c->flags |= CONN_READ_POSSIBLE;

            if( events[i].filter == EVFILT_WRITE && !(c->flags & CONN_WRITE_BLOCK) )
				c->flags |= CONN_WRITE_POSSIBLE;

            if( c->handle != NULL && !c->handle(c) )
                cf_connection_disconnect(c);
			break;
#ifdef CF_PGSQL
        case CF_TYPE_PGSQL_CONN:
            cf_pgsql_handle(events[i].udata, 0);
			break;
#endif

#ifdef CF_TASKS
        case CF_TYPE_TASK:
            cf_task_handle(events[i].udata, 0);
			break;
#endif
		default:
			cf_fatal("wrong type in event %d", type);
		}
	}

	return (r);
}
/****************************************************************
 *  Helper function add file descriptor to catch
 *  all available events to scheduler
 ****************************************************************/
void cf_platform_event_all(int fd, void *c)
{
    cf_platform_event_schedule(fd, EVFILT_READ, EV_ADD | EV_CLEAR, c);
    cf_platform_event_schedule(fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, c);
}
/****************************************************************
 *  Helper function add file descriptor to event scheduler
 ****************************************************************/
void cf_platform_event_schedule(int fd, int type, int flags, void *data)
{
    struct kevent event[1];

	EV_SET(&event[0], fd, type, flags, 0, 0, data);
    if( kevent(kfd, event, 1, NULL, 0, NULL) == -1 )
		cf_fatal("kevent: %s", errno_s);
}
/****************************************************************
 *  Helper function add file descriptor to catch
 *  only incoming data available events to scheduler
 ****************************************************************/
void cf_platform_enable_accept(void)
{
    struct listener	*l = NULL;

    LIST_FOREACH(l, &server.listeners, list)
        cf_platform_event_schedule(l->fd, EVFILT_READ, EV_ENABLE, l);
}
/****************************************************************
 *  Remove all listeners from event scheduler
 ****************************************************************/
void cf_platform_disable_accept()
{
    struct listener	*l = NULL;

    LIST_FOREACH(l, &server.listeners, list)
        cf_platform_event_schedule(l->fd, EVFILT_READ, EV_DISABLE, l);
}
/****************************************************************
 *  Helper function add file descriptor to catch
 *  only incoming data available events to scheduler
 ****************************************************************/
void cf_platform_schedule_read(int fd, void *data)
{
    cf_platform_event_schedule(fd, EVFILT_READ, EV_ADD, data);
}
/****************************************************************
 *  Helper function add file descriptor to catch
 *  only outgoing data available events to scheduler
 ****************************************************************/
void cf_platform_schedule_write(int fd, void *data)
{
    cf_platform_event_schedule(fd, EVFILT_WRITE, EV_ADD, data);
}
/****************************************************************
 *  Helper function add file descriptor to disable
 *  catch incoming data events
 ****************************************************************/
void cf_platform_disable_events(int fd)
{
    cf_platform_event_schedule(fd, EVFILT_READ, EV_DELETE, NULL);
}
/****************************************************************
 *  Set proc title function
 ****************************************************************/
void cf_platform_proctitle( char *title )
{
#ifndef __MACH__
	setproctitle("%s", title);
#endif
}
