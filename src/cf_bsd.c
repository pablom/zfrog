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

#if defined(__OpenBSD__)
    #include <unistd.h>
#endif

#ifdef CF_PGSQL
    #include "cf_pgsql.h"
#endif

#ifdef CF_TASKS
    #include "cf_tasks.h"
#endif

static int kfd = -1;
static struct kevent *events = NULL;
static uint32_t event_count = 0;

#if defined(__OpenBSD__)
    static char	pledges[256] = { "stdio rpath inet error" };
#endif

/****************************************************************
 *  Init platform function
 ****************************************************************/
void cf_platform_init( void )
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
void cf_platform_event_init( void )
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
void cf_platform_event_cleanup( void )
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
    uint32_t  r = 0;
    struct cf_event	*evt = NULL;
    struct timespec timeo;
    int	n, i;

    struct listener *l = NULL;
    struct connection *c = NULL;
    uint8_t type;


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

    for(i = 0; i < n; i++)
    {
        if( events[i].udata == NULL )
			cf_fatal("events[%d].udata == NULL", i);

        /* Reinit return value */
        r = 0;
        evt = (struct cf_event*)events[i].udata;

        if( events[i].filter == EVFILT_READ )
            evt->flags |= CF_EVENT_READ;

        if( events[i].filter == EVFILT_WRITE )
            evt->flags |= CF_EVENT_WRITE;

        if( events[i].flags & EV_EOF || events[i].flags & EV_ERROR )
            r = 1;

        evt->handle(events[i].udata, r);
    }

    return r;
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
    cf_platform_event_schedule(fd, EVFILT_READ, EV_ADD | EV_CLEAR, data);
}
/****************************************************************
 *  Helper function add file descriptor to catch
 *  only outgoing data available events to scheduler
 ****************************************************************/
void cf_platform_schedule_write(int fd, void *data)
{
    cf_platform_event_schedule(fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, data);
}
/****************************************************************
 *  Helper function add file descriptor to disable
 *  catch incoming data events
 ****************************************************************/
void cf_platform_disable_read(int fd)
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

#ifndef CF_NO_SENDFILE
int cf_platform_sendfile( struct connection* c, struct netbuf* nb )
{
    int   ret;
    off_t len, smin;

    smin = nb->fd_len - nb->fd_off;
    len = MIN(SENDFILE_PAYLOAD_MAX, smin);

#if defined(__MACH__)
    ret = sendfile(nb->file_ref->fd, c->fd, nb->fd_off, &len, NULL, 0);
#else
    ret = sendfile(nb->file_ref->fd, c->fd, nb->fd_off, len, NULL, &len, 0);
#endif

    if( ret == -1 )
    {
        if( errno == EAGAIN )
        {
            nb->fd_off += len;
            c->evt.flags &= ~CF_EVENT_WRITE;
            return CF_RESULT_OK;
        }

        if( errno == EINTR )
        {
            nb->fd_off += len;
            return CF_RESULT_OK;
        }

        return CF_RESULT_ERROR;
    }

    nb->fd_off += len;

    if( len == 0 || nb->fd_off == nb->fd_len )
    {
        net_remove_netbuf(&(c->send_queue), nb);
        c->snb = NULL;
    }

    return CF_RESULT_OK;
}
#endif

#if defined(__OpenBSD__)
void cf_platform_pledge(void)
{
    if( pledge(pledges, NULL) == -1 )
        cf_fatal("failed to pledge process");
}

void cf_platform_add_pledge(const char* pledge)
{
    size_t len;

    len = strlcat(pledges, " ", sizeof(pledges));
    if( len >= sizeof(pledges) )
        cf_fatal("truncation on pledges");

    len = strlcat(pledges, pledge, sizeof(pledges));
    if( len >= sizeof(pledges) )
        cf_fatal("truncation on pledges (%s)", pledge);
 }
#endif
