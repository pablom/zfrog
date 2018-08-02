// cf_solaris.c

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <malloc.h>
#include <fcntl.h>

#include <sys/devpoll.h>
#include <sys/types.h>
#include <sys/processor.h>
#include <sys/procset.h>
#include <sys/sendfile.h>
#include <kstat.h>

#include <sys/port.h>
#include <port.h>


#include "zfrog.h"
#include "cf_common.h"


#ifdef CF_PGSQL
    #include "cf_pgsql.h"
#endif

#ifdef CF_TASKS
    #include "cf_tasks.h"
#endif

/*
    The port_event_t structure contains the following members:

    int       portev_events;   // detected events
    ushort_t  portev_source;   // event source
    uintptr_t portev_object;   // specific to event source
    void      *portev_user;    // user defined cookie
*/

static int evp = -1; /* event port descriptor */


struct event_base {
    int  evp;     /* event port descriptor */

    port_event_t *event;  /* event[] - events that were triggered */
    int          nevent;  /* # event */

    event_cb_t   cb;      /* event callback */
};

static uint32_t event_count = 0;
static struct port_event_t *events0 = NULL;
//static struct pollfd *events = NULL;

/****************************************************************
 *  Init platform function
 ****************************************************************/
void cf_platform_init(void)
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
void cf_platform_worker_setcpu( struct cf_worker *kw )
{
    // processor_bind(P_LWPID, P_MYID, kw->pid, NULL);
    processor_bind(P_LWPID, P_MYID, PBIND_NONE, NULL);
}
/****************************************************************
 *  Event platform init function
 ****************************************************************/
void cf_platform_event_init(void)
{
    /* Initialize the kernel queue, create a port */
    if( (evp = port_create()) < 0 )
        cf_fatal("port_create(): %s", errno_s);

    if( cf_cloexec_ioctl( evp, 1 ) == CF_RESULT_ERROR )
        cf_fatal("cf_cloexec_ioctl(): %s", errno_s);

    /* Open the driver */
  //  if( (pfd = open("/dev/poll", O_RDWR)) < 0 ) {
  //      cf_fatal("/dev/poll: %s", errno_s);
  //  }

    event_count = server.worker_max_connections + server.nlisteners;

    //events0 = mem_calloc( event_count, sizeof(struct port_event_t) );
    //events = mem_calloc( event_count, sizeof(struct pollfd) );

#ifdef NONE

    pollfd = (struct pollfd* )malloc(sizeof(struct pollfd) * MAXBUF);
            if (pollfd == NULL) {
                    close(wfd);
                    exit(-1);
            }
            /*
             * initialize buffer
             */
            for (i = 0; i < MAXBUF; i++) {
                    pollfd[i].fd = fds[i];
                    pollfd[i].events = POLLIN;
                    pollfd[i].revents = 0;
            }
            if (write(wfd, &pollfd[0], sizeof(struct pollfd) * MAXBUF) !=
                            sizeof(struct pollfd) * MAXBUF) {
                    perror("failed to write all pollfds");
                    close (wfd);
                    free(pollfd);
                    exit(-1);
            }
#endif

}
/****************************************************************
 *  Cleanup event platform init function
 ****************************************************************/
void cf_platform_event_cleanup(void)
{
    if( evp != -1 )
    {
        close( evp );
        evp = -1;
    }

    if( events0 != NULL )
    {
        mem_free(events0);
        events0 = NULL;
    }
}
/****************************************************************
 *  Event platform wait function
 ****************************************************************/
int cf_platform_event_wait( uint64_t timer )
{
    uint32_t r = 0; /* return value */
    uint_t i = 0;
    struct timespec timeo;
    int err;
    unsigned int nevents; /* number of signaled events */
    struct listener	*l = NULL;
    struct connection *c = NULL;
    uint8_t type;

    struct port_event events[1024];
     
    /* port_getn() should block indefinitely if timeout == 0 */
    if( timer > 0 )
        cf_ms2ts( &timeo, timer );

    nevents = 1;

    /*
     * port_getn() can return with errno == ETIME having returned some events (!).
     * So if we get ETIME, we check nevents, too
     */
    err = port_getn( evp, events, ARRAY_SIZE(events), &nevents, timer > 0 ? &timeo : NULL);

    if( err == -1 && (errno != ETIME || nevents == 0) )
    {
          if( errno == ETIME || errno == EINTR )
              return 0;

          /* Any other error indicates a bug */
          cf_fatal("port_getn(): %s", errno_s);
    }

    if( nevents > 0 ) {
        log_debug("cf_platform_event_wait(): %d sockets available", nevents);
    }
    
    for( i = 0; i < nevents; i++ )
    {
        if( events[i].portev_user == NULL )
            cf_fatal("events[%d].portev_user == NULL", i);

        type = *(uint8_t *)events[i].portev_user;

        if( events[i].portev_events & POLLERR || events[i].portev_events & POLLHUP )
        {
            switch (type)
            {
            case CF_TYPE_LISTENER:
                cf_fatal("failed on listener socket");
                /* NOTREACHED */
#ifdef CF_PGSQL
            case CF_TYPE_PGSQL_CONN:
                cf_pgsql_handle(events[i].portev_user, 1);
                break;
#endif
#ifdef CF_TASKS
            case CF_TYPE_TASK:
                cf_task_handle(events[i].portev_user, 1);
                break;
#endif
            default:
                c = (struct connection *)events[i].portev_user;
                cf_connection_disconnect(c);
                break;
            }

            continue;
        }

        switch( type )
        {
        case CF_TYPE_LISTENER:
            l = (struct listener *)events[i].portev_user;

            while( server.worker_active_connections < server.worker_max_connections )
            {
                if( server.worker_accept_threshold != 0 && r >= server.worker_accept_threshold )
                    break;

                if( !cf_connection_accept(l, &c) )
                {
                    r = 1;
                    break;
                }

                if( c == NULL )
                    break;

                r++;

                /* Add connection to evport scheduler */
                cf_platform_event_all(c->fd, c);

                /* Reassociate listener in evport scheduler */
                cf_platform_event_schedule(l->fd, POLLIN, 0, l);
            }
            break;

        case CF_TYPE_CLIENT:
            c = (struct connection *)events[i].portev_user;

            if( events[i].portev_events & POLLIN && !(c->flags & CONN_READ_BLOCK) )
                c->flags |= CONN_READ_POSSIBLE;

            if( events[i].portev_events & POLLOUT && !(c->flags & CONN_WRITE_BLOCK) )
                c->flags |= CONN_WRITE_POSSIBLE;

            if( c->handle != NULL && !c->handle(c) )
                cf_connection_disconnect( c );
            else /* Reassociate listener in evport scheduler */
                cf_platform_schedule_read(c->fd,c);

            break;

#ifdef CF_PGSQL
        case CF_TYPE_PGSQL_CONN:
            cf_pgsql_handle(events[i].portev_user, 0);
            break;
#endif

#ifdef CF_TASKS
        case CF_TYPE_TASK:
            cf_task_handle(events[i].portev_user, 0);
            break;
#endif
        default:
            cf_fatal("wrong type in event %d", type);
        }
    }

    return r;
}
/****************************************************************
 *  Helper function add file descriptor to event scheduler
 ****************************************************************/
void cf_platform_event_all( int fd, void *c )
{
   cf_platform_event_schedule(fd, POLLIN | POLLOUT /*| POLLRDHUP | POLLET*/, 0, c);
}
/****************************************************************
 *  Helper function add file descriptor to event scheduler
 ****************************************************************/
void cf_platform_event_schedule(int fd, int type, int flags, void *udata)
{
    log_debug("cf_platform_event_schedule(%d, %d, %d, %p)", fd, type, flags, udata);

    if( port_associate(evp, PORT_SOURCE_FD, fd, type, udata) ) {
      cf_fatal("port_associate(): %s", errno_s);
    }
}
/****************************************************************
 *  Helper function add file descriptor to event scheduler for
 *  catch available data
 ****************************************************************/
void cf_platform_schedule_read(int fd, void *data)
{
    cf_platform_event_schedule(fd, POLLIN, 0, data);
}

void cf_platform_schedule_write(int fd, void *data)
{
    cf_platform_event_schedule(fd, POLLOUT, 0, data);
}

void cf_platform_disable_events( int fd )
{
    if( port_dissociate(evp, PORT_SOURCE_FD, fd) != 0 ) {
        cf_fatal("port_associate(): %s", errno_s);
    }
}
/****************************************************************
 *  Add all listeners to event scheduler
 ****************************************************************/
void cf_platform_enable_accept()
{
    struct listener	*l = NULL;

    log_debug("cf_platform_enable_accept()");

    LIST_FOREACH(l, &server.listeners, list)
        cf_platform_event_schedule(l->fd, POLLIN /*| POLLOUT*/, 0, l);
}
/****************************************************************
 *  Remove all listeners from event scheduler
 ****************************************************************/
void cf_platform_disable_accept()
{
    struct listener	*l = NULL;

    log_debug("cf_platform_disable_accept()");

    LIST_FOREACH(l, &server.listeners, list)
    {
        if( port_dissociate(evp, PORT_SOURCE_FD, l->fd) != 0 )
            cf_fatal("cf_platform_disable_accept: %s", errno_s);
    }
}
/****************************************************************
 *  Set proc title function
 ****************************************************************/
void cf_platform_proctitle( char *title )
{
#if defined(PR_SET_NAME)
    if( prctl(PR_SET_NAME, title) == -1 )
        log_debug("prctl(): %s", errno_s);
#endif
}
/****************************************************************
 *  Helper function return uptime
 ****************************************************************/
#ifdef NONE
int cf_uptime( double* uptime )
{
    kstat_ctl_t *kc = NULL;
    kstat_t *ksp = NULL;
    kstat_named_t *knp = NULL;

    long hz = sysconf(_SC_CLK_TCK);

    if( (kc = kstat_open()) == NULL )
        return CF_RESULT_ERROR;

    ksp = kstat_lookup(kc, (char*) "unix", 0, (char*) "system_misc");

    if( kstat_read(kc, ksp, NULL) == -1 ) {
        *uptime = -1;
    }
    else
    {
        knp = (kstat_named_t*)  kstat_data_lookup(ksp, (char*) "clk_intr");
        *uptime = knp->value.ul / hz;
    }

    kstat_close( kc );

  return CF_RESULT_OK;
}
#endif

#ifndef CF_NO_SENDFILE
int cf_platform_sendfile( struct connection* c, struct netbuf* nb )
{
    size_t	len = 0;
    ssize_t	sent = 0;
    off_t	smin = 0;

    smin = nb->fd_len - nb->fd_off;
    len = MIN(SENDFILE_PAYLOAD_MAX, smin);

    if( (sent = sendfile(c->fd, nb->file_ref->fd, &nb->fd_off, len)) == -1 )
    {
        if( errno == EAGAIN )
        {
            c->flags &= ~CONN_WRITE_POSSIBLE;
            return CF_RESULT_OK;
        }

        if( errno == EINTR )
            return CF_RESULT_OK;

        return CF_RESULT_ERROR;
    }

    if( sent == 0 || nb->fd_off == nb->fd_len )
    {
        net_remove_netbuf(&(c->send_queue), nb);
        c->snb = NULL;
    }

    return CF_RESULT_OK;
}
#endif


/* Not implemented by default */
char* strsep( char** stringp, const char* delim )
{
    char *begin, *end;

    begin = *stringp;

    if( begin == NULL )
      return NULL;

    /* A frequent case is when the delimiter string contains only one
       character.  Here we don't need to call the expensive `strpbrk'
       function and instead work using `strchr'.  */
    if( delim[0] == '\0' || delim[1] == '\0' )
    {
        char ch = delim[0];

        if( ch == '\0' )
            end = NULL;
        else
        {
            if( *begin == ch )
                end = begin;
            else if( *begin == '\0' )
                end = NULL;
            else
                end = strchr (begin + 1, ch);
        }
    }
    else
        /* Find the end of the token.  */
        end = strpbrk (begin, delim);

    if( end )
    {
        /* Terminate the token and set *STRINGP past NUL character.  */
        *end++ = '\0';
        *stringp = end;
    }
    else
        /* No more delimiters; this is the last token.  */
        *stringp = NULL;

    return begin;
}

int vasprintf( char** ret, const char* format, va_list ap )
{
    size_t size;
    int len;
    va_list aq;

    va_copy(aq, ap);
    len = vsnprintf(NULL, 0, format, aq);
    va_end(aq);
    if( len < 0 || (*ret = malloc(size = len + 1)) == NULL )
        return -1;
    return vsnprintf(*ret, size, format, ap);
}
