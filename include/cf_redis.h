// cf_redis.h

#ifndef __CF_REDIS_H_
#define __CF_REDIS_H_

#include <stdint.h>

#define REDIS_CONN_READ_POSSIBLE    0x0001
#define REDIS_CONN_WRITE_POSSIBLE   0x0002
#define REDIS_CONN_WRITE_BLOCK      0x0004
#define REDIS_CONN_FREE             0x0008
#define REDIS_CONN_IDLE_TIMER_ACT   0x1000
#define REDIS_CONN_READ_BLOCK       0x2000


#define CF_REDIS_SYNC           0x0001
#define CF_REDIS_ASYNC          0x0002
#define CF_REDIS_SCHEDULED		0x0004

#define CF_REDIS_STATE_INIT         1
#define CF_REDIS_STATE_WAIT         2
#define CF_REDIS_STATE_RESULT		3
#define CF_REDIS_STATE_ERROR		4
#define CF_REDIS_STATE_DONE         5
#define CF_REDIS_STATE_COMPLETE     6


#if defined(__cplusplus)
extern "C" {
#endif


struct redis_conn
{
    uint8_t	 type;
    int      fd;     /* Redis socket handle */
    uint8_t  state;
    uint8_t	 flags;
    char	 *name;

    int	   (*handle)(struct redis_conn *); /* Callback function to catch redis events */

    struct redis_job   *job;
    TAILQ_ENTRY(redis_conn) list;
};

struct cf_redis
{
    uint8_t		state;
    int			flags;
    char		*error;
    struct redis_conn *conn;

    struct http_request	*req;
    void *arg;
    void (*cb)(struct cf_redis *, void *);

    LIST_ENTRY(cf_redis) rlist;
};


void cf_redis_sys_init(void);
void cf_redis_sys_cleanup(void);
int cf_redis_register( char *, char *, int );
void cf_redis_init(struct cf_redis*);
int cf_redis_setup( struct cf_redis *, const char *, int );
void cf_redis_cleanup(struct cf_redis *);
void cf_redis_handle(struct redis_conn *, int);

int cf_redis_format_command(char **target, const char *format, ...);

void cf_redis_continue(struct cf_redis *);
void cf_redis_logerror(struct cf_redis *);
void cf_redis_bind_request( struct cf_redis*, struct http_request* );
void cf_redis_bind_callback( struct cf_redis *, void (*cb)(struct cf_redis *, void *), void *arg );

extern uint16_t redis_serv_conn_max;

//typedef struct cf_redis_t  cf_redis;

//struct cf_redis;


#if defined(__cplusplus)
}
#endif


#endif /* __CF_REDIS_H_ */
