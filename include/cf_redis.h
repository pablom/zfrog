// cf_redis.h

#ifndef __CF_REDIS_H_
#define __CF_REDIS_H_

#include <stdint.h>

#define REDIS_CONN_MAX          2   /* Default maximum redis connections */


#define REDIS_CONN_READ_POSSIBLE    0x0001
#define REDIS_CONN_WRITE_POSSIBLE   0x0002
#define REDIS_CONN_WRITE_BLOCK      0x0004

#define REDIS_CONN_IDLE_TIMER_ACT   0x1000
#define REDIS_CONN_READ_BLOCK       0x2000


#define REDIS_CONN_FREE             0x0008

#define CF_REDIS_SYNC               0x0001
#define CF_REDIS_ASYNC              0x0002
#define CF_REDIS_SCHEDULED          0x0004

/* Redis state defines */
#define CF_REDIS_STATE_CONNECTING   1
#define CF_REDIS_STATE_INIT         2
#define CF_REDIS_STATE_READY        3
#define CF_REDIS_STATE_WAIT         4
#define CF_REDIS_STATE_RESULT		5
#define CF_REDIS_STATE_ERROR		6
#define CF_REDIS_STATE_DONE         7
#define CF_REDIS_STATE_COMPLETE     8


/* Redis reply defines */
#define REDIS_REPLY_STRING      1
#define REDIS_REPLY_ARRAY       2
#define REDIS_REPLY_INTEGER     3
#define REDIS_REPLY_NIL         4
#define REDIS_REPLY_STATUS      5
#define REDIS_REPLY_ERROR       6


#if defined(__cplusplus)
extern "C" {
#endif


struct cf_redis_reply
{
    uint8_t     type;     /* Redis reply type */
    long long   integer;  /* The integer when type is REDIS_REPLY_INTEGER */
    size_t      len;      /* Length of string */
    char        *str;     /* Used for both REDIS_REPLY_ERROR and REDIS_REPLY_STRING */
    size_t      elements; /* number of elements, for REDIS_REPLY_ARRAY */

    struct cf_redis_reply **element; /* elements vector for REDIS_REPLY_ARRAY */
};


struct cf_redis
{
    uint8_t		state;
    int			flags;
    char		*error;

    struct redis_conn      *conn;  /* Pointer to Redis connection structure */
    struct cf_redis_reply  *reply; /* Redis reply */

#ifndef CF_NO_HTTP
    struct http_request	*req;      /* HTTP request */
#endif

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
void cf_redis_handle(void *, int);

void cf_redis_continue(struct cf_redis *);
void cf_redis_logerror(struct cf_redis *);
void cf_redis_bind_request( struct cf_redis*, struct http_request* );
void cf_redis_bind_callback( struct cf_redis *, void (*cb)(struct cf_redis *, void *), void *arg );


int cf_redis_format_command(char**, const char*, ...);
int cf_redis_query(struct cf_redis*, const char*, ...);


#if defined(__cplusplus)
}
#endif


#endif /* __CF_REDIS_H_ */
