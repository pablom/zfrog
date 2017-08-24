// cf_redis.h

#ifndef __CF_REDIS_H_
#define __CF_REDIS_H_


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
    uint8_t	 flags;
    char	 *name;

    int fd;  /* Redis socket connection handle */

    struct redis_job        *job;
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
void cf_redis_handle(void *, int);

int cf_redis_format_command(char **target, const char *format, ...);


extern uint16_t g_redis_conn_max;

//typedef struct cf_redis_t  cf_redis;

//struct cf_redis;


#if defined(__cplusplus)
}
#endif


#endif /* __CF_REDIS_H_ */
