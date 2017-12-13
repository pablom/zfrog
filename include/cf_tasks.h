// cf_tasks.h


#ifndef __CF_TASKS_H__
#define __CF_TASKS_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>

#define CF_TASK_STATE_CREATED		1
#define CF_TASK_STATE_RUNNING		2
#define CF_TASK_STATE_FINISHED      3
#define CF_TASK_STATE_ABORT         4

#define CF_MAX_TASK_THREADS         2

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef CF_NO_HTTP
    struct http_request;
#endif

struct cf_task
{
    uint8_t type;
    int	state;
    int	result;
    pthread_rwlock_t lock;

#ifndef CF_NO_HTTP
	struct http_request	*req;
#endif

    int	fds[2];
    int	(*entry)(struct cf_task *);
    void (*cb)(struct cf_task *);

    struct cf_task_thread *thread;

    TAILQ_ENTRY(cf_task) list;
    LIST_ENTRY(cf_task)	 rlist;
};

struct cf_task_thread
{
    uint8_t            idx;
    pthread_t           tid;
	pthread_mutex_t		lock;
	pthread_cond_t		cond;
    TAILQ_HEAD(, cf_task)	tasks;

    TAILQ_ENTRY(cf_task_thread)	list;
};

void cf_task_init(void);
void cf_task_run(struct cf_task*);
void cf_task_finish(struct cf_task*);
void cf_task_destroy(struct cf_task*);
int	cf_task_finished(struct cf_task*);
void cf_task_handle(struct cf_task*, int);

#ifndef CF_NO_HTTP
    void cf_task_bind_request(struct cf_task*, struct http_request*);
#endif

void cf_task_bind_callback(struct cf_task*, void (*cb)(struct cf_task*));
void cf_task_create(struct cf_task*, int (*entry)(struct cf_task*));

uint32_t cf_task_channel_read(struct cf_task*, void*, uint32_t);
void cf_task_channel_write(struct cf_task*, void*, uint32_t);
void cf_task_set_state(struct cf_task*,int);
void cf_task_set_result(struct cf_task*,int);
int cf_task_state(struct cf_task*);
int cf_task_result(struct cf_task*);


#if defined(__cplusplus)
}
#endif

#endif // __CF_TASKS_H__
