// cf_timer.c

#include <sys/param.h>
#include <sys/queue.h>

#include "zfrog.h"

TAILQ_HEAD(timerlist, cf_timer)	cf_timers;

void cf_timer_init(void)
{
    TAILQ_INIT( &cf_timers );
}

struct cf_timer* cf_timer_add( void (*cb)(void *, uint64_t), uint64_t interval, void* arg, int flags)
{
    struct cf_timer	*timer, *t;

    timer = mem_malloc(sizeof(*timer));

	timer->cb = cb;
	timer->arg = arg;
	timer->flags = flags;
	timer->interval = interval;
	timer->nextrun = cf_time_ms() + timer->interval;

    TAILQ_FOREACH(t, &cf_timers, list)
    {
        if(t->nextrun > timer->nextrun)
        {
			TAILQ_INSERT_BEFORE(t, timer, list);
			return (timer);
		}
	}

    TAILQ_INSERT_TAIL(&cf_timers, timer, list);
    return timer;
}

void cf_timer_remove(struct cf_timer *timer)
{
    TAILQ_REMOVE(&cf_timers, timer, list);
    mem_free(timer);
}

uint64_t cf_timer_run( uint64_t now )
{
    struct cf_timer	*timer, *t;
    uint64_t next_timer = 100;

    while( (timer = TAILQ_FIRST(&cf_timers)) != NULL )
    {
        if( timer->nextrun > now ) {
			next_timer = timer->nextrun - now;
			break;
		}

        TAILQ_REMOVE(&cf_timers, timer, list);
		timer->cb(timer->arg, now);

        if( timer->flags & CF_TIMER_ONESHOT )
        {
            mem_free(timer);
        }
        else
        {
			timer->nextrun = now + timer->interval;
            TAILQ_FOREACH(t, &cf_timers, list)
            {
                if( t->nextrun > timer->nextrun )
                {
					TAILQ_INSERT_BEFORE(t, timer, list);
					break;
				}
			}

			if (t == NULL)
                TAILQ_INSERT_TAIL(&cf_timers, timer, list);
		}
	}

    if( next_timer > 1 )
		next_timer -= 1;

    return next_timer;
}
