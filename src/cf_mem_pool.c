// cf_mem_pool.c

#include <sys/mman.h>
#include <sys/queue.h>
#include <stdint.h>

#include "zfrog.h"

#define POOL_ELEMENT_BUSY		0
#define POOL_ELEMENT_FREE		1

#ifdef CF_TASKS
    static void	pool_lock( struct cf_mem_pool *pool );
    static void	pool_unlock( struct cf_mem_pool *pool );
#endif

static void	pool_region_create(struct cf_mem_pool *pool, size_t elms);
static void	pool_region_destroy( struct cf_mem_pool *pool );

/****************************************************************
 *  Helper function init memory pool
 ****************************************************************/
void cf_mem_pool_init(struct cf_mem_pool *pool, const char *name, size_t len, size_t elm)
{
    log_debug("cf_mem_pool_init(%p, %s, %zu, %zu)", pool, name, len, elm);

    if( (pool->name = strdup(name)) == NULL ) {
        cf_fatal("cf_mem_pool_init: strdup %s", errno_s);
    }

	pool->lock = 0;
	pool->elms = 0;
	pool->inuse = 0;
	pool->elen = len;
    pool->slen = pool->elen + sizeof(struct cf_mem_pool_entry);

	LIST_INIT(&(pool->regions));
	LIST_INIT(&(pool->freelist));

	pool_region_create(pool, elm);
}
/****************************************************************
 *  Helper function to clean up memory pool
 ****************************************************************/
void cf_mem_pool_cleanup(struct cf_mem_pool *pool)
{
	pool->lock = 0;
	pool->elms = 0;
	pool->inuse = 0;
	pool->elen = 0;
	pool->slen = 0;

    if( pool->name != NULL )
    {
        free( pool->name );
		pool->name = NULL;
	}

	pool_region_destroy(pool);
}
/****************************************************************
 *  Helper function to get memory free chunck from memory pool
 ****************************************************************/
void* cf_mem_pool_get( struct cf_mem_pool *pool )
{
    uint8_t *ptr = NULL;
    struct cf_mem_pool_entry *entry = NULL;

#ifdef CF_TASKS
    pool_lock( pool );
#endif

    if( LIST_EMPTY(&(pool->freelist)) )
    {
        cf_log(LOG_NOTICE, "pool %s is exhausted (%zu/%zu)", pool->name, pool->inuse, pool->elms);
		pool_region_create(pool, pool->elms);
	}

	entry = LIST_FIRST(&(pool->freelist));
    if( entry->state != POOL_ELEMENT_FREE )
        cf_fatal("%s: element %p was not free", pool->name, entry);
	LIST_REMOVE(entry, list);

	entry->state = POOL_ELEMENT_BUSY;
    ptr = (uint8_t *)entry + sizeof(struct cf_mem_pool_entry);

	pool->inuse++;

#ifdef CF_TASKS
	pool_unlock(pool);
#endif

    return ptr;
}
/****************************************************************
 *  Helper function to return memory chunck back to memory pool
 ****************************************************************/
void cf_mem_pool_put( struct cf_mem_pool *pool, void *ptr )
{
    struct cf_mem_pool_entry *entry = NULL;

#ifdef CF_TASKS
	pool_lock(pool);
#endif

    entry = (struct cf_mem_pool_entry *) ((uint8_t *)ptr - sizeof(struct cf_mem_pool_entry));

    if( entry->state != POOL_ELEMENT_BUSY ) {
        cf_fatal("%s: element %p was not busy", pool->name, ptr);
    }

	entry->state = POOL_ELEMENT_FREE;
	LIST_INSERT_HEAD(&(pool->freelist), entry, list);

	pool->inuse--;

#ifdef CF_TASKS
	pool_unlock(pool);
#endif
}
/****************************************************************
 *  Helper function to create memory region
 ****************************************************************/
static void pool_region_create(struct cf_mem_pool *pool, size_t elms)
{
    size_t i;
    void *p = NULL;
    struct cf_mem_pool_region *reg = NULL;
    struct cf_mem_pool_entry *entry = NULL;

    log_debug("pool_region_create(%p, %d)", pool, elms);

    if( (reg = calloc(1, sizeof(struct cf_mem_pool_region))) == NULL )
        cf_fatal("pool_region_create: calloc: %s", errno_s);

	LIST_INSERT_HEAD(&(pool->regions), reg, list);

    if( SIZE_MAX / elms < pool->slen ) {
        cf_fatal("pool_region_create: overflow");
    }

	reg->length = elms * pool->slen;
    reg->start = mmap(NULL, reg->length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    if( reg->start == MAP_FAILED ) {
        cf_fatal("mmap: %s", errno_s);
    }

    p = (uint8_t *)reg->start;

    for( i = 0; i < elms; i++ )
    {
        entry = (struct cf_mem_pool_entry *)p;
		entry->region = reg;
		entry->state = POOL_ELEMENT_FREE;
		LIST_INSERT_HEAD(&(pool->freelist), entry, list);

        p = ((uint8_t *)p + pool->slen);
	}

	pool->elms += elms;
}
/****************************************************************
 *  Helper function to delete memory region
 ****************************************************************/
static void pool_region_destroy( struct cf_mem_pool *pool )
{
    struct cf_mem_pool_region *reg = NULL;

    log_debug("pool_region_destroy(%p)", pool);

	/* Take care iterating when modifying list contents */
    while( !LIST_EMPTY(&pool->regions) )
    {
		reg = LIST_FIRST(&pool->regions);
		LIST_REMOVE(reg, list);
        munmap( reg->start, reg->length );
		free(reg);
	}

	/* Freelist references into the regions memory allocations */
	LIST_INIT(&pool->freelist);
	pool->elms = 0;
}

#ifdef CF_TASKS
static void pool_lock( struct cf_mem_pool *pool )
{
    for(;;)
    {
		if (__sync_bool_compare_and_swap(&pool->lock, 0, 1))
			break;
    }
}

static void pool_unlock(struct cf_mem_pool *pool)
{
    if( !__sync_bool_compare_and_swap(&pool->lock, 1, 0) )
        cf_fatal("pool_unlock: failed to release %s", pool->name);
}
#endif
