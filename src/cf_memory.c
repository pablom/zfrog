// cf_memory.c

#include <sys/param.h>

#include <stdlib.h>
#include <stdint.h>

#include "zfrog.h"

#define MALLOC_MEM_BLOCKS               11
#define MALLOC_MEM_BLOCK_SIZE_MAX       8192
#define MALLOC_MEM_BLOCK_PREALLOC		128

#define MALLOC_MEM_ALIGN		(sizeof(size_t))
#define MALLOC_MEM_MAGIC		0xd0d0
#define MALLOC_MEMSIZE(x)		\
    (*(size_t *)((uint8_t *)x - sizeof(size_t)))

#define MALLOC_MEMINFO(x)		\
    (struct meminfo *)((uint8_t *)x + MALLOC_MEMSIZE(x))


struct meminfo {
    uint16_t magic;
};

struct memblock {
    struct cf_mem_pool	pool;
};

/* Forward function declaration */
static size_t memblock_index(size_t);

static struct memblock blocks[MALLOC_MEM_BLOCKS];


/************************************************************************
 *  Helper function memory pool init
 ************************************************************************/
void mem_init()
{
    int	i, len;
    char name[32];
    uint32_t size, elm, mlen;

	size = 8;

    for( i = 0; i < MALLOC_MEM_BLOCKS; i++ )
    {
		len = snprintf(name, sizeof(name), "block-%u", size);
        if( len == -1 || (size_t)len >= sizeof(name) )
            cf_fatal("mem_init: snprintf");

        elm = (MALLOC_MEM_BLOCK_PREALLOC * 1024) / size;
        mlen = sizeof(size_t) + size + sizeof(struct meminfo) + MALLOC_MEM_ALIGN;
        mlen = mlen & ~(MALLOC_MEM_ALIGN - 1);

        cf_mem_pool_init(&blocks[i].pool, name, mlen, elm);

		size = size << 1;
	}
}
/************************************************************************
 *  Helper function memory pools cleanup
 ************************************************************************/
void mem_cleanup(void)
{
    int i;

    for( i = 0; i < MALLOC_MEM_BLOCKS; i++) {
        cf_mem_pool_cleanup( &blocks[i].pool );
    }
}
/************************************************************************
 *  Helper function memory allocate
 ************************************************************************/
void* mem_malloc( size_t len )
{
    void *ptr = NULL;
    struct meminfo* mem = NULL;
    uint8_t *addr = NULL;
    size_t	mlen, idx, *plen;

    if( len == 0 ) {
        //cf_fatal("mem_malloc(): zero size");
        len = 8;
    }

#if defined(__sun)
    if( len % 2 ) len += 1;
#endif

    if( len <= MALLOC_MEM_BLOCK_SIZE_MAX )
    {
		idx = memblock_index(len);
        ptr = cf_mem_pool_get( &blocks[idx].pool );
    }
    else
    {
		mlen = sizeof(size_t) + len + sizeof(struct meminfo);

        if( (ptr = calloc(1, mlen)) == NULL )
            cf_fatal("mem_malloc(%zd): %d", len, errno);
	}

	plen = (size_t *)ptr;
	*plen = len;
    addr = (uint8_t *)ptr + sizeof(size_t);

    mem = MALLOC_MEMINFO(addr);
    mem->magic = MALLOC_MEM_MAGIC;

    return addr;
}
/************************************************************************
 *  Helper function memory reallocate
 ************************************************************************/
void* mem_realloc( void *ptr, size_t len )
{
    struct meminfo *mem = NULL;
    void *nptr = NULL;

    if( len == 0 )
        cf_fatal("mem_realloc(): zero size");

    if( ptr == NULL )
    {
        nptr = mem_malloc(len);
    }
    else
    {
        mem = MALLOC_MEMINFO(ptr);
        if( mem->magic != MALLOC_MEM_MAGIC )
            cf_fatal("mem_realloc(): magic boundary not found");

        nptr = mem_malloc(len);
        memcpy(nptr, ptr, MIN(len, MALLOC_MEMSIZE(ptr)));
        mem_free(ptr);
	}

    return nptr;
}
/************************************************************************
 *  Helper function memory allocate
 ************************************************************************/
void* mem_calloc( size_t memb, size_t len )
{
    if( memb == 0 || len == 0 )
        cf_fatal("mem_calloc(): zero size");

    if( SIZE_MAX / memb < len )
        cf_fatal("mem_calloc(): memb * len > SIZE_MAX");

    return mem_malloc(memb * len);
}
/************************************************************************
 *  Helper function memory deallocate (free)
 ************************************************************************/
void mem_free( void *ptr )
{
    uint8_t *addr = NULL;
    struct meminfo	*mem = NULL;
    size_t len, idx;

    if( ptr == NULL )
		return;

    mem = MALLOC_MEMINFO(ptr);
    if( mem->magic != MALLOC_MEM_MAGIC ) {
        cf_fatal("mem_free(): magic boundary not found");
    }

    len = MALLOC_MEMSIZE(ptr);
    addr = (uint8_t *)ptr - sizeof(size_t);

    if( len <= MALLOC_MEM_BLOCK_SIZE_MAX )
    {
		idx = memblock_index(len);
        cf_mem_pool_put(&blocks[idx].pool, addr);
    }
    else {
		free(addr);
	}
}
/************************************************************************
 *  Helper function duplicate string
 ************************************************************************/
char* mem_strdup( const char *str )
{
    size_t len = 0;
    char *nstr = NULL;

    if( str == NULL ) {
        return NULL;
    }

	len = strlen(str) + 1;
    nstr = mem_malloc(len);    
    cf_strlcpy(nstr, str, len);

    return nstr;
}
/************************************************************************
 *  Helper function to get memory block index
 ************************************************************************/
static size_t memblock_index( size_t len )
{
    size_t mlen = 8;
    size_t idx = 0;

    while( mlen < len )
    {
		idx++;
		mlen = mlen << 1;
	}

    if( idx > (MALLOC_MEM_BLOCKS - 1) )
        cf_fatal("mem_malloc: idx too high");

    return idx;
}
