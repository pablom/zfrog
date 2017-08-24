// cf_cstl_memory.c


#include "zfrog.h"
#include "cf_cstl_memory.h"


void * __c_malloc( size_t s )
{
    return (void *)(mem_malloc(s));
}

void __c_free( void * p )
{
    mem_free( p );
}





