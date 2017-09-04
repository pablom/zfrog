// memtag.c

#include <zfrog.h>
#include <cf_http.h>

/*
 * This example demonstrates how dynamically reloadable modules
 * can use the memory tagging system in zFrog in order to restore
 * the global pointers in the module
 */

/* Some unique value */
#define MEM_TAG_HELLO		100

int		init(int);
int		page(struct http_request *);

/* Global pointer, gets initialized to NULL when module loads/reloads */
char *fixed_ptr = NULL;

int init( int state )
{
    /* Ignore unload(s) */
    if( state == CF_MODULE_UNLOAD)
        return CF_RESULT_OK;

	printf("fixed_ptr: %p\n", (void *)fixed_ptr);

	/* Attempt to lookup the original pointer. */
    if( (fixed_ptr = mem_lookup(MEM_TAG_HELLO)) == NULL )
    {
        /* Failed, grab a new chunk of memory and tag it */
		printf("  allocating fixed_ptr for the first time\n");
        fixed_ptr = mem_malloc_tagged(6, MEM_TAG_HELLO);
        cf_strlcpy(fixed_ptr, "hello", 6);
    }
    else
    {
		printf("  fixed_ptr address resolved\n");
	}

	printf("  fixed_ptr: %p\n", (void *)fixed_ptr);
	printf("  value    : %s\n", fixed_ptr);

    return CF_RESULT_OK;
}

int page(struct http_request *req)
{
	http_response(req, 200, fixed_ptr, strlen(fixed_ptr));
    return CF_RESULT_OK;
}
