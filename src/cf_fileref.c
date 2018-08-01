// cf_fileref.c

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#if !defined(__MACH__) && !defined(__linux__)
#include <sys/stdint.h>
#endif

#include "zfrog.h"

/* cached filerefs expire after 30 seconds of inactivity */
#define FILEREF_EXPIRATION		(1000 * 30)

static void	fileref_drop(struct cf_fileref*);
static void	fileref_soft_remove(struct cf_fileref*);
static void	fileref_expiration_check(void *, uint64_t);

static TAILQ_HEAD(, cf_fileref)	refs;
static struct cf_mem_pool       ref_pool;

void cf_fileref_init(void)
{
	TAILQ_INIT(&refs);
    cf_mem_pool_init(&ref_pool, "ref_pool", sizeof(struct cf_fileref), 100);
    cf_timer_add(fileref_expiration_check, 10000, NULL, 0);
}

struct cf_fileref* cf_fileref_create( const char* path, int fd, off_t size, struct timespec* ts )
{
    struct cf_fileref* ref = NULL;

    if( (ref = cf_fileref_get(path)) != NULL )
        return ref;

    ref = cf_mem_pool_get(&ref_pool);

	ref->cnt = 1;
	ref->flags = 0;
	ref->size = size;
    ref->path = mem_strdup(path);
    ref->mtime_sec = ts->tv_sec;
    ref->mtime = ((uint64_t)(ts->tv_sec * 1000 + (ts->tv_nsec / 1000000)));

#ifdef CF_NO_SENDFILE
    if( (uintmax_t)size> SIZE_MAX )
    {
        mem_pool_put(&ref_pool, ref);
        return NULL;
    }

	ref->base = mmap(NULL, (size_t)size, PROT_READ, MAP_PRIVATE, fd, 0);
    if( ref->base == MAP_FAILED )
        cf_fatal("net_send_file: mmap failed: %s", errno_s);
    if( madvise(ref->base, (size_t)size, MADV_SEQUENTIAL) == -1 ) {
        cf_fatal("net_send_file: madvise: %s", errno_s);
    }
	close(fd);
#else
	ref->fd = fd;
#endif

	TAILQ_INSERT_TAIL(&refs, ref, list);

    return ref;
}
/*
 * Caller must call cf_fileref_release() after cf_fileref_get() even
 * if they don't end up using the ref.
 */
struct cf_fileref* cf_fileref_get( const char* path )
{
	struct stat		st;
    struct cf_fileref* ref = NULL;
    uint64_t		mtime;

    TAILQ_FOREACH(ref, &refs, list)
    {
        if( !strcmp(ref->path, path) )
        {
            if( stat(ref->path, &st) == -1 )
            {
                if( errno != ENOENT )
                    cf_log(LOG_ERR, "stat(%s): %s",ref->path, errno_s);

				fileref_soft_remove(ref);
                return NULL;
			}

            mtime = ((uint64_t)(st.st_mtim.tv_sec * 1000 + (st.st_mtim.tv_nsec / 1000000)));

            if( ref->mtime != mtime )
            {
				fileref_soft_remove(ref);
                return NULL;
			}

			ref->cnt++;

			TAILQ_REMOVE(&refs, ref, list);
			TAILQ_INSERT_HEAD(&refs, ref, list);
            return ref;
		}
	}

    return NULL;
}

void cf_fileref_release(struct cf_fileref* ref)
{
	ref->cnt--;

    if( ref->cnt < 0 )
    {
        cf_fatal("cf_fileref_release: cnt < 0 (%p:%d)",(void *)ref, ref->cnt);
	}

    if( ref->cnt == 0 )
    {
        if( ref->flags & CF_FILEREF_SOFT_REMOVED )
			fileref_drop(ref);
		else
            ref->expiration = cf_time_ms() + FILEREF_EXPIRATION;
	}
}

static void fileref_soft_remove( struct cf_fileref* ref )
{
    if( ref->flags & CF_FILEREF_SOFT_REMOVED )
        cf_fatal("fileref_soft_remove: %p already removed", (void *)ref);

	TAILQ_REMOVE(&refs, ref, list);
    ref->flags |= CF_FILEREF_SOFT_REMOVED;

    if( ref->cnt == 0 )
		fileref_drop(ref);
}

static void fileref_expiration_check(void *arg, uint64_t now)
{
    struct cf_fileref	*ref, *next;

    for( ref = TAILQ_FIRST(&refs); ref != NULL; ref = next )
    {
		next = TAILQ_NEXT(ref, list);

        if( ref->cnt != 0 )
			continue;

        if( ref->expiration > now )
			continue;

		fileref_drop(ref);
	}
}

static void fileref_drop(struct cf_fileref* ref)
{
    if( !(ref->flags & CF_FILEREF_SOFT_REMOVED) )
		TAILQ_REMOVE(&refs, ref, list);

    mem_free( ref->path );

#ifdef CF_NO_SENDFILE
    munmap(ref->base, ref->size);
#else
	close(ref->fd);
#endif
    cf_mem_pool_put(&ref_pool, ref);
}
