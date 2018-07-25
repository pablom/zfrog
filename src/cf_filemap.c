// cf_filemap.c

#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>

#include "zfrog.h"
#include "cf_http.h"

struct filemap_entry
{
	char				*root;
	size_t				root_len;
    struct cf_domain	*domain;
	char				*ondisk;
    size_t				ondisk_len;
	TAILQ_ENTRY(filemap_entry)	list;
};

int	filemap_resolve(struct http_request*);
static void	filemap_serve(struct http_request*, struct filemap_entry*);

static TAILQ_HEAD(, filemap_entry)	maps;


void cf_filemap_init(void)
{
	TAILQ_INIT(&maps);
}

int cf_filemap_create( struct cf_domain* dom, const char* path, const char* root )
{
    size_t sz = 0;
    int	len = 0;
    struct stat	st;
    struct cf_module_handle* hdlr = NULL;
    struct filemap_entry* entry = NULL;
    char regex[1024];
    char fpath[PATH_MAX];

    if( (sz = strlen(root)) == 0 )
        return CF_RESULT_ERROR;

    if( root[0] != '/' || root[sz - 1] != '/' ) {
        return CF_RESULT_ERROR;
    }

    if( server.root_path != NULL )
    {
        len = snprintf(fpath, sizeof(fpath), "%s/%s", server.root_path, path);
        if( len == -1 || (size_t)len >= sizeof(fpath) )
            cf_fatal("cf_filemap_create: failed to concat paths");
    }
    else
    {
        if( cf_strlcpy(fpath, path, sizeof(fpath)) >= sizeof(fpath) )
            cf_fatal("cf_filemap_create: failed to copy path");
    }

    if( stat(fpath, &st) == -1 ) {
        return CF_RESULT_ERROR;
    }

	len = snprintf(regex, sizeof(regex), "^%s.*$", root);
    if( len == -1 || (size_t)len >= sizeof(regex) )
        cf_fatal("cf_filemap_create: buffer too small");

    if( !cf_module_handler_new(regex, dom->domain,"filemap_resolve", NULL, HANDLER_TYPE_DYNAMIC) )
        return CF_RESULT_ERROR;

    TAILQ_FOREACH(hdlr, &dom->handlers, list)
    {
        if( !strcmp(hdlr->path, regex) )
            break;
    }

    if( hdlr == NULL )
        cf_fatal("couldn't find newly created handler for filemap");

    /* Allow HTTP methods */
    hdlr->methods = HTTP_METHOD_GET | HTTP_METHOD_HEAD;

    entry = mem_calloc(1, sizeof(*entry));

	entry->domain = dom;
	entry->root_len = sz;
    entry->root = mem_strdup(root);
    /*
     * Resolve the ondisk component inside the workers to make sure
     * realpath() resolves the correct path (they maybe chrooted).
     */
    entry->ondisk_len = strlen(path);
    entry->ondisk = mem_strdup(path);

	TAILQ_INSERT_TAIL(&maps, entry, list);

    return CF_RESULT_OK;
}

void cf_filemap_resolve_paths( void )
{
    struct filemap_entry* entry = NULL;
    char rpath[PATH_MAX];

    TAILQ_FOREACH(entry, &maps, list)
    {
        if( realpath(entry->ondisk, rpath) == NULL )
            cf_fatal("realpath(%s): %s", entry->ondisk, errno_s);

        mem_free(entry->ondisk);
        entry->ondisk_len = strlen(rpath);
        entry->ondisk = mem_strdup(rpath);
    }
}

int filemap_resolve( struct http_request* req )
{
    size_t best_len;
	struct filemap_entry	*entry, *best;

    if( req->method != HTTP_METHOD_GET && req->method != HTTP_METHOD_HEAD )
    {
		http_response_header(req, "allow", "get, head");
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
        return CF_RESULT_OK;
	}

	best = NULL;
	best_len = 0;

    TAILQ_FOREACH(entry, &maps, list)
    {
        if( entry->domain != req->hdlr->dom )
            continue;

        if( !strncmp(entry->root, req->path, entry->root_len) )
        {
            if( best == NULL || entry->root_len > best_len )
            {
				best = entry;
				best_len = entry->root_len;
				continue;
			}
		}
	}

    if( best == NULL )
    {
		http_response(req, HTTP_STATUS_NOT_FOUND, NULL, 0);
        return CF_RESULT_OK;
	}

	filemap_serve(req, best);

    return CF_RESULT_OK;
}

static void filemap_serve( struct http_request* req, struct filemap_entry* map )
{
    struct stat	st;
    struct cf_fileref* ref = NULL;
    const char* path = NULL;
    int	len, fd, index;
    char fpath[MAXPATHLEN];

    path = req->path + map->root_len;

    len = snprintf(fpath, sizeof(fpath), "%s/%s", map->ondisk, path);

    if( len == -1 || (size_t)len >= sizeof(fpath) )
    {
		http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
		return;
	}

    if( !http_argument_urldecode(fpath) )
    {
		http_response(req, HTTP_STATUS_BAD_REQUEST, NULL, 0);
		return;
	}

    if( strstr(fpath, "..") )
    {
		http_response(req, HTTP_STATUS_NOT_FOUND, NULL, 0);
		return;
	}

	index = 0;

lookup:
    if( (ref = cf_fileref_get(fpath)) == NULL )
    {
        if( (fd = open(fpath, O_RDONLY | O_NOFOLLOW)) == -1 )
        {
            switch( errno )
            {
			case ENOENT:
                if( index || server.filemap_ext == NULL )
                {
                    req->status = HTTP_STATUS_NOT_FOUND;
                }
                else
                {
                    len = snprintf(fpath, sizeof(fpath),"%s/%s%s", map->ondisk, path, server.filemap_ext);
                    if( len == -1 || (size_t)len >= sizeof(fpath) )
                    {
                        http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
                        return;
                    }
                    index++;
                    goto lookup;
                }
				break;
			case EPERM:
			case EACCES:
				req->status = HTTP_STATUS_FORBIDDEN;
				break;
			default:
				req->status = HTTP_STATUS_INTERNAL_ERROR;
				break;
			}

			http_response(req, req->status, NULL, 0);
			return;
		}

        if( fstat(fd, &st) == -1 )
        {
			http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
			goto cleanup;
		}

        if( S_ISREG(st.st_mode) )
        {
            if( st.st_size <= 0 )
            {
                http_response(req, HTTP_STATUS_NOT_FOUND, NULL, 0);
				goto cleanup;
			}

            /* cf_fileref_create() takes ownership of the fd */
            ref = cf_fileref_create(fpath, fd,st.st_size, &st.st_mtim);
            if( ref == NULL )
				http_response(req,HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
            else
				fd = -1;
        }
        else if( S_ISDIR(st.st_mode) && index == 0 )
        {
            len = snprintf(fpath, sizeof(fpath), "%s/%s%s", map->ondisk, path, server.filemap_index != NULL ? server.filemap_index : "index.html");
            if( len == -1 || (size_t)len >= sizeof(fpath) )
            {
                http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
                return;
            }

			index++;
			goto lookup;
        }
        else
        {
			http_response(req, HTTP_STATUS_NOT_FOUND, NULL, 0);
		}
	}

    if( ref != NULL )
    {
		http_response_fileref(req, HTTP_STATUS_OK, ref);
		fd = -1;
	}

cleanup:
	if (fd != -1)
		close(fd);
}


