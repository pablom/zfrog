
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <fcntl.h>

#include <zfrog.h>
#include <cf_http.h>

#include "assets.h"

struct video {
	int			fd;
	int			ref;
    off_t		size;
    char		*path;
    uint8_t		*data;
    void		*base;

	TAILQ_ENTRY(video)	list;
};

int	init(int);
int	serve_page(struct http_request *);
int	video_stream(struct http_request *);

static void	video_unmap(struct video *);
static int	video_stream_finish(struct netbuf *);
static int	video_mmap(struct http_request *, struct video *);
static int	video_open(struct http_request *, struct video **);

TAILQ_HEAD(, video)		videos;

int init(int state)
{
    if( state == CF_MODULE_UNLOAD )
    {
        cf_log(LOG_NOTICE, "not reloading module");
        return CF_RESULT_ERROR;
	}

	TAILQ_INIT(&videos);
    return CF_RESULT_OK;
}

int serve_page(struct http_request *req)
{
	http_response_header(req, "content-type", "text/html");
    http_response_stream(req, 200, asset_video_html, asset_len_video_html, NULL, NULL);

    return CF_RESULT_OK;
}

int video_stream(struct http_request *req)
{
    struct video *v;
    off_t start, end;
    int	n, err, status;
    char *header, *bytes, *range[3], rb[128], *ext, ctype[32];

    if( !video_open(req, &v) )
        return CF_RESULT_OK;

    if( (ext = strrchr(req->path, '.')) == NULL )
    {
		v->ref--;
		http_response(req, 400, NULL, 0);
        return CF_RESULT_OK;
	}

    if( !cf_snprintf(ctype, sizeof(ctype), NULL, "video/%s", ext + 1) )
    {
		v->ref--;
		http_response(req, 500, NULL, 0);
        return CF_RESULT_OK;
	}

    cf_log(LOG_NOTICE, "%p: opened %s (%s) for streaming (%lld ref:%d)", (void *)req->owner, v->path, ctype, v->size, v->ref);

    if( http_request_header(req, "range", &header) )
    {
        if ((bytes = strchr(header, '=')) == NULL)
        {
			v->ref--;
			http_response(req, 416, NULL, 0);
            return CF_RESULT_OK;
		}

		bytes++;
        n = cf_split_string(bytes, "-", range, 2);
		if (n == 0) {
			v->ref--;
			http_response(req, 416, NULL, 0);
            return CF_RESULT_OK;
		}

        if( n >= 1 )
        {
            start = cf_strtonum64(range[0], 1, &err);
            if( err != CF_RESULT_OK )
            {
				v->ref--;
				http_response(req, 416, NULL, 0);
                return CF_RESULT_OK;
			}
		}

        if( n > 1 )
        {
            end = cf_strtonum64(range[1], 1, &err);
            if( err != CF_RESULT_OK )
            {
				v->ref--;
				http_response(req, 416, NULL, 0);
                return CF_RESULT_OK;
			}
        }
        else {
			end = 0;
		}

        if( end == 0 )
			end = v->size;

        if( start > end || start > v->size || end > v->size )
        {
			v->ref--;
			http_response(req, 416, NULL, 0);
            return CF_RESULT_OK;
		}

		status = 206;
        if( !cf_snprintf(rb, sizeof(rb), NULL, "bytes %ld-%ld/%ld", start, end - 1, v->size))
        {
			v->ref--;
			http_response(req, 500, NULL, 0);
            return CF_RESULT_OK;
		}

        cf_log(LOG_NOTICE, "%p: %s sending: %lld-%lld/%lld",(void *)req->owner, v->path, start, end - 1, v->size);
		http_response_header(req, "content-range", rb);
    }
    else
    {
		start = 0;
		status = 200;
		end = v->size;
	}

	http_response_header(req, "content-type", ctype);
	http_response_header(req, "accept-ranges", "bytes");
    http_response_stream(req, status, v->data + start, end - start, video_stream_finish, v);

    return CF_RESULT_OK;
}

static int video_open(struct http_request *req, struct video **out)
{
	struct stat		st;
	struct video		*v;
	char			fpath[MAXPATHLEN];

    if( !cf_snprintf(fpath, sizeof(fpath), NULL, "videos%s", req->path) )
    {
		http_response(req, 500, NULL, 0);
        return CF_RESULT_ERROR;
	}

    TAILQ_FOREACH(v, &videos, list)
    {
        if( !strcmp(v->path, fpath) )
        {
            if( video_mmap(req, v) )
            {
				*out = v;
                return CF_RESULT_OK;
			}

			close(v->fd);
			TAILQ_REMOVE(&videos, v, list);
            mem_free(v->path);
            mem_free(v);

			http_response(req, 500, NULL, 0);
            return CF_RESULT_ERROR;
		}
	}

    v = mem_malloc(sizeof(*v));
	v->ref = 0;
	v->base = NULL;
	v->data = NULL;
    v->path = cf_strdup(fpath);

    if( (v->fd = open(fpath, O_RDONLY)) == -1 )
    {
        mem_free(v->path);
        mem_free(v);

        if( errno == ENOENT )
			http_response(req, 404, NULL, 0);
		else
			http_response(req, 500, NULL, 0);

        return cf_RESULT_ERROR;
	}

    if( fstat(v->fd, &st) == -1 )
    {
		close(v->fd);
        mem_free(v->path);
        mem_free(v);

		http_response(req, 500, NULL, 0);
        return CF_RESULT_ERROR;
	}

	v->size = st.st_size;
    if( !video_mmap(req, v) )
    {
		close(v->fd);
        mem_free(v->path);
        mem_free(v);

		http_response(req, 500, NULL, 0);
        return CF_RESULT_ERROR;
	}

	*out = v;
	TAILQ_INSERT_TAIL(&videos, v, list);

    return CF_RESULT_OK;
}

static int video_mmap( struct http_request *req, struct video *v )
{
    if (v->base != NULL && v->data != NULL)
    {
		v->ref++;
        return CF_RESULT_OK;
	}

	v->base = mmap(NULL, v->size, PROT_READ, MAP_SHARED, v->fd, 0);
    if( v->base == MAP_FAILED )
        return CF_RESULT_ERROR;

	v->ref++;
	v->data = v->base;

    return CF_RESULT_OK;
}

static int video_stream_finish(struct netbuf *nb)
{
    struct video *v = nb->extra;

	v->ref--;
    cf_log(LOG_NOTICE, "%p: video stream %s done (%zu/%zu ref:%d)",(void *)nb->owner, v->path, nb->s_off, nb->b_len, v->ref);

    if( v->ref == 0 )
		video_unmap(v);

    return CF_RESULT_OK;
}

static void video_unmap( struct video *v )
{
    if( munmap(v->base, v->size) == -1 )
    {
        cf_log(LOG_ERR, "munmap(%s): %s", v->path, errno_s);
    }
    else
    {
		v->base = NULL;
		v->data = NULL;
        cf_log(LOG_NOTICE, "unmapped %s for streaming, no refs left", v->path);
	}
}
