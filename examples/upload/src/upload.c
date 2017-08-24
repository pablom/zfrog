// upload.c

#include <zfrog.h>
#include <cf_http.h>

#include <fcntl.h>
#include <unistd.h>

int	page(struct http_request *);

int page(struct http_request *req)
{
	int			fd;
	struct http_file	*file;
	uint8_t		buf[BUFSIZ];
	ssize_t			ret, written;

	/* Only deal with POSTs */
	if( req->method != HTTP_METHOD_POST ) 
	{
		http_response(req, 405, NULL, 0);
		return CF_RESULT_OK;
	}

	/* Parse the multipart data that was present */
	http_populate_multipart_form(req);

	/* Find our file */
	if( (file = http_file_lookup(req, "file")) == NULL )
	{
		http_response(req, 400, NULL, 0);
		return CF_RESULT_OK;
	}

	/* Open dump file where we will write file contents */
	fd = open(file->filename, O_CREAT | O_TRUNC | O_WRONLY, 0700);
	if( fd == -1 ) 
	{
		http_response(req, 500, NULL, 0);
		return CF_RESULT_OK;
	}

	/* While we have data from http_file_read(), write it. */
	/* Alternatively you could look at file->offset and file->length */
	ret = CF_RESULT_ERROR;
	for(;;) 
	{
		ret = http_file_read(file, buf, sizeof(buf));
		if( ret == -1 ) 
		{
			cf_log(LOG_ERR, "failed to read from file");
			http_response(req, 500, NULL, 0);
			goto cleanup;
		}

		if (ret == 0)
			break;

		written = write(fd, buf, ret);
		if( written == -1 ) 
		{
			cf_log(LOG_ERR,"write(%s): %s", file->filename, errno_s);
			http_response(req, 500, NULL, 0);
			goto cleanup;
		}

		if (written != ret) 
		{
			cf_log(LOG_ERR, "partial write on %s", file->filename);
			http_response(req, 500, NULL, 0);
			goto cleanup;
		}
	}

	ret = CF_RESULT_OK;
	http_response(req, 200, NULL, 0);
	cf_log(LOG_INFO, "file '%s' successfully received", file->filename);

cleanup:
	if( close(fd) == -1 )
		cf_log(LOG_WARNING, "close(%s): %s", file->filename, errno_s);

	if( ret == CF_RESULT_ERROR ) 
	{
		if( unlink(file->filename) == -1 ) 
		{
			cf_log(LOG_WARNING, "unlink(%s): %s", file->filename, errno_s);
		}
		ret = CF_RESULT_OK;
	}

	return CF_RESULT_OK;
}
