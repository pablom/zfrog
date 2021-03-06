// cpp.cpp

#include <zfrog.h>
#include <cf_http.h>

#include "example_class.h"

extern "C" {
	int		page(struct http_request *);
}

int page( struct http_request *req )
{
	example_class	example;
	const char	*str = example.a();

    http_response(req, 200, static_cast<void*>(const_cast<char*>(str)), strlen(str));

    return CF_RESULT_OK;
}
