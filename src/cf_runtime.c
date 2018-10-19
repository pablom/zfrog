// cf_runtime.c

#include <sys/param.h>

#include "zfrog.h"

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

static void	native_runtime_execute(void*);
static int	native_runtime_onload(void*, int);
static void	native_runtime_connect(void*, struct connection*);
static void	native_runtime_configure(void*, int, char**);

#ifndef CF_NO_HTTP
    static int native_runtime_http_request(void*, struct http_request*);
    static int native_runtime_validator(void*, struct http_request*, const void*);
    static void	native_runtime_wsmessage(void*, struct connection*, uint8_t, const void*, size_t);
#endif

struct cf_runtime cf_native_runtime =
{
    CF_RUNTIME_NATIVE,
#ifndef CF_NO_HTTP
	.http_request = native_runtime_http_request,
	.validator = native_runtime_validator,
    .wsconnect = native_runtime_connect,
    .wsmessage = native_runtime_wsmessage,
    .wsdisconnect = native_runtime_connect,
#endif
	.onload = native_runtime_onload,
    .connect = native_runtime_connect,
    .execute = native_runtime_execute,
    .configure = native_runtime_configure
};

struct cf_runtime_call * cf_runtime_getcall(const char *symbol)
{
    void *ptr = NULL;
    struct cf_runtime_call	*rcall = NULL;
    struct cf_runtime *runtime = NULL;

    if( (ptr = cf_module_getsym(symbol, &runtime)) == NULL )
        return NULL;

    rcall = mem_malloc( sizeof(*rcall) );
	rcall->addr = ptr;
	rcall->runtime = runtime;

    return rcall;
}

void cf_runtime_execute( struct cf_runtime_call* rcall )
{
    rcall->runtime->execute(rcall->addr);
}

void cf_runtime_configure( struct cf_runtime_call* rcall, int argc, char **argv )
{
    rcall->runtime->configure(rcall->addr, argc, argv);
}

int cf_runtime_onload( struct cf_runtime_call* rcall, int action )
{
	return (rcall->runtime->onload(rcall->addr, action));
}

void cf_runtime_connect( struct cf_runtime_call* rcall, struct connection* c )
{
	rcall->runtime->connect(rcall->addr, c);
}

#ifndef CF_NO_HTTP
int cf_runtime_http_request( struct cf_runtime_call* rcall, struct http_request* req )
{
	return (rcall->runtime->http_request(rcall->addr, req));
}

int cf_runtime_validator(struct cf_runtime_call *rcall, struct http_request *req, const void *data)
{
	return (rcall->runtime->validator(rcall->addr, req, data));
}

void cf_runtime_wsconnect( struct cf_runtime_call* rcall, struct connection* c )
{
    rcall->runtime->wsconnect(rcall->addr, c);
}

void cf_runtime_wsmessage( struct cf_runtime_call *rcall, struct connection *c,
                           uint8_t op, const void *data, size_t len )
{
    rcall->runtime->wsmessage(rcall->addr, c, op, data, len);
}

void cf_runtime_wsdisconnect( struct cf_runtime_call* rcall, struct connection* c )
{
    rcall->runtime->wsdisconnect(rcall->addr, c);
}
#endif

static void native_runtime_configure( void* addr, int argc, char** argv )
{
    void (*cb)(int, char **);

    *(void **)&(cb) = addr;
    cb(argc, argv);
}

static void native_runtime_execute(void *addr)
{
    void (*cb)(void);

    *(void **)&(cb) = addr;
    cb();
}

static void native_runtime_connect(void *addr, struct connection *c)
{
    void (*cb)(struct connection *);

	*(void **)&(cb) = addr;
	cb(c);
}

static int native_runtime_onload(void *addr, int action)
{
    int	(*cb)(int);

	*(void **)&(cb) = addr;
	return (cb(action));
}

#ifndef CF_NO_HTTP
static int native_runtime_http_request(void *addr, struct http_request *req)
{
    int	(*cb)(struct http_request *);

	*(void **)&(cb) = addr;
	return (cb(req));
}

static int native_runtime_validator(void *addr, struct http_request *req, const void *data)
{
    int	(*cb)(struct http_request*, const void*);

	*(void **)&(cb) = addr;
	return (cb(req, data));
}

static void native_runtime_wsmessage(void *addr, struct connection *c, uint8_t op, const void *data, size_t len)
{
    void (*cb)(struct connection *, uint8_t, const void *, size_t);

    *(void **)&(cb) = addr;
    cb(c, op, data, len);

}
#endif /* CF_NO_HTTP */
