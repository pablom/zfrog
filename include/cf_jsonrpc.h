// cf_jsonrpc.h

#ifndef __CF_JSONRPC_H__
#define __CF_JSONRPC_H__

#if defined(__cplusplus)
extern "C" {
#endif

/* JSON RPC request handling log entry */
struct jsonrpc_log
{
    char *msg;
	struct jsonrpc_log	*next, *prev;
    int	lvl;
};

/* JSON RPC request */
struct jsonrpc_request
{
	struct jsonrpc_log	log;
	struct cf_buf		buf;
	struct http_request	*http;
    yajl_gen            gen;
    yajl_val            json;
    yajl_val            id;
    char                *method;
    yajl_val            params;
	unsigned int		flags;
    int                 log_levels;
};

#define YAJL_GEN_CONST_STRING(CTX, STR)	\
	yajl_gen_string((CTX), (unsigned char *)(STR), sizeof (STR) - 1)

#define YAJL_GEN_CONST_NUMBER(CTX, STR)	\
	yajl_gen_number((CTX), (unsigned char *)(STR), sizeof (STR) - 1)

#define YAJL_GEN_KO(OPERATION)	\
	((OPERATION) != yajl_gen_status_ok)

enum jsonrpc_error_code
{
#define JSONRPC_PARSE_ERROR_MSG		"Parse error"
	JSONRPC_PARSE_ERROR		= -32700,
#define JSONRPC_INVALID_REQUEST_MSG	"Invalid Request"
	JSONRPC_INVALID_REQUEST		= -32600,
#define JSONRPC_METHOD_NOT_FOUND_MSG	"Method not found"
	JSONRPC_METHOD_NOT_FOUND	= -32601,
#define JSONRPC_INVALID_PARAMS_MSG	"Invalid params"
	JSONRPC_INVALID_PARAMS		= -32602,
#define JSONRPC_INTERNAL_ERROR_MSG	"Internal error"
	JSONRPC_INTERNAL_ERROR		= -32603,
#define JSONRPC_SERVER_ERROR_MSG	"Server error"
	JSONRPC_SERVER_ERROR		= -32000,
#define JSONRPC_LIMIT_REACHED_MSG	"Limit reached"
	JSONRPC_LIMIT_REACHED		= -31997
};

void jsonrpc_log(struct jsonrpc_request*, int, const char*, ...);
int	 jsonrpc_read_request(struct http_request*, struct jsonrpc_request*);
void jsonrpc_destroy_request(struct jsonrpc_request*);
int	 jsonrpc_error(struct jsonrpc_request*, int, const char*);
int	 jsonrpc_result(struct jsonrpc_request*, int (*)(struct jsonrpc_request *, void *), void*);

#if defined(__cplusplus)
}

#endif

#endif /* __CF_JSONRPC_H__ */
