// zfrog.h

#ifndef __ZFROG_H__
#define __ZFROG_H__

#if defined( __APPLE__ )
    #include "cfos/darwin.h"
#endif /* __APPLE__ */

#if defined( __sun )
    #include "cfos/sunos.h"
#endif /* __sun */


#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef CF_NO_TLS
    #include <openssl/err.h>
    #include <openssl/dh.h>
    #include <openssl/ssl.h>
#endif

#include <errno.h>
#include <regex.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

//#define __CONNECTION_PACKED __attribute__ ((__packed__))
#define __CONNECTION_PACKED

#if defined(__cplusplus)
extern "C" {
#endif


#if defined(__APPLE__) || defined(__sun)
    #undef daemon
    extern int daemon(int, int);
#endif

#define CF_VERSION_MAJOR        0
#define CF_VERSION_MINOR        0
#define CF_VERSION_PATCH        1
#define CF_VERSION_STATE        "devel"


#define CF_RESULT_ERROR         0
#define CF_RESULT_OK            1
#define CF_RESULT_RETRY         2

#define CF_TLS_VERSION_1_3      0
#define CF_TLS_VERSION_1_2      1
#define CF_TLS_VERSION_1_1      2
#define CF_TLS_VERSION_1_0      3
#define CF_TLS_VERSION_BOTH     4

#define CF_RESEED_TIME	(1800 * 1000)

#define errno_s			strerror(errno)
#define ssl_errno_s		ERR_error_string(ERR_get_error(), NULL)

#define CF_DOMAINNAME_LEN		256
#define CF_PIDFILE_DEFAULT		"zfrog.pid"
#define CF_DEFAULT_CIPHER_LIST	"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!kRSA:!kDSA"

#if defined(CF_DEBUG)
#define log_debug(...)		\
    if( server.debug_log )		\
        log_debug_internal(__FILE__, __LINE__, __VA_ARGS__)
#else
#define log_debug(...)
#endif

#define NETBUF_RECV                 0
#define NETBUF_SEND                 1
#define NETBUF_SEND_PAYLOAD_MAX		8192
#define SENDFILE_PAYLOAD_MAX		(1024 * 1024 * 10)

#define NETBUF_LAST_CHAIN           0
#define NETBUF_BEFORE_CHAIN         1

#define NETBUF_CALL_CB_ALWAYS       0x01
#define NETBUF_FORCE_REMOVE         0x02
#define NETBUF_MUST_RESEND          0x04
#define NETBUF_IS_STREAM            0x10
#define NETBUF_IS_FILEREF           0x20

#define X509_GET_CN(c, o, l)					\
	X509_NAME_get_text_by_NID(X509_get_subject_name(c),	\
	    NID_commonName, o, l)

#define X509_CN_LENGTH		(ub_common_name + 1)

/* Forward structure declaration */
#ifndef CF_NO_HTTP
    struct http_request;
#endif

#define CF_FILEREF_SOFT_REMOVED     0x1000

struct cf_fileref
{
    int			cnt;
    int			flags;
    off_t		size;
    char		*path;
    uint64_t	mtime;
    time_t		mtime_sec;
    uint64_t	expiration;
#ifndef CF_NO_SENDFILE
    int         fd;
#else
    void*       base;
#endif

    TAILQ_ENTRY(cf_fileref)	list;
};

struct netbuf
{
    uint8_t	 *buf;
    size_t	 s_off;
    size_t	 b_len;
    size_t	 m_len;
    uint8_t	 type;
    uint8_t	 flags;

    struct cf_fileref	*file_ref;

#ifndef CF_NO_SENDFILE
    off_t	fd_off;
    off_t	fd_len;
#endif

    void	 *owner;
    void	 *extra;

    int		 (*cb)(struct netbuf *);

	TAILQ_ENTRY(netbuf)	list;
};

TAILQ_HEAD(netbuf_head, netbuf);

/* Connection type definition */
#define CF_TYPE_CONNECTION          1
#define CF_TYPE_LISTENER            2
#define CF_TYPE_CLIENT              3
#define CF_TYPE_BACKEND             4
#define CF_TYPE_TASK                5
#define CF_TYPE_PYSOCKET            6
#define CF_TYPE_PGSQL_CONN          7
#define CF_TYPE_REDIS               8

/* Connection state definition */
#define CONN_STATE_UNKNOWN          0
#define CONN_STATE_TLS_SHAKE	    1
#define CONN_STATE_ESTABLISHED		2
#define CONN_STATE_CONNECTING       3
#define CONN_STATE_DISCONNECTING	4
#define CONN_STATE_ERROR            5

/* Connection protocol definition */
#define CONN_PROTO_UNKNOWN          0
#define CONN_PROTO_HTTP             1
#define CONN_PROTO_WEBSOCKET        2
#define CONN_PROTO_MSG              3
#define CONN_PROTO_REDIS            4

#define CF_EVENT_READ               0x01
#define CF_EVENT_WRITE              0x02
#define CF_EVENT_ERROR              0x04


#define CONN_WRITE_BLOCK            0x04 // ?????

#define CONN_IDLE_TIMER_ACT         0x10
#define CONN_READ_BLOCK             0x20
#define CONN_CLOSE_EMPTY            0x40
#define CONN_WS_CLOSE_SENT          0x80

#define CF_IDLE_TIMER_MAX           5000

#define WEBSOCKET_OP_CONT           0x00
#define WEBSOCKET_OP_TEXT           0x01
#define WEBSOCKET_OP_BINARY         0x02
#define WEBSOCKET_OP_CLOSE          0x08
#define WEBSOCKET_OP_PING           0x09
#define WEBSOCKET_OP_PONG           0x0A

#define WEBSOCKET_BROADCAST_LOCAL       1
#define WEBSOCKET_BROADCAST_GLOBAL      2

#define CF_TIMER_ONESHOT                0x01
#define CF_TIMER_FLAGS                  (CF_TIMER_ONESHOT)

#define CF_CONNECTION_PRUNE_DISCONNECT  0
#define CF_CONNECTION_PRUNE_ALL         1

struct cf_event {
    int		type;
    int		flags;
    void	(*handle)(void *, int);
} __attribute__((packed));

struct connection
{
    struct cf_event evt;
    int             fd;
    uint8_t         state;
    uint8_t         proto;
    void            *owner;

#ifndef CF_NO_TLS
    X509            *cert;
    SSL             *ssl;
    int             tls_reneg;
#endif

    uint8_t         flags;
    void*           hdlr_extra;

    int	   (*handle)(struct connection *);
    void   (*disconnect)(struct connection *, int);
    int	   (*read)(struct connection *, size_t *);
    int	   (*write)(struct connection *, size_t , size_t *);

    uint8_t family;

	union {
		struct sockaddr_in	ipv4;
		struct sockaddr_in6	ipv6;
        struct sockaddr_un  un;
	} addr;

	struct {
        uint64_t	length;
        uint64_t	start;
	} idle_timer;

	struct netbuf_head	send_queue;
	struct netbuf		*snb;
	struct netbuf		*rnb;

#ifndef CF_NO_HTTP
    struct cf_runtime_call	*ws_connect;
    struct cf_runtime_call	*ws_message;
    struct cf_runtime_call	*ws_disconnect;
	TAILQ_HEAD(, http_request)	http_requests;
#endif

	TAILQ_ENTRY(connection)	list;

}  __CONNECTION_PACKED;

TAILQ_HEAD(connection_list, connection);
extern struct connection_list	connections;
extern struct connection_list	disconnected;


#define CF_RUNTIME_NATIVE	0
#define CF_RUNTIME_PYTHON	1
#define CF_RUNTIME_LUA      2

struct cf_runtime
{
    int	type;
#ifndef CF_NO_HTTP
    int	(*http_request)(void*, struct http_request*);
    int	(*validator)(void*, struct http_request*, const void*);
    void (*wsconnect)(void*, struct connection*);
    void (*wsdisconnect)(void*, struct connection*);
    void (*wsmessage)(void*, struct connection*, uint8_t, const void*, size_t);
#endif
    int	 (*onload)(void*, int);
    void (*connect)(void*, struct connection*);
    void (*execute)(void*);
    void (*configure)(void*, int, char**);
};

struct cf_runtime_call
{
    void              *addr;
    struct cf_runtime *runtime;
};

extern struct cf_runtime cf_native_runtime;

struct listener
{
    struct cf_event         evt;
    int                     fd;
    int                     family;
    struct cf_runtime_call	*connect;

	LIST_ENTRY(listener)	list;
};

LIST_HEAD(listener_head, listener);

#ifndef CF_NO_HTTP

#define CF_PARAMS_QUERY_STRING	0x0001

struct cf_handler_params
{
    char*       name;
    int         flags;
    uint8_t     method;
    struct cf_validator *validator;

    TAILQ_ENTRY(cf_handler_params)	list;
};

#define CF_AUTH_TYPE_COOKIE		1
#define CF_AUTH_TYPE_HEADER		2
#define CF_AUTH_TYPE_REQUEST	3

struct cf_auth
{
    uint8_t             type;
    char                *name;
    char                *value;
    char                *redirect;
    struct cf_validator	*validator;

    TAILQ_ENTRY(cf_auth)	list;
};

#define HANDLER_TYPE_STATIC     1
#define HANDLER_TYPE_DYNAMIC	2

#endif /* CF_NO_HTTP */

#define CF_MODULE_LOAD          1
#define CF_MODULE_UNLOAD        2

#define CF_MODULE_NATIVE        0
#define CF_MODULE_PYTHON        1
#define CF_MODULE_LUA           2

struct cf_module
{
    void  *handle;
    char  *path;
    char  *onload;

    int   type;

    time_t	mtime;

    struct cf_runtime_call	*ocb;

    struct cf_module_functions	*fun;
    struct cf_runtime		*runtime;

    TAILQ_ENTRY(cf_module)	list;
};

struct cf_module_functions
{
    void (*free)(struct cf_module *);
    void (*reload)(struct cf_module *);
    int	 (*callback)(struct cf_module *, int);
    void (*load)(struct cf_module *);
    void *(*getsym)(struct cf_module *, const char *);
};

struct cf_module_handle
{
    char                    *path;
    char                    *func;
    int                     type;
    int                     errors;
    regex_t                 rctx;
    struct cf_domain        *dom;
    struct cf_runtime_call	*rcall;
#ifndef CF_NO_HTTP
    struct cf_auth          *auth;
    int                     methods;
    TAILQ_HEAD(, cf_handler_params)	params;
#endif
    TAILQ_ENTRY(cf_module_handle)	list;
};

/*
 * The workers get a 128KB log buffer per worker, and parent will fetch their
 * logs when it reached at least 75% of that or if its been > 1 second since
 * it was last synced.
 */
#define CF_ACCESSLOG_BUFLEN		131072U
#define CF_ACCESSLOG_SYNC		98304U

struct cf_alog_header
{
    uint16_t		domain;
    uint16_t		loglen;
} __attribute__((packed));

struct cf_worker
{
    uint8_t                 id;
    uint8_t                 cpu;
    pid_t                   pid;
    int                     pipe[2];
    struct connection       *msg[2];
    uint8_t                 has_lock;
    uint64_t                time_locked;
    struct cf_module_handle	*active_hdlr;

    /* Used by the workers to store accesslogs. */
    struct {
        int			lock;
        size_t		offset;
        char		buf[CF_ACCESSLOG_BUFLEN];
    } lb;
};

struct cf_domain
{
    uint16_t id;
    char     *domain;
    int      accesslog;

    struct cf_buf* logbuf;
    int            logerr;
    uint64_t       logwarn;

#ifndef CF_NO_TLS
    char    *cafile;
    char    *crlfile;
    char    *certfile;    /* Certificate file path */
    char    *certkey;     /* Private key path */
    SSL_CTX *ssl_ctx;
    int     x509_verify_depth;
#endif

    TAILQ_HEAD(, cf_module_handle)	handlers;
    TAILQ_ENTRY(cf_domain)          list;
};

TAILQ_HEAD(cf_domain_header, cf_domain);

#ifndef CF_NO_HTTPP

#define CF_VALIDATOR_TYPE_REGEX         1
#define CF_VALIDATOR_TYPE_FUNCTION      2

struct cf_validator
{
    uint8_t                type;
    char	               *name;
    char	               *arg;
    regex_t	               rctx;
    struct cf_runtime_call *rcall;

    TAILQ_ENTRY(cf_validator) list;
};
#endif

#define CF_BUF_OWNER_API	0x0001

struct cf_buf
{
    uint8_t     *data;
    int         flags;
    size_t      length;
    size_t      offset;
};

struct cf_mem_pool_region
{
    void		*start;
    size_t		length;

    LIST_ENTRY(cf_mem_pool_region)	list;
};

struct cf_mem_pool_entry
{
    uint8_t                     state;
    struct cf_mem_pool_region   *region;

    LIST_ENTRY(cf_mem_pool_entry) list;
};

struct cf_mem_pool
{
	size_t			elen;
	size_t			slen;
	size_t			elms;
	size_t			inuse;
    size_t			growth;

#ifdef CF_TASKS
    volatile int	lock;
#endif

    char			*name;

    LIST_HEAD(, cf_mem_pool_region)	regions;
    LIST_HEAD(, cf_mem_pool_entry)	freelist;
};

struct cf_timer
{
    uint64_t	nextrun;
    uint64_t	interval;
    int         flags;
	void		*arg;
    void		(*cb)(void *, uint64_t);

    TAILQ_ENTRY(cf_timer)	list;
};

#define CF_WORKER_KEYMGR            0

/* Reserved message ids, registered on workers */
#define CF_MSG_WEBSOCKET            1
#define CF_MSG_KEYMGR_REQ           2
#define CF_MSG_KEYMGR_RESP          3
#define CF_MSG_SHUTDOWN             4
#define CF_MSG_ENTROPY_REQ          5
#define CF_MSG_ENTROPY_RESP         6
#define CF_MSG_CERTIFICATE          7
#define CF_MSG_CERTIFICATE_REQ      8
#define CF_MSG_CRL			        9

/* Predefined message targets */
#define CF_MSG_PARENT               1000
#define CF_MSG_WORKER_ALL           1001

struct cf_msg
{
    uint8_t     id;
    uint16_t	src;
    uint16_t    dst;
    size_t      length;
};

#ifndef CF_NO_TLS
struct cf_keyreq
{
    int         padding;
    char		domain[CF_DOMAINNAME_LEN];
    uint8_t     domain_len;
    uint16_t	data_len;
    uint8_t     data[];
};

struct cf_x509_msg
{
    char        domain[CF_DOMAINNAME_LEN];
    uint16_t    domain_len;
    size_t      data_len;
    uint8_t	    data[];
};
#endif

/*-----------------------------------------------------------------------------
 *  zFrog server structure
 *----------------------------------------------------------------------------*/
struct zfrogServer
{
#ifndef CF_SINGLE_BINARY
    char*  config_file; /* Configuration file path */
#endif

    pid_t  pid;         /* Main process pid */
    char*  pidfile;     /* Store the pid of the main process in this file */

    uint8_t   worker_count;               /* Number of workers */
    uint32_t  worker_rlimit_nofiles;      /* Limit of maximum open files per worker */
    uint8_t   worker_set_affinity;        /* Workers bind themselves to a single CPU by default */
    uint32_t  worker_max_connections;     /* The number of active connections each worker can handle */
    uint32_t  worker_active_connections;  /* Current number of active connections per worker */
    uint32_t  worker_accept_threshold;

    uint32_t  socket_backlog; /* Socket backlog */
    uint16_t  cpu_count;      /* CPU count */
    uint8_t   nlisteners;     /* Number of current listeners */

    char*   root_path; /* */
    char*   runas_user;

    int     foreground;
    int     skip_chroot;
    int     skip_runas;

    int     debug_log;

#ifndef CF_NO_TLS
    int    tls_version;      /* TLS version     */    
    char*  tls_cipher_list;  /* TLS cipher list */
    DH*    tls_dhparam;      /* DH parameters   */
    char*  keymgr_runas_user;
    char*  keymgr_root_path;
#endif

#ifndef CF_NO_HTTP
    size_t      http_body_max;
    uint16_t    http_keepalive_time;
    uint16_t    http_header_max;
    uint32_t	http_request_ms;
    uint32_t    http_request_limit;
    uint64_t    http_body_disk_offload;
    uint64_t    http_hsts_enable;
    char*       http_body_disk_path;
    uint32_t    http_request_count;

    uint64_t    websocket_maxframe;
    uint64_t    websocket_timeout;

    char*       filemap_index;
    char*       filemap_ext;
#endif

#ifdef CF_TASKS
    uint16_t    task_threads;
#endif

#ifdef CF_PGSQL
    uint32_t   pgsql_queue_count;
    uint16_t   pgsql_conn_max;
    uint32_t   pgsql_queue_limit;
#endif

#ifdef CF_MYSQL
    uint16_t	mysql_conn_max;
#endif

#ifdef CF_REDIS
    uint16_t    redis_serv_conn_max;
#endif

    struct cf_worker* worker;         /* Current worker structure pointer */

    struct cf_domain*        primary_dom;
    struct cf_domain_header  domains;

    struct listener_head  listeners;
    struct cf_mem_pool    nb_pool;

    long long stat_net_input_bytes;     /* Bytes read from network */
    long long stat_net_output_bytes;    /* Bytes written to network */
};
/*-----------------------------------------------------------------------------
 *  Extern declarations
 *----------------------------------------------------------------------------*/
extern struct zfrogServer server;

/* Signal functions */
void cf_signal_setup(void);
void cf_signal(int);
/* Worker functions */
void cf_worker_wait(int);
void cf_worker_init(void);
void cf_worker_make_busy(void);
void cf_worker_shutdown(void);
void cf_worker_dispatch_signal(int);
void cf_worker_privdrop(const char*, const char*);

struct cf_worker* cf_worker_data(uint8_t);

/* Platform depended functions */
void cf_platform_init(void);
void cf_platform_event_init(void);
void cf_platform_event_cleanup(void);
void cf_platform_proctitle(char*);
void cf_platform_disable_read(int);
void cf_platform_disable_write(int);
void cf_platform_enable_accept(void);
void cf_platform_disable_accept(void);
void cf_platform_event_wait(uint64_t);
void cf_platform_event_all(int, void*);
void cf_platform_schedule_read(int, void*);
void cf_platform_schedule_write(int, void*);
void cf_platform_event_schedule(int, int, int, void*);
void cf_platform_worker_setcpu(struct cf_worker*);
int  cf_proc_pidpath(pid_t, void*, size_t);

#ifndef CF_NO_SENDFILE
    int	cf_platform_sendfile(struct connection*, struct netbuf*);
#endif

void cf_shutdown(void);
void cf_worker_teardown(void);
void cf_parent_teardown(void);

void cf_accesslog_worker_init(void);
void cf_accesslog_run(void*, uint64_t);
void cf_accesslog_gather(void*, uint64_t, int);

/* Timer functions */
void cf_timer_init(void);
uint64_t cf_timer_run(uint64_t);
void cf_timer_remove(struct cf_timer*);
struct cf_timer* cf_timer_add(void (*cb)(void*, uint64_t), uint64_t, void*, int);

/* Listener functions list */
void cf_listener_cleanup(void);

/* Server address bind function */
int	cf_server_bind(const char*,const char*,const char*);
int cf_server_bind_unix( const char*, const char*);

#ifndef CF_NO_TLS
    int	cf_tls_sni_cb(SSL*,int*,void*);
    void cf_tls_info_callback(const SSL*,int,int);
    void cf_domain_keymgr_init(void);
    void cf_domain_tls_init(struct cf_domain*,const void*,size_t);
    void cf_domain_crl_add(struct cf_domain*,const void*,size_t);
#endif

/* List of support client & backend functions */
void cf_connection_init(void);
void cf_connection_cleanup(void);
void cf_connection_prune(int);
struct connection* cf_connection_new(void*, uint8_t);
void cf_connection_event(void*, int);
void cf_connection_check_timeout(uint64_t);
int	cf_connection_handle(struct connection*);
void cf_connection_remove(struct connection*);
void cf_connection_disconnect(struct connection*);
void cf_connection_start_idletimer(struct connection*);
void cf_connection_stop_idletimer(struct connection*);
void cf_connection_check_idletimer(uint64_t, struct connection*);
int	cf_connection_accept(struct listener*, struct connection**);

/* Backend connection support functions */
int connection_add_backend(struct connection*);
void cf_connection_backend_error(struct connection*);
int cf_connection_backend_connect(struct connection*);
int cf_connection_address_init(struct connection*,const char*, uint16_t);
struct connection* cf_connection_backend_new(void*, const char*, uint16_t);


void cf_log_init(void);

void cf_parse_config(void);

/* Memory function definitions */
void* mem_malloc(size_t);
void* mem_calloc(size_t, size_t);
void* mem_realloc(void*, size_t);
void  mem_free(void*);
void  mem_init(void);
void  mem_cleanup(void);
void  mem_untag(void*);
void* mem_lookup(uint32_t);
void  mem_tag(void*, uint32_t);
void* mem_malloc_tagged(size_t, uint32_t);

/* Memory pool utility functions */
void* cf_mem_pool_get(struct cf_mem_pool*);
void  cf_mem_pool_put(struct cf_mem_pool*, void*);
void  cf_mem_pool_init(struct cf_mem_pool*, const char*, size_t, size_t);
void  cf_mem_pool_cleanup(struct cf_mem_pool*);

/* Utility functions */
time_t cf_date_to_time(const char*);
char* cf_time_to_date(time_t);
char* mem_strdup(const char*);
void cf_log(int, const char*, ...) __attribute__((format (printf, 2, 3)));
uint64_t cf_strtonum64(const char*, int, int*);
double cf_strtodouble(const char*, long double, long double, int*);
size_t cf_strlcpy(char*, const char*, const size_t);
char* cf_strncpy0(char*, const char*, size_t);
int	cf_split_string(char*, const char*, char**, size_t);
void cf_strip_chars(char*, const char, char**);
int	cf_snprintf(char*, size_t, int*, const char*, ...);
long long cf_strtonum(const char*, int, long long, long long, int*);
int cf_base64_encode(const void*, size_t, char**);
int cf_base64_decode(const char*, size_t, uint8_t**, size_t*);
void* cf_mem_find(void*, size_t, const void*, size_t);
char* cf_text_trim(char*, size_t);
char* cf_fread_line(FILE*, char*, size_t);
char* cf_uppercase(char*);
int cf_endswith(const char*, const char*);
uint64_t cf_time_ms(void);
uint64_t cf_time_us(void);
void cf_ms2ts(struct timespec*, uint64_t);
#ifdef __linux__
    int cf_get_sig_name(int, char*, size_t);
#endif

/* Messages function definitions */
void cf_msg_init(void);
void cf_msg_worker_init(void);
void cf_msg_parent_init(void);
void cf_msg_parent_add(struct cf_worker*);
void cf_msg_parent_remove(struct cf_worker*);
void cf_msg_send(uint16_t, uint8_t, const void*, size_t);
int	 cf_msg_register(uint8_t, void (*cb)(struct cf_msg*, const void*));

/* Domain functions definitions */
void cf_domain_init(void);
void cf_domain_cleanup(void);
int  cf_domain_new(char*);
void cf_domain_free(struct cf_domain*);
struct cf_domain* cf_domain_lookup(const char*);
struct cf_domain* cf_domain_byid(uint16_t);
void cf_domain_closelogs(void);
void cf_domain_callback(void (*cb)(struct cf_domain*));

/* Module functions definitions */
void  cf_module_init(void);
void  cf_module_cleanup(void);
void  cf_module_reload(int);
void  cf_module_onload(void);
int	  cf_module_loaded(void);
void* cf_module_getsym(const char*, struct cf_runtime**);
void  cf_module_load(const char*, const char*, int);
int	  cf_module_handler_new(const char*, const char*, const char*, const char*, int);
void  cf_module_handler_free(struct cf_module_handle*);

void cf_runtime_execute(struct cf_runtime_call*);
struct cf_runtime_call* cf_runtime_getcall(const char*);
int	cf_runtime_onload(struct cf_runtime_call*, int);
void cf_runtime_connect(struct cf_runtime_call*, struct connection*);
void cf_runtime_configure(struct cf_runtime_call*, int, char**);

#ifndef CF_NO_HTTP
    /* Authentication function list */
    int	cf_auth_run(struct http_request*, struct cf_auth*);
    void cf_auth_init(void);
    int cf_auth_new(const char*);
    int cf_auth_cookie(struct http_request*, struct cf_auth*);
    int cf_auth_header(struct http_request*, struct cf_auth*);
    int cf_auth_request(struct http_request*, struct cf_auth*);
    struct cf_auth* cf_auth_lookup(const char*);
    /* Web sockets function's list */
    void cf_websocket_handshake(struct http_request*, const char*, const char*, const char*);
    int	cf_websocket_send_clean(struct netbuf*);
    void cf_websocket_send(struct connection*, uint8_t, const void*, size_t);
    void cf_websocket_broadcast(struct connection*, uint8_t, const void*, size_t, int);

    int cf_runtime_http_request(struct cf_runtime_call*, struct http_request*);
    int cf_runtime_validator(struct cf_runtime_call*, struct http_request*, const void*);
    void cf_runtime_wsconnect(struct cf_runtime_call*, struct connection*);
    void cf_runtime_wsdisconnect(struct cf_runtime_call*, struct connection*);
    void cf_runtime_wsmessage(struct cf_runtime_call*, struct connection*, uint8_t, const void*, size_t);
    void cf_validator_init(void);
    void cf_validator_reload(void);
    int	cf_validator_add(const char*, uint8_t, const char*);
    int	cf_validator_run(struct http_request*, const char*, char*);
    int	cf_validator_check(struct http_request*, struct cf_validator*, const void*);
    struct cf_validator* cf_validator_lookup(const char*);
#endif

void cf_filemap_init(void);
int	 cf_filemap_create(struct cf_domain*, const char*, const char*);
void cf_filemap_resolve_paths(void);
void cf_fileref_init(void);
struct cf_fileref* cf_fileref_get(const char*);
struct cf_fileref* cf_fileref_create(const char*, int, off_t,struct timespec*);
void cf_fileref_release(struct cf_fileref*);
void cf_fileref_init(void);

struct cf_module_handle* cf_module_handler_find(const char*, const char*);

void cf_fatal(const char*, ...) __attribute__((noreturn));
void cf_fatalx(const char*, ...) __attribute__((noreturn));
void log_debug_internal(char*, int, const char*, ...);

uint16_t net_read16(uint8_t*);
uint32_t net_read32(uint8_t*);
uint64_t net_read64(uint8_t*);
void	 net_write16(uint8_t*, uint16_t);
void	 net_write32(uint8_t*, uint32_t);
void	 net_write64(uint8_t*, uint64_t);

/* Network functions list */
void net_init(void);
void net_cleanup(void);
int  net_send(struct connection*);
int	 net_send_flush(struct connection*);
int	 net_recv_flush(struct connection*);
int	 net_read(struct connection*, size_t*);
int	 net_read_tls(struct connection*, size_t*);
int	 net_write(struct connection*, size_t, size_t*);
int	 net_write_tls(struct connection*, size_t, size_t*);
void net_recv_reset(struct connection*, size_t, int (*cb)(struct netbuf*));
void net_remove_netbuf(struct connection*, struct netbuf*);
void net_recv_queue(struct connection*, size_t, int, int (*cb)(struct netbuf*));
void net_recv_expand(struct connection*, size_t, int (*cb)(struct netbuf*));
void net_send_queue(struct connection*, const void*, size_t);
void net_send_stream(struct connection*, void*, size_t, int (*cb)(struct netbuf*), struct netbuf**);
struct netbuf* net_netbuf_get(void);
void net_send_fileref(struct connection*, struct cf_fileref*);

/* Buffer functions list */
void cf_buf_free(struct cf_buf*);
struct cf_buf* cf_buf_alloc(size_t);
void cf_buf_init(struct cf_buf*, size_t);
void cf_buf_append(struct cf_buf*, const void*, size_t);
uint8_t* cf_buf_release(struct cf_buf*, size_t*);
void cf_buf_reset(struct cf_buf*);
void cf_buf_cleanup(struct cf_buf*);

char* cf_buf_stringify(struct cf_buf*, size_t*);
void cf_buf_appendf(struct cf_buf*, const char*, ...);
void cf_buf_appendv(struct cf_buf*, const char*, va_list);
void cf_buf_replace_string(struct cf_buf*, char*, const void*, size_t);
void cf_buf_replace_position_string(struct cf_buf*, char*, size_t, void*, size_t);
void cf_buf_replace_first_string(struct cf_buf*, char*, void*, size_t);

void cf_keymgr_run(void);
void cf_keymgr_cleanup(int);
void cf_init_pkcs11_module(void);

int cf_cloexec_ioctl(int, int);
int cf_get_backlog_size(void);

int	cf_socket_nonblock(int, int);
int cf_socket_opt(int, int, int);

size_t cf_random_buffer(unsigned char [], size_t, int);
const char* cf_file_extension(const char*);
size_t cf_uuid_buffer(char [], size_t);
int cf_is_hex_digit(char);
void cf_bytes_to_human(char*,unsigned long long);

int cf_tcp_socket(const char *hostname, int type /*SOCK_STREAM*/);

void cf_worker_configure(void);
void cf_parent_configure(int, char**);
void cf_parent_daemonized(void);

/* Some macros to help */
#define BITMASK_SET(x,y) ((x) |= (y))
#define BITMASK_CLEAR(x,y) ((x) &= (~(y)))
#define BITMASK_FLIP(x,y) ((x) ^= (y))
#define BITMASK_CHECK(x,y) ((x) & (y))


#if defined(__cplusplus)
}
#endif

#endif /* !__ZFROG_H__ */
