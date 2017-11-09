// zfrog.h

#ifndef __ZFROG_H__
#define __ZFROG_H__

#if defined(__APPLE__)
    #define daemon portability_is_king
#endif

#if defined( __sun )
    #include <inttypes.h>
    #include <sys/port.h>
    #include <port.h>
    #include <atomic.h>

    /* Macros for min/max  */
    #define MIN(a,b) (((a)<(b))?(a):(b))
    #define MAX(a,b) (((a)>(b))?(a):(b))

    #define __sync_bool_compare_and_swap(p, o, n) atomic_cas_uint((volatile uint_t *)p, o, n)

#endif /* __sun */


#include <sys/types.h>
#include <sys/time.h>
#include <sys/queue.h>

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
#include <stdarg.h>

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

#define CF_TLS_VERSION_1_2      0
#define CF_TLS_VERSION_1_1      1
#define CF_TLS_VERSION_1_0      2
#define CF_TLS_VERSION_BOTH     3

#define CF_RESEED_TIME	(1800 * 1000)

#define errno_s			strerror(errno)
#define ssl_errno_s		ERR_error_string(ERR_get_error(), NULL)

#define CF_DOMAINNAME_LEN		256
#define CF_PIDFILE_DEFAULT		"cf.pid"
#define CF_DEFAULT_CIPHER_LIST	"ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!MD5:!PSK:!kRSA:!kDSA"

#if defined(CF_DEBUG)
#define log_debug(...)		\
    if (log_debug)		\
        log_debug_internal(__FILE__, __LINE__, __VA_ARGS__)
#else
#define log_debug(...)
#endif

#define NETBUF_RECV                 0
#define NETBUF_SEND                 1
#define NETBUF_SEND_PAYLOAD_MAX		8192

#define NETBUF_LAST_CHAIN           0
#define NETBUF_BEFORE_CHAIN         1

#define NETBUF_CALL_CB_ALWAYS       0x01
#define NETBUF_FORCE_REMOVE         0x02
#define NETBUF_MUST_RESEND          0x04
#define NETBUF_IS_STREAM            0x10

#define X509_GET_CN(c, o, l)					\
	X509_NAME_get_text_by_NID(X509_get_subject_name(c),	\
	    NID_commonName, o, l)

#define X509_CN_LENGTH		(ub_common_name + 1)

#ifndef CF_NO_HTTP
    struct http_request;
#endif

struct netbuf
{
    uint8_t	 *buf;
    size_t	 s_off;
    size_t	 b_len;
    size_t	 m_len;
    uint8_t	 type;
    uint8_t	 flags;

    void	 *owner;
    void	 *extra;

    int		 (*cb)(struct netbuf *);

	TAILQ_ENTRY(netbuf)	list;
};

TAILQ_HEAD(netbuf_head, netbuf);

#define CF_TYPE_LISTENER        1
#define CF_TYPE_CONNECTION      2
#define CF_TYPE_PGSQL_CONN      3
#define CF_TYPE_REDIS           4
#define CF_TYPE_TASK            5

#define CONN_STATE_UNKNOWN          0
#define CONN_STATE_SSL_SHAKE		1
#define CONN_STATE_ESTABLISHED		2
#define CONN_STATE_DISCONNECTING	3

#define CONN_PROTO_UNKNOWN      0
#define CONN_PROTO_HTTP         1
#define CONN_PROTO_WEBSOCKET	2
#define CONN_PROTO_MSG          3

#define CONN_READ_POSSIBLE      0x01
#define CONN_WRITE_POSSIBLE     0x02
#define CONN_WRITE_BLOCK        0x04
#define CONN_IDLE_TIMER_ACT     0x10
#define CONN_READ_BLOCK         0x20
#define CONN_CLOSE_EMPTY        0x40
#define CONN_WS_CLOSE_SENT      0x80

#define CF_IDLE_TIMER_MAX       20000

#define WEBSOCKET_OP_CONT       0x00
#define WEBSOCKET_OP_TEXT       0x01
#define WEBSOCKET_OP_BINARY     0x02
#define WEBSOCKET_OP_CLOSE      0x08
#define WEBSOCKET_OP_PING       0x09
#define WEBSOCKET_OP_PONG       0x10

#define WEBSOCKET_BROADCAST_LOCAL           1
#define WEBSOCKET_BROADCAST_GLOBAL          2

#define CF_TIMER_ONESHOT                    0x01

#define CF_CONNECTION_PRUNE_DISCONNECT      0
#define CF_CONNECTION_PRUNE_ALL             1

struct connection
{
    uint8_t  type;
    int      fd;
    uint8_t  state;
    uint8_t  proto;
    void	 *owner;

#ifndef CF_NO_TLS
    X509 *cert;
    SSL	 *ssl;
    int	 tls_reneg;
#endif

    uint8_t	flags;
    void *hdlr_extra;

    int	   (*handle)(struct connection *);
    void   (*disconnect)(struct connection *);
    int	   (*read)(struct connection *, size_t *);
    int	   (*write)(struct connection *, size_t , size_t *);

    uint8_t addrtype;
	union {
		struct sockaddr_in	ipv4;
		struct sockaddr_in6	ipv6;
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
    int	(*http_request)(void *, struct http_request *);
    int	(*validator)(void *, struct http_request *, void *);
    void (*wsconnect)(void *, struct connection *);
    void (*wsdisconnect)(void *, struct connection *);
    void (*wsmessage)(void *, struct connection *, uint8_t, const void *, size_t);
#endif
    int	 (*onload)(void *, int);
    void (*connect)(void *, struct connection *);    
    void (*execute)(void *);
};

struct cf_runtime_call
{
    void *addr;
    struct cf_runtime *runtime;
};

extern struct cf_runtime cf_native_runtime;


struct listener
{
    uint8_t type;
    uint8_t addrtype;
    int		 fd;

    struct cf_runtime_call	*connect;

	union {
		struct sockaddr_in	ipv4;
		struct sockaddr_in6	ipv6;
	} addr;

	LIST_ENTRY(listener)	list;
};

LIST_HEAD(listener_head, listener);

#ifndef CF_NO_HTTP

struct cf_handler_params
{
    char  *name;
    uint8_t method;
    struct cf_validator *validator;

    TAILQ_ENTRY(cf_handler_params)	list;
};

#define CF_AUTH_TYPE_COOKIE		1
#define CF_AUTH_TYPE_HEADER		2
#define CF_AUTH_TYPE_REQUEST	3

struct cf_auth
{
    uint8_t	 type;
    char	 *name;
    char	 *value;
    char	 *redirect;
    struct cf_validator	*validator;

    TAILQ_ENTRY(cf_auth)	list;
};

#define HANDLER_TYPE_STATIC     1
#define HANDLER_TYPE_DYNAMIC	2

#endif

#define CF_MODULE_LOAD      1
#define CF_MODULE_UNLOAD	2

#define CF_MODULE_NATIVE	0
#define CF_MODULE_PYTHON	1
#define CF_MODULE_LUA       2

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
    void (*load)(struct cf_module *, const char *);
    void *(*getsym)(struct cf_module *, const char *);
};

struct cf_module_handle
{
    char		*path;
    char		*func;
    void		*addr;
	int			type;
	int			errors;
    regex_t		rctx;
    struct cf_domain *dom;
    struct cf_runtime_call	*rcall;
#ifndef CF_NO_HTTP
    struct cf_auth	*auth;
    TAILQ_HEAD(, cf_handler_params)	params;
#endif
    TAILQ_ENTRY(cf_module_handle)		list;
};


struct cf_worker
{
    uint8_t  id;
    uint8_t	 cpu;
    pid_t	 pid;
    int		 pipe[2];
    struct connection *msg[2];
    uint8_t	 has_lock;
    struct cf_module_handle	*active_hdlr;
};

struct cf_domain
{
    char *domain;
    int	 accesslog;

#ifndef CF_NO_TLS
    char  *cafile;
    char  *crlfile;
    char  *certfile;
    char  *certkey;
    SSL_CTX *ssl_ctx;

#endif

    TAILQ_HEAD(, cf_module_handle)	handlers;
    TAILQ_ENTRY(cf_domain)          list;
};

TAILQ_HEAD(cf_domain_h, cf_domain);

#ifndef CF_NO_HTTPP

#define CF_VALIDATOR_TYPE_REGEX         1
#define CF_VALIDATOR_TYPE_FUNCTION      2

struct cf_validator
{
    uint8_t   type;
    char	  *name;
    char	  *arg;
    regex_t	  rctx;
    struct cf_runtime_call	*rcall;

    TAILQ_ENTRY(cf_validator)	list;
};
#endif

#define CF_BUF_OWNER_API	0x0001

struct cf_buf
{
    uint8_t *data;
    int		 flags;
    size_t	 length;
    size_t	 offset;
};

struct cf_mem_pool_region
{
	void				*start;
	size_t				length;
    LIST_ENTRY(cf_mem_pool_region)	list;
};

struct cf_mem_pool_entry
{
    uint8_t	 state;
    struct cf_mem_pool_region *region;
    LIST_ENTRY(cf_mem_pool_entry) list;
};


struct cf_mem_pool
{
	size_t			elen;
	size_t			slen;
	size_t			elms;
	size_t			inuse;
    volatile int	lock;
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

#define CF_WORKER_KEYMGR        0

/* Reserved message ids, registered on workers */
#define CF_MSG_ACCESSLOG        1
#define CF_MSG_WEBSOCKET        2
#define CF_MSG_KEYMGR_REQ       3
#define CF_MSG_KEYMGR_RESP      4
#define CF_MSG_SHUTDOWN         5
#define CF_MSG_ENTROPY_REQ      6
#define CF_MSG_ENTROPY_RESP     7

/* Predefined message targets */
#define CF_MSG_PARENT           1000
#define CF_MSG_WORKER_ALL       1001

struct cf_msg
{
    uint8_t     id;
    uint16_t	src;
    uint16_t	dst;
    uint32_t	length;
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
#endif

#if !defined(CF_SINGLE_BINARY)
    extern char	*config_file;
#endif

extern pid_t  cf_pid;
extern int	foreground;
extern int	log_debug;
extern int	skip_chroot;
extern char	*chroot_path;
extern int	skip_runas;
extern char	*runas_user;
extern char	*cf_pidfile;
extern char	*cf_tls_cipher_list;
extern int	tls_version;

#ifndef CF_NO_TLS
    extern DH *tls_dhparam;
#endif

extern uint8_t	nlisteners;
extern uint16_t cpu_count;
extern uint8_t	worker_count;
extern uint8_t	worker_set_affinity;
extern uint32_t worker_rlimit_nofiles;
extern uint32_t worker_max_connections;
extern uint32_t worker_active_connections;
extern uint32_t worker_accept_threshold;
extern uint64_t cf_websocket_maxframe;
extern uint64_t cf_websocket_timeout;
extern uint32_t cf_socket_backlog;

extern struct listener_head	listeners;
extern struct cf_worker	    *worker;
extern struct cf_domain_h   domains;
extern struct cf_domain	    *primary_dom;
extern struct cf_mem_pool   nb_pool;

void cf_cli_usage(int);
int	zfrog_cli_main(int, char **);

void cf_signal(int);
void cf_worker_wait(int);
void cf_worker_init(void);
void cf_worker_shutdown(void);
void cf_worker_privdrop(void);
void cf_worker_dispatch_signal(int);
void cf_worker_spawn(uint16_t, uint16_t);
void cf_worker_entry(struct cf_worker *);

struct cf_worker *cf_worker_data(uint8_t);

void cf_platform_init(void);
void cf_platform_event_init(void);
void cf_platform_event_cleanup(void);
void cf_platform_proctitle(char *);
void cf_platform_disable_read(int);
void cf_platform_enable_accept(void);
void cf_platform_disable_accept(void);
int	 cf_platform_event_wait( uint64_t timer );
void cf_platform_event_all(int, void *);
void cf_platform_schedule_read(int, void *);
void cf_platform_schedule_write(int, void *);
void cf_platform_event_schedule(int, int, int, void *);
void cf_platform_worker_setcpu(struct cf_worker *);
int  cf_proc_pidpath( pid_t pid, void *buf, size_t len );

void cf_accesslog_init(void);
void cf_accesslog_worker_init(void);
int  cf_accesslog_write(const void *data, uint32_t len);


void cf_timer_init(void);
uint64_t cf_timer_run(uint64_t);
void cf_timer_remove(struct cf_timer *);
struct cf_timer *cf_timer_add(void (*cb)(void *, uint64_t), uint64_t, void *, int);

void cf_listener_cleanup(void);
int	cf_server_bind(const char *, const char *, const char *);

#ifndef CF_NO_TLS
    int	cf_tls_sni_cb(SSL *, int *, void *);
    void cf_tls_info_callback(const SSL *, int, int);
#endif

void connection_init(void);
void connection_cleanup(void);
void cf_connection_prune( int );
struct connection *cf_connection_new( void* );
int connection_add_backend( struct connection * );
void cf_connection_check_timeout(void);
int	cf_connection_nonblock(int, int);
int	cf_connection_handle(struct connection *);
void cf_connection_remove(struct connection *);
void cf_connection_disconnect(struct connection *);
void cf_connection_start_idletimer(struct connection *);
void cf_connection_stop_idletimer(struct connection *);
void cf_connection_check_idletimer(uint64_t, struct connection *);
int	connection_accept(struct listener *, struct connection **);

uint64_t cf_time_ms(void);
void cf_ms2ts( struct timespec *ts, uint64_t ms );

void cf_log_init(void);

void cf_parse_config(void);

void *mem_malloc(size_t);
void *mem_calloc(size_t, size_t);
void *mem_realloc(void *, size_t);
void mem_free(void *);
void mem_init(void);
void mem_cleanup(void);
void mem_untag(void *);
void* mem_lookup(uint32_t);
void mem_tag(void *, uint32_t);
void* mem_malloc_tagged(size_t, uint32_t);


void *cf_mem_pool_get(struct cf_mem_pool *);
void cf_mem_pool_put(struct cf_mem_pool *, void *);
void cf_mem_pool_init(struct cf_mem_pool *, const char *, size_t, size_t);
void cf_mem_pool_cleanup(struct cf_mem_pool *);

time_t	cf_date_to_time(char *);
char *cf_time_to_date(time_t);
char *mem_strdup(const char *);
void cf_log(int, const char *, ...) __attribute__((format (printf, 2, 3)));
uint64_t cf_strtonum64(const char *, int, int *);
size_t cf_strlcpy(char *, const char *, const size_t);
char* cf_strncpy0(char *dst, const char *src, size_t len);

void core_server_disconnect(struct connection *);
int	cf_split_string(char *, const char *, char **, size_t);
void cf_strip_chars(char *, const char, char **);
int	cf_snprintf(char *, size_t, int *, const char *, ...);
long long	cf_strtonum(const char *, int, long long, long long, int *);
int cf_base64_encode(const void *, size_t, char **);
int cf_base64_decode(char *in, size_t ilen, uint8_t **out, size_t *olen);
void *cf_mem_find(void *, size_t, void *, size_t);
char *cf_text_trim(char *, size_t);
char *cf_read_line(FILE *, char *, size_t);


void cf_msg_init(void);
void cf_msg_worker_init(void);
void cf_msg_parent_init(void);
void cf_msg_parent_add(struct cf_worker *);
void cf_msg_parent_remove(struct cf_worker *);
void cf_msg_send(uint16_t, uint8_t, const void *, uint32_t);
int	 cf_msg_register(uint8_t, void (*cb)(struct cf_msg *, const void *));

void cf_domain_init(void);
void cf_domain_cleanup(void);
int  domain_new(char *domain );
void cf_domain_free(struct cf_domain *);

void cf_module_init(void);
void cf_module_cleanup(void);
void cf_module_reload(int);
void cf_module_onload(void);
int	 cf_module_loaded(void);

void cf_domain_closelogs(void);
void *cf_module_getsym( const char *symbol, struct cf_runtime **runtime );
void cf_domain_load_crl(void);
void cf_domain_keymgr_init(void);
void cf_module_load(const char *path, const char *onload, int type);
void cf_domain_tls_init(struct cf_domain *);
void cf_domain_callback(void (*cb)(struct cf_domain *));
int	 cf_module_handler_new(const char *, const char *, const char *, const char *, int);
void cf_module_handler_free( struct cf_module_handle * );

void   cf_runtime_execute(struct cf_runtime_call *);
struct cf_runtime_call	*cf_runtime_getcall(const char *);
int	   cf_runtime_onload(struct cf_runtime_call *, int);
void   cf_runtime_connect(struct cf_runtime_call *, struct connection *);

#ifndef CF_NO_HTTP
    int	cf_auth_run(struct http_request *, struct cf_auth *);
    void cf_auth_init(void);
    int cf_auth_new(const char *);
    struct cf_auth *cf_auth_lookup(const char *);
    void cf_websocket_handshake(struct http_request *, const char *, const char *, const char *);
    void cf_websocket_send(struct connection *, uint8_t, const void *, size_t);
    void cf_websocket_broadcast(struct connection *, uint8_t, const void *, size_t, int);
    int cf_runtime_http_request(struct cf_runtime_call *, struct http_request *);
    int cf_runtime_validator(struct cf_runtime_call *, struct http_request *, void *);
    void cf_runtime_wsconnect(struct cf_runtime_call *, struct connection *);
    void cf_runtime_wsdisconnect(struct cf_runtime_call *, struct connection *);
    void cf_runtime_wsmessage(struct cf_runtime_call *, struct connection *, uint8_t, const void *, size_t);
    void cf_validator_init(void);
    void cf_validator_reload(void);
    int	cf_validator_add(const char *, uint8_t, const char *);
    int	cf_validator_run(struct http_request *, const char *, char *);
    int	cf_validator_check(struct http_request *, struct cf_validator *, void *);
    struct cf_validator *cf_validator_lookup(const char *);
#endif

struct cf_domain *cf_domain_lookup(const char *);
struct cf_module_handle *cf_module_handler_find(const char *, const char *);

void cf_fatal(const char *, ...) __attribute__((noreturn));
void log_debug_internal(char *, int, const char *, ...);

uint16_t net_read16(uint8_t *);
uint32_t net_read32(uint8_t *);
uint64_t net_read64(uint8_t *);
void	 net_write16(uint8_t *, uint16_t);
void	 net_write32(uint8_t *, uint32_t);
void	 net_write64(uint8_t *, uint64_t);

void net_init(void);
void net_cleanup(void);
int  net_send(struct connection *);
int	 net_send_flush(struct connection *);
int	 net_recv_flush(struct connection *);
int	 net_read(struct connection *, size_t  *);
int	 net_read_tls(struct connection *, size_t  *);
int	 net_write(struct connection *, size_t, size_t *);
int	 net_write_tls(struct connection *, size_t, size_t *);
void net_recv_reset(struct connection *, size_t, int (*cb)(struct netbuf *));
void net_remove_netbuf(struct netbuf_head *, struct netbuf *);
void net_recv_queue(struct connection *, size_t, int, int (*cb)(struct netbuf *));
void net_recv_expand(struct connection *c, size_t, int (*cb)(struct netbuf *));
void net_send_queue(struct connection *, const void *, size_t);
void net_send_stream(struct connection *, void *, size_t, int (*cb)(struct netbuf *), struct netbuf **);

void cf_buf_free(struct cf_buf *);
struct cf_buf *cf_buf_alloc(size_t initial_size);
void cf_buf_init(struct cf_buf *, size_t);
void cf_buf_append(struct cf_buf *, const void *, size_t);
uint8_t *cf_buf_release(struct cf_buf *, size_t *);
void cf_buf_reset(struct cf_buf *);
void cf_buf_cleanup(struct cf_buf *);

char *cf_buf_stringify(struct cf_buf *, size_t *);
void cf_buf_appendf(struct cf_buf *, const char *, ...);
void cf_buf_appendv(struct cf_buf *, const char *, va_list);
void cf_buf_replace_string(struct cf_buf *, char *, void *, size_t);
void cf_buf_replace_position_string( struct cf_buf *, char *, size_t, void *, size_t );
void cf_buf_replace_first_string( struct cf_buf *, char *, void *, size_t );

void cf_keymgr_run(void);
void cf_keymgr_cleanup(void);
void cf_init_pkcs11_module(void);

int cf_cloexec_ioctl(int fd, int set);
int cf_get_backlog_size(void);
int cf_sockopt( int fd, int what, int opt );

size_t cf_random_buffer( unsigned char [], size_t, int );
const char * cf_file_extension( const char * );
size_t cf_uuid_buffer( char [], size_t );

/* Mustache template parser */
#ifdef CF_TMUSTACHE

#define CF_MUSTACH_OK                       0
#define CF_MUSTACH_ERROR_SYSTEM            -1
#define CF_MUSTACH_ERROR_UNEXPECTED_END    -2
#define CF_MUSTACH_ERROR_EMPTY_TAG         -3
#define CF_MUSTACH_ERROR_TAG_TOO_LONG      -4
#define CF_MUSTACH_ERROR_BAD_SEPARATORS    -5
#define CF_MUSTACH_ERROR_TOO_DEPTH         -6
#define CF_MUSTACH_ERROR_CLOSING           -7
#define CF_MUSTACH_ERROR_BAD_UNESCAPE_TAG  -8

struct cf_mustach_itf
{
    int (*start)(void *closure);
    int (*put)(void *closure, const char *name, int escape, FILE *file);
    int (*enter)(void *closure, const char *name);
    int (*next)(void *closure);
    int (*leave)(void *closure);
};

int cf_fmustach(const char *template, struct cf_mustach_itf *itf, void *closure, FILE *file);
int cf_fdmustach(const char *template, struct cf_mustach_itf *itf, void *closure, int fd);
int cf_mustach(const char *template, struct cf_mustach_itf *itf, void *closure, char **result, size_t *size);

#endif /* CF_TMUSTACHE */


#ifdef CF_CTEMPL

typedef struct cf_tmpl_varlist cf_tmpl_varlist;
typedef struct cf_tmpl_loop  cf_tmpl_loop;
typedef struct cf_tmpl_fmtlist cf_tmpl_fmtlist;
typedef void (*cf_tmpl_fmtfunc) (const char *, FILE *);

cf_tmpl_varlist* cf_tmpl_add_var(cf_tmpl_varlist *varlist, ...) ;
cf_tmpl_varlist* cf_tmpl_add_loop(cf_tmpl_varlist *varlist, const char *name, cf_tmpl_loop *loop);
cf_tmpl_loop* cf_tmpl_add_varlist(cf_tmpl_loop *loop, cf_tmpl_varlist *varlist);
void cf_tmpl_free_varlist( cf_tmpl_varlist *varlist );
cf_tmpl_fmtlist* cf_tmpl_add_fmt( cf_tmpl_fmtlist *fmtlist, const char *name, cf_tmpl_fmtfunc fmtfunc );
void cf_tmpl_free_fmtlist( cf_tmpl_fmtlist *fmtlist );
int cf_tmpl_write( char *filename, char *tmplstr, const cf_tmpl_fmtlist *fmtlist, const cf_tmpl_varlist *varlist, FILE *out, FILE *errout);

void cf_tmpl_encode_entity( const char *value, FILE *out );
void cf_tmpl_encode_url( const char *value, FILE *out );

#endif /* CF_CTEMPL */


#if defined(__cplusplus)
}
#endif

#endif /* !__ZFROG_H__ */
