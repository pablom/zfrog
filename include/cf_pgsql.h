// cf_pgsql.h

#ifndef __CF_PGSQL_H_
#define __CF_PGSQL_H_

#include <libpq-fe.h>

#define CF_PGSQL_FORMAT_TEXT		0
#define CF_PGSQL_FORMAT_BINARY      1

#define CF_PGSQL_SYNC               0x0001
#define CF_PGSQL_ASYNC              0x0002
#define CF_PGSQL_SCHEDULED          0x0004

#define CF_PGSQL_QUEUE_LIMIT	    1000
#define CF_PGSQL_CONN_MAX           2

#if defined(__cplusplus)
extern "C" {
#endif

struct pgsql_conn
{
    u_int8_t   type;
    u_int8_t   flags;
    char	   *name;

    PGconn             *db;
    struct pgsql_job   *job;
    TAILQ_ENTRY(pgsql_conn) list;
};

struct pgsql_db
{
    char        *name;
    char        *conn_string;
    u_int16_t	conn_max;
    u_int16_t	conn_count;

    LIST_ENTRY(pgsql_db) rlist;
};

struct cf_pgsql
{
	uint8_t		state;
	int			flags;
    char		*error;
    PGresult	*result;
    struct pgsql_conn *conn;

    struct {
        char		*channel;
        char		*extra;
    } notify;

    struct http_request	*req;
    void                *arg;
    void (*cb)(struct cf_pgsql*, void*);

    LIST_ENTRY(cf_pgsql) rlist;
};

void cf_pgsql_sys_init(void);
void cf_pgsql_sys_cleanup(void);
void cf_pgsql_init(struct cf_pgsql*);
#ifndef CF_NO_HTTP
void cf_pgsql_bind_request(struct cf_pgsql*, struct http_request*);
#endif
void cf_pgsql_bind_callback(struct cf_pgsql*, void (*cb)(struct cf_pgsql*, void*), void*);

int	cf_pgsql_setup(struct cf_pgsql*, const char*, int);
void cf_pgsql_handle(void *, int);
void cf_pgsql_cleanup(struct cf_pgsql*);
void cf_pgsql_continue(struct cf_pgsql*);
int	 cf_pgsql_query(struct cf_pgsql*, const char*);
int	 cf_pgsql_query_params(struct cf_pgsql*, const char *, int, uint8_t, ...);
int	 cf_pgsql_v_query_params(struct cf_pgsql*, const char *, int, uint8_t, va_list);
int	 cf_pgsql_register(const char*, const char*);
int	 cf_pgsql_ntuples(struct cf_pgsql*);
int	 cf_pgsql_nfields(struct cf_pgsql*);
void cf_pgsql_logerror(struct cf_pgsql*);
char *cf_pgsql_fieldname(struct cf_pgsql*, int);
char *cf_pgsql_getvalue(struct cf_pgsql*, int, int);
int	 cf_pgsql_getlength(struct cf_pgsql*, int, int);

#if defined(__cplusplus)
}
#endif

#define CF_PGSQL_STATE_INIT         1
#define CF_PGSQL_STATE_WAIT         2
#define CF_PGSQL_STATE_RESULT		3
#define CF_PGSQL_STATE_ERROR		4
#define CF_PGSQL_STATE_DONE         5
#define CF_PGSQL_STATE_COMPLETE     6
#define CF_PGSQL_STATE_NOTIFY		7

#endif // __CF_PGSQL_H_
