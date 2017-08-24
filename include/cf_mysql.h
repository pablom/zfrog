// cf_mysql.h

#ifndef __CF_MYSQL_H_
#define __CF_MYSQL_H_

#include <my_config.h>
#include <mysql.h>

#define CF_MYSQL_FORMAT_TEXT		0
#define CF_MYSQL_FORMAT_BINARY      1

#define CF_MYSQL_SYNC			0x0001
#define CF_MYSQL_ASYNC          0x0002

#if defined(__cplusplus)
extern "C" {
#endif

struct mysql_conn
{
    uint8_t type;
    uint8_t	flags;
    char	*name;
	
    MYSQL *mysql;

    struct mysql_job *job;
    TAILQ_ENTRY(mysql_conn) list;
};

struct mysql_db
{
    const char *host;
    const char *user;
    const char *passwd;
    const char *dbname;
    unsigned int port;
    const char *unix_socket;
	unsigned long flags;

    LIST_ENTRY(mysql_db) rlist;
};

struct cf_mysql
{
    uint8_t state;
	int flags;
	char *error;
	MYSQL_RES *result;
	struct mysql_conn *conn;

    LIST_ENTRY(cf_mysql) rlist;
};

extern uint16_t	mysql_conn_max;

void cf_mysql_sys_init(void);

int	cf_mysql_query_init( struct cf_mysql *, struct http_request *,
                         const char *, const char *, const char *, const char *,
                         unsigned int, const char *, unsigned long);
    
void cf_mysql_cleanup(struct cf_mysql *);
int	cf_mysql_query(struct cf_mysql *, const char *);
int	cf_mysql_register(const char *, const char *);
void cf_mysql_logerror(struct cf_mysql *);
void cf_mysql_queue_remove(struct http_request *);

//void	cf_mysql_handle(void *, int);
//void	cf_mysql_continue(struct http_request *, struct cf_mysql *);
//int	cf_mysql_ntuples(struct cf_mysql *);
//char	*cf_mysql_getvalue(struct cf_mysql *, int, int);
//int	cf_mysql_getlength(struct cf_mysql *, int, int);

#if defined(__cplusplus)
}
#endif

#define CF_MYSQL_STATE_INIT         1
#define CF_MYSQL_STATE_WAIT         2
#define CF_MYSQL_STATE_RESULT		3
#define CF_MYSQL_STATE_ERROR		4
#define CF_MYSQL_STATE_DONE         5
#define CF_MYSQL_STATE_COMPLETE     6

#endif // __CF_MYSQL_H_

