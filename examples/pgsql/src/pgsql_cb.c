// pgsql_cb.c

#include <zfrog.h>
#include <cf_http.h>
#include <cf_pgsql.h>

void connection_del(struct connection *c);
void connection_new(struct connection *);

void db_state_change(struct cf_pgsql *, void *);
void db_init(struct connection *, struct cf_pgsql *);
void db_results(struct cf_pgsql *, struct connection *);

void connection_new( struct connection *c )
{
    struct cf_pgsql	*pgsql = NULL;

	c->disconnect = connection_del;
	c->proto = CONN_PROTO_UNKNOWN;
	c->state = CONN_STATE_ESTABLISHED;

    pgsql = mem_calloc(1, sizeof(*pgsql));

    cf_pgsql_init(pgsql);
    cf_pgsql_bind_callback(pgsql, db_state_change, c);

	c->hdlr_extra = pgsql;
	printf("new connection %p\n", (void *)c);

	db_init(c, pgsql);
}

void db_init( struct connection *c, struct cf_pgsql *pgsql )
{
    if( !cf_pgsql_setup(pgsql, "db", CF_PGSQL_ASYNC) )
    {
        if( pgsql->state == CF_PGSQL_STATE_INIT )
        {
			printf("\twaiting for available pgsql connection\n");
			return;
		}

        cf_pgsql_logerror(pgsql);
        cf_connection_disconnect(c);
		return;
	}

	printf("\tgot pgsql connection\n");
    if( !cf_pgsql_query(pgsql, "SELECT * FROM coders, pg_sleep(5)") )
    {
        cf_pgsql_logerror(pgsql);
        cf_connection_disconnect(c);
		return;
	}

	printf("\tquery fired off!\n");
}

void connection_del( struct connection *c )
{
	printf("%p: disconnecting\n", (void *)c);

    if( c->hdlr_extra != NULL )
        cf_pgsql_cleanup(c->hdlr_extra);

    mem_free(c->hdlr_extra);
	c->hdlr_extra = NULL;
}

void db_state_change( struct cf_pgsql *pgsql, void *arg )
{
    struct connection *c = arg;

	printf("%p: state change on pgsql %d\n", arg, pgsql->state);

    switch( pgsql->state )
    {
    case CF_PGSQL_STATE_INIT:
		db_init(c, pgsql);
		break;
    case CF_PGSQL_STATE_WAIT:
		break;
    case CF_PGSQL_STATE_COMPLETE:
        cf_connection_disconnect(c);
		break;
    case CF_PGSQL_STATE_ERROR:
        cf_pgsql_logerror(pgsql);
        cf_connection_disconnect(c);
		break;
    case CF_PGSQL_STATE_RESULT:
		db_results(pgsql, c);
		break;
	default:
        cf_pgsql_continue(pgsql);
		break;
	}
}

void db_results( struct cf_pgsql *pgsql, struct connection *c )
{
    char *name = NULL;
    int	i, rows;

    rows = cf_pgsql_ntuples(pgsql);

    for( i = 0; i < rows; i++ )
    {
        name = cf_pgsql_getvalue(pgsql, i, 0);
		net_send_queue(c, name, strlen(name));
	}

	net_send_flush(c);
    cf_pgsql_continue(pgsql);
}
