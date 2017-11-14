// redis_cb.c

#include <zfrog.h>
#include <cf_http.h>
#include <cf_redis.h>

void connection_del(struct connection *c);
void connection_new(struct connection *);

void db_state_change(struct cf_redis *, void *);
void db_init(struct connection *, struct cf_redis *);
void db_results(struct cf_redis *, struct connection *);

void connection_new( struct connection *c )
{
    struct cf_redis	*redis = NULL;

	c->disconnect = connection_del;
	c->proto = CONN_PROTO_UNKNOWN;
	c->state = CONN_STATE_ESTABLISHED;

    redis = mem_calloc(1, sizeof(*redis));


    printf("cf_redis_init\n");

    cf_redis_init( redis );
    cf_redis_bind_callback(redis, db_state_change, c);

    c->hdlr_extra = redis;
	printf("new connection %p\n", (void *)c);

    db_init(c, redis);
}

void db_init( struct connection *c, struct cf_redis *redis )
{
    if( !cf_redis_setup(redis, "db", CF_REDIS_ASYNC) )
    {
        if( redis->state == CF_REDIS_STATE_INIT )
        {
            printf("\twaiting for available redis connection\n");
			return;
		}

        cf_redis_logerror(redis);
        cf_connection_disconnect(c);
		return;
	}

	printf("\tgot pgsql connection\n");

#ifdef MMM
    if( !cf_pgsql_query(pgsql, "SELECT * FROM coders, pg_sleep(5)") )
    {
        cf_redis_logerror(redis);
        cf_connection_disconnect(c);
		return;
	}
#endif

	printf("\tquery fired off!\n");
}

void connection_del( struct connection *c )
{
	printf("%p: disconnecting\n", (void *)c);

    if( c->hdlr_extra != NULL )
        cf_redis_cleanup(c->hdlr_extra);

    mem_free(c->hdlr_extra);
	c->hdlr_extra = NULL;
}

void db_state_change( struct cf_redis *redis, void *arg )
{
    struct connection *c = arg;

    printf("%p: state change on redis %d\n", arg, redis->state);

    switch( redis->state )
    {
    case CF_REDIS_STATE_INIT:
        db_init(c, redis);
		break;
    case CF_REDIS_STATE_WAIT:
		break;
    case CF_REDIS_STATE_COMPLETE:
        cf_connection_disconnect(c);
		break;
    case CF_REDIS_STATE_ERROR:
        cf_redis_logerror( redis );
        cf_connection_disconnect(c);
		break;
    case CF_REDIS_STATE_RESULT:
        db_results(redis, c);
		break;
	default:
        cf_redis_continue( redis );
		break;
	}
}

void db_results( struct cf_redis *redis, struct connection *c )
{
    char *name = NULL;
    int	i, rows;

//    rows = cf_pgsql_ntuples(pgsql);

    for( i = 0; i < rows; i++ )
    {
  //      name = cf_pgsql_getvalue(pgsql, i, 0);
		net_send_queue(c, name, strlen(name));
	}

	net_send_flush(c);
    cf_redis_continue( redis );
}
