// pgsql-sync.c

#include <zfrog.h>
#include <cf_http.h>
#include <cf_pgsql.h>

int	init(int);
int	page(struct http_request *);

/* Called when our module is loaded (see config) */
int init( int state )
{
    /* Register our database */
    cf_pgsql_register("db", "host=/tmp dbname=test");

    return CF_RESULT_OK;
}

/* Page handler entry point (see config) */
int page( struct http_request *req )
{
    struct cf_pgsql sql;
    char *name = NULL;
    int	rows, i;

	req->status = HTTP_STATUS_INTERNAL_ERROR;

    cf_pgsql_init(&sql);

	/*
     * Initialise our cf_pgsql data structure with the database name
	 * we want to connect to (note that we registered this earlier with
     * cf_pgsql_register()). We also say we will perform a synchronous
     * query (CF_PGSQL_SYNC) and we do not need to pass our http_request
	 * so we pass NULL instead.
	 */
    if( !cf_pgsql_setup(&sql, "db", CF_PGSQL_SYNC) )
    {
        cf_pgsql_logerror(&sql);
		goto out;
	}

	/*
	 * Now we can fire off the query, once it returns we either have
     * a result on which we can operate or an error occured
	 */
    if( !cf_pgsql_query(&sql, "SELECT * FROM coders") )
    {
        cf_pgsql_logerror(&sql);
		goto out;
	}

	/*
     * Iterate over the result and dump it to somewhere
	 */
    rows = cf_pgsql_ntuples(&sql);
    for( i = 0; i < rows; i++ )
    {
        name = cf_pgsql_getvalue(&sql, i, 0);
        cf_log(LOG_NOTICE, "name: '%s'", name);
	}

	req->status = HTTP_STATUS_OK;

out:
	http_response(req, req->status, NULL, 0);

    /* Don't forget to cleanup the cf_pgsql data structure */
    cf_pgsql_cleanup(&sql);

    return CF_RESULT_OK;
}
