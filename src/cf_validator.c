// cf_validator.c

#include "zfrog.h"

TAILQ_HEAD(, cf_validator) validators;

void cf_validator_init(void)
{
	TAILQ_INIT(&validators);
}

int cf_validator_add(const char *name, uint8_t type, const char *arg)
{
    int ret;
    struct cf_validator *val = mem_malloc(sizeof(*val));

	val->type = type;

    switch( val->type )
    {
    case CF_VALIDATOR_TYPE_REGEX:
        if( (ret = regcomp(&(val->rctx), arg, REG_EXTENDED | REG_NOSUB)) )
        {
            mem_free(val);
            cf_log(LOG_NOTICE, "validator %s has bad regex %s (%d)", name, arg, ret);
            return CF_RESULT_ERROR;
		}
		break;

    case CF_VALIDATOR_TYPE_FUNCTION:
        val->rcall = cf_runtime_getcall( arg );
        if( val->rcall == NULL )
        {
            mem_free(val);
            cf_log(LOG_NOTICE, "validator %s has undefined callback %s", name, arg);
            return CF_RESULT_ERROR;
		}
		break;

	default:
        mem_free( val );
        return CF_RESULT_ERROR;
	}

    val->arg = mem_strdup(arg);
    val->name = mem_strdup(name);
	TAILQ_INSERT_TAIL(&validators, val, list);

    return CF_RESULT_OK;
}

int cf_validator_run(struct http_request *req, const char *name, char *data)
{
    struct cf_validator *val = NULL;

    TAILQ_FOREACH(val, &validators, list)
    {
        if( strcmp(val->name, name) )
			continue;

        return (cf_validator_check(req, val, data));
	}

    return CF_RESULT_ERROR;
}

int cf_validator_check( struct http_request *req, struct cf_validator *val, const void* data )
{
    int	r;

    switch( val->type )
    {
    case CF_VALIDATOR_TYPE_REGEX:
        if( !regexec(&(val->rctx), data, 0, NULL, 0) )
            r = CF_RESULT_OK;
		else
            r = CF_RESULT_ERROR;
		break;
    case CF_VALIDATOR_TYPE_FUNCTION:
        r = cf_runtime_validator(val->rcall, req, data);
		break;
	default:
        r = CF_RESULT_ERROR;
        cf_log(LOG_NOTICE, "invalid type %d for validator %s", val->type, val->name);
		break;
	}

    return r;
}

void cf_validator_reload(void)
{
    struct cf_validator *val = NULL;

    TAILQ_FOREACH(val, &validators, list)
    {
        if( val->type != CF_VALIDATOR_TYPE_FUNCTION )
			continue;

        mem_free(val->rcall);
        val->rcall = cf_runtime_getcall(val->arg);
        if( val->rcall == NULL )
            cf_fatal("no function for validator %s found", val->arg);
	}
}

struct cf_validator* cf_validator_lookup( const char *name )
{
    struct cf_validator *val = NULL;

    TAILQ_FOREACH(val, &validators, list)
    {
        if( !strcmp(val->name, name) )
            return val;
	}

    return NULL;
}
