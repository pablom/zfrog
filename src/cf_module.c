// cf_module.c

#include <sys/stat.h>
#include <dlfcn.h>

#include "zfrog.h"

#ifdef CF_PYTHON
    #include "cf_python.h"
#endif

#ifdef CF_LUA
    #include "cf_lua.h"
#endif

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

static TAILQ_HEAD(, cf_module)  modules;

static void	native_free(struct cf_module*);
static void	native_reload(struct cf_module*);
static void	native_load(struct cf_module*);
static void	*native_getsym(struct cf_module*, const char*);

struct cf_module_functions cf_native_module =
{
    .free = native_free,
    .load = native_load,
    .getsym = native_getsym,
    .reload = native_reload,
};

void cf_module_init(void)
{
    TAILQ_INIT( &modules );
}

void cf_module_cleanup(void)
{
    struct cf_module *module, *next;

    for( module = TAILQ_FIRST(&modules); module != NULL; module = next )
    {
        next = TAILQ_NEXT(module, list);
        TAILQ_REMOVE(&modules, module, list);
        module->fun->free(module);
    }
}

void cf_module_load( const char *path, const char *onload, int type )
{
    struct stat	st;
    struct cf_module *module = NULL;

    log_debug("cf_module_load(%s, %s)", path, onload);

    module = mem_malloc(sizeof(struct cf_module));
    module->ocb = NULL;
    module->type = type;
    module->onload = NULL;
    module->handle = NULL;

    if( path != NULL )
    {
        if( stat(path, &st) == -1 )
            cf_fatal("stat(%s): %s", path, errno_s);

        module->path = mem_strdup(path);
        module->mtime = st.st_mtime;
    }
    else
    {
        module->path = NULL;
        module->mtime = 0;
    }

    switch( module->type )
    {
    case CF_MODULE_NATIVE:
        module->fun = &cf_native_module;
        module->runtime = &cf_native_runtime;
        break;
#ifdef CF_PYTHON
    case CF_MODULE_PYTHON:
        module->fun = &cf_python_module;
        module->runtime = &cf_python_runtime;
        break;
#endif
#ifdef CF_LUA
    case CF_MODULE_LUA:
        module->fun = &cf_lua_module;
        module->runtime = &cf_lua_runtime;
        break;
#endif
    default:
        cf_fatal("cf_module_load: unknown type %d", type);
    }

    module->fun->load( module );
    TAILQ_INSERT_TAIL(&modules, module, list);

    if( onload != NULL )
    {
        /* remember the onload callback */
        module->onload = mem_strdup( onload );
        module->ocb = mem_malloc(sizeof(*module->ocb));
        module->ocb->runtime = module->runtime;
        module->ocb->addr = module->fun->getsym(module, onload);

        if( module->ocb->addr == NULL ) {
            cf_fatal("%s: onload '%s' not present", module->path, onload);
        }
    }
}

void cf_module_onload( void )
{
    struct cf_module *module = NULL;

    TAILQ_FOREACH(module, &modules, list)
    {
        if( module->ocb == NULL )
            continue;

        cf_runtime_onload(module->ocb, CF_MODULE_LOAD);
    }
}

void cf_module_reload( int cbs )
{

    struct stat st;
    int	ret;
    struct cf_domain *dom = NULL;
    struct cf_module_handle	*hdlr = NULL;
    struct cf_module *module = NULL;

    TAILQ_FOREACH(module, &modules, list)
    {
        if( stat(module->path, &st) == -1 )
        {
            cf_log(LOG_NOTICE, "stat(%s): %s, skipping reload", module->path, errno_s);
            continue;
        }

        if( module->mtime == st.st_mtime )
        {
            cf_log(LOG_NOTICE, "not reloading %s", module->path);
            continue;
        }

        if( module->ocb != NULL && cbs == 1 )
        {
            ret = cf_runtime_onload(module->ocb, CF_MODULE_UNLOAD);
            if( ret == CF_RESULT_ERROR )
            {
                cf_log(LOG_NOTICE,"not reloading %s", module->path);
                continue;
            }
        }

        module->mtime = st.st_mtime;
        module->fun->reload(module);

        if( module->onload != NULL )
        {
            mem_free(module->ocb);
            module->ocb = mem_malloc(sizeof(*module->ocb));
            module->ocb->runtime = module->runtime;
            module->ocb->addr = module->fun->getsym(module, module->onload);

            if( module->ocb->addr == NULL )
            {
                cf_fatal("%s: onload '%s' not present", module->path, module->onload);
            }
        }

        if( module->ocb != NULL && cbs == 1 )
            cf_runtime_onload(module->ocb, CF_MODULE_LOAD);

        cf_log(LOG_NOTICE, "reloaded '%s' module", module->path);
    }

    TAILQ_FOREACH(dom, &server.domains, list)
    {
        TAILQ_FOREACH(hdlr, &(dom->handlers), list)
        {
            mem_free(hdlr->rcall);
            hdlr->rcall = cf_runtime_getcall(hdlr->func);
            if( hdlr->rcall == NULL )
                cf_fatal("no function '%s' found", hdlr->func);
            hdlr->errors = 0;
        }
    }

#ifndef CF_NO_HTTP
    cf_validator_reload();
#endif
}

int cf_module_loaded( void )
{
    if( TAILQ_EMPTY(&modules) )
        return 0;

    return 1;
}

#ifndef CF_NO_HTTP
int cf_module_handler_new(const char *path, const char *domain, const char *func, const char *auth, int type)
{
    struct cf_auth *ap = NULL;
    struct cf_domain *dom = NULL;
    struct cf_module_handle *hdlr = NULL;

    log_debug("cf_module_handler_new(%s, %s, %s, %s, %d)", path, domain, func, auth, type);

    if( (dom = cf_domain_lookup(domain)) == NULL )
        return CF_RESULT_ERROR;

    if( auth != NULL )
    {
        if( (ap = cf_auth_lookup(auth)) == NULL )
            cf_fatal("no authentication block '%s' found", auth);
    }
    else {
        ap = NULL;
    }

    hdlr = mem_malloc(sizeof(*hdlr));
    hdlr->auth = ap;
    hdlr->dom = dom;
    hdlr->errors = 0;
    hdlr->type = type;
    hdlr->path = mem_strdup(path);
    hdlr->func = mem_strdup(func);
    hdlr->methods = HTTP_METHOD_ALL;

    TAILQ_INIT(&(hdlr->params));

    if( (hdlr->rcall = cf_runtime_getcall(func)) == NULL )
    {
        cf_module_handler_free(hdlr);
        cf_log(LOG_ERR, "function '%s' not found", func);
        return CF_RESULT_ERROR;
    }

    if( hdlr->type == HANDLER_TYPE_DYNAMIC )
    {
        if( regcomp(&(hdlr->rctx), hdlr->path, REG_EXTENDED | REG_NOSUB) )
        {
            cf_module_handler_free(hdlr);
            log_debug("regcomp() on %s failed", path);
            return CF_RESULT_ERROR;
        }
    }

    TAILQ_INSERT_TAIL(&(dom->handlers), hdlr, list);
    return CF_RESULT_OK;
}

void cf_module_handler_free(struct cf_module_handle *hdlr)
{
    struct cf_handler_params *param = NULL;

    if( hdlr == NULL )
        return;

    if( hdlr->func != NULL )
        mem_free(hdlr->func);

    if( hdlr->path != NULL )
        mem_free(hdlr->path);

    if( hdlr->type == HANDLER_TYPE_DYNAMIC )
        regfree(&(hdlr->rctx));

    /* Drop all validators associated with this handler */
    while( (param = TAILQ_FIRST(&(hdlr->params))) != NULL )
    {
        TAILQ_REMOVE(&(hdlr->params), param, list);
        if( param->name != NULL )
            mem_free(param->name);
        mem_free(param);
    }

    mem_free(hdlr);
}

struct cf_module_handle * cf_module_handler_find(const char *domain, const char *path)
{
    struct cf_domain *dom = NULL;
    struct cf_module_handle	*hdlr = NULL;

    if( (dom = cf_domain_lookup(domain)) == NULL )
        return NULL;

    TAILQ_FOREACH(hdlr, &(dom->handlers), list)
    {
        if( hdlr->type == HANDLER_TYPE_STATIC )
        {
            if( !strcmp(hdlr->path, path) )
                return hdlr;
        }
        else
        {
            if( !regexec(&(hdlr->rctx), path, 0, NULL, 0) )
                return hdlr;
        }
    }

    return NULL;
}
#endif /* CF_NO_HTTP */

void* cf_module_getsym( const char *symbol, struct cf_runtime **runtime )
{
    void *ptr = NULL;
    struct cf_module *module = NULL;

    if( runtime != NULL )
        *runtime = NULL;

    TAILQ_FOREACH(module, &modules, list)
    {
        ptr = module->fun->getsym(module, symbol);
        if( ptr != NULL )
        {
            if( runtime != NULL )
                *runtime = module->runtime;
            return ptr;
        }
    }

    return NULL;
}

static void * native_getsym( struct cf_module *module, const char *symbol )
{
    return dlsym(module->handle, symbol);
}

static void native_free( struct cf_module *module )
{
    mem_free(module->path);
    dlclose(module->handle);
    mem_free(module);
}

static void native_reload( struct cf_module *module )
{
    if( dlclose(module->handle) )
        cf_fatal("cannot close existing module: %s", dlerror());
    module->fun->load( module );
}

static void native_load( struct cf_module *module )
{
    module->handle = dlopen(module->path, RTLD_NOW | RTLD_GLOBAL);
    if( module->handle == NULL )
        cf_fatal("%s: %s", module->path, dlerror());
}
