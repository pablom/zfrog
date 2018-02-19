// cf_lua.c


#include <luajit-2.0/lua.h>
#include <luajit-2.0/lualib.h>
#include <luajit-2.0/lauxlib.h>

#include "zfrog.h"
#include "cf_lua.h"

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

#define ALWAYS_INLINE inline __attribute__((always_inline))

struct cf_lua_module
{
    lua_State *L;
};


struct cf_lua_call
{
    struct cf_lua_module *lua_module;
    const char* symbol;
};

static const char *request_metatable_name = "zfg.request";


static void* lua_import( const char * );
//static void* lua_alloc(void *, void *, size_t ,size_t);

static int lua_script_is_function(lua_State *L, const char *name );

/* Helper functions */
static int lua_cf_log( lua_State * );
static void lua_inject_log_api( lua_State * );
static void lua_inject_http_req_api( lua_State * );

static void	lua_module_free(struct cf_module *);
static void	lua_module_reload(struct cf_module *);
static void	lua_module_load(struct cf_module*);
static void	*lua_module_getsym(struct cf_module *, const char *);

static void	lua_runtime_execute(void *);
static int	lua_runtime_onload(void *, int);
static void	lua_runtime_connect(void *, struct connection *);

#ifndef CF_NO_HTTP
    static int	lua_runtime_http_request(void *, struct http_request *);
    static int	lua_runtime_validator(void*, struct http_request*, const void*);
    static void	lua_runtime_wsmessage(void *, struct connection *, uint8_t, const void *, size_t);
#endif

struct cf_module_functions cf_lua_module =
{
    .free = lua_module_free,
    .load = lua_module_load,
    .getsym = lua_module_getsym,
    .reload = lua_module_reload
};

struct cf_runtime cf_lua_runtime =
{
    CF_RUNTIME_LUA,
#ifndef CF_NO_HTTP
    .http_request = lua_runtime_http_request,
    .validator = lua_runtime_validator,
    .wsconnect = lua_runtime_connect,
    .wsmessage = lua_runtime_wsmessage,
    .wsdisconnect = lua_runtime_connect,
#endif
    .onload = lua_runtime_onload,
    .connect = lua_runtime_connect,
    .execute = lua_runtime_execute
};

struct cf_mem_pool lua_lib_pool;
struct cf_mem_pool lua_call_pool;

static lua_State *gL = NULL;

static int req_set_response_cb( lua_State *L );

static const struct luaL_reg request_meta_regs[] = {
    { "response", req_set_response_cb },
/*    { "query_param", req_query_param_cb },
    { "post_param", req_post_param_cb },

    { "say", req_say_cb },
    { "send_event", req_send_event_cb },
    { "cookie", req_cookie_cb },
    { "set_headers", req_set_headers_cb },
*/
    { NULL, NULL }
};

/****************************************************************
 *  Helper function init LUA context
 ****************************************************************/
void cf_lua_init( void )
{
    //lua_State *L = luaL_newstate( lua_alloc, NULL);
    gL = luaL_newstate();
    luaL_openlibs( gL );

    lua_createtable(gL, 0 /* narr */, 116 /* nrec */);    /* ngx.* */

    lua_inject_log_api( gL );
    lua_inject_http_req_api( gL );

    lua_setglobal(gL, "zfg");

    /* Init Lua state memory pool */
    cf_mem_pool_init(&lua_lib_pool, "lua_lib_pool", sizeof(struct cf_lua_module), 100);
    cf_mem_pool_init(&lua_call_pool, "lua_call_pool", sizeof(struct cf_lua_call), 100);
}
/****************************************************************
 *  Helper function cleanup LUA context
 ****************************************************************/
void cf_lua_cleanup(void)
{
    log_debug("cf_lua_cleanup()");
    cf_mem_pool_cleanup(&lua_lib_pool);
    cf_mem_pool_cleanup(&lua_call_pool);

    /* Close global Lua state */
    lua_close( gL );
}
/****************************************************************
 *  Helper function LUA memory allocation/reallocation & free
 ****************************************************************/
#if 0
static void* lua_alloc( void* ud, void* ptr, size_t osize, size_t nsize )
{
    (void)ud;  (void)osize;  /* not used */

    if( nsize == 0 )
    {
        if( ptr )
            mem_free( ptr );
        return NULL;
    }

    if( ptr == NULL )
        return mem_malloc( nsize );

    return mem_realloc(ptr, nsize);
}
#endif
/****************************************************************
 *  Helper function cleanup LUA module
 ****************************************************************/
static void lua_module_free( struct cf_module *module )
{
    mem_free( module->path );
    mem_free( module );
}
/****************************************************************
 *  Helper function reload LUA module
 ****************************************************************/
static void lua_module_reload( struct cf_module *module )
{

}
/****************************************************************
 *  Helper function load LUA module
 ****************************************************************/
static void lua_module_load( struct cf_module *module )
{
    lua_State* L = NULL;
    struct cf_lua_module* lua_module = NULL;

    if( (L = lua_import(module->path)) == NULL )
        cf_fatal("%s: failed to import lua module", module->path);

    /* Allocate lua module structure */
    lua_module = cf_mem_pool_get( &lua_lib_pool );
    lua_module->L = L;
    /* Set result parameter */
    module->handle = lua_module;

/*
    if( onload )
    {
        if( lua_script_is_function( L, onload ) )
        {
            lua_getglobal(L, onload);
            if( lua_pcall(L, 0, 0, 0) != 0 )
                cf_log(LOG_ERR, "Error running function '%s': %s\n", onload, lua_tostring(L, -1) );
        }
    }
*/
}
/****************************************************************
 *  Helper function to find function in module
 ****************************************************************/
static void * lua_module_getsym( struct cf_module *module, const char *symbol )
{
    struct cf_lua_module* lua_module = (struct cf_lua_module*)module->handle;

    if( lua_script_is_function( lua_module->L, symbol ) )
    {
        struct cf_lua_call* lua_call = cf_mem_pool_get( &lua_call_pool );
        lua_call->lua_module = lua_module;
        lua_call->symbol = mem_strdup(symbol);
        return lua_call;
    }

    return NULL;
}
/****************************************************************
 *  Helper function to create Lua module (load script)
 ****************************************************************/
static void* lua_import( const char *path )
{
    lua_State *L = luaL_newstate();

    luaL_openlibs(L);

    luaL_newmetatable(L, request_metatable_name);
    luaL_register(L, NULL, request_meta_regs);
    lua_setfield(L, -1, "__index");

    if( luaL_dofile(L, path) != 0 )
    {
        cf_log( LOG_ERR, "Error opening Lua script %s", lua_tostring(L, -1));
        /* Close Lua state */
        lua_close( L );
        return NULL;
    }

    return L;
}

static int lua_runtime_onload(void *addr, int action)
{

    return CF_RESULT_ERROR;
}

static void lua_runtime_connect(void *addr, struct connection *c)
{

}

static void lua_runtime_execute(void *addr)
{

}

#ifndef CF_NO_HTTP
static int lua_runtime_http_request( void *addr, struct http_request *req )
{
    struct http_request **userdata = NULL;
    struct cf_lua_call* lua_call = (struct cf_lua_call*) addr;
    lua_State* L = lua_call->lua_module->L;

    lua_getglobal( L, lua_call->symbol );

    userdata = lua_newuserdata( L, sizeof(struct http_request *) );
    *userdata = req;

    luaL_getmetatable(L, request_metatable_name);
    lua_setmetatable(L, -2);

     if( lua_pcall(L, 1, 0, 0) )
     {
         cf_log( LOG_ERR, "Error call Lua script %s", lua_tostring(L, -1));
         lua_pop(L, 1);
         return CF_RESULT_ERROR;
     }

    return CF_RESULT_OK;
}

static int lua_runtime_validator( void *addr, struct http_request *req, const void *data )
{

    return CF_RESULT_ERROR;
}

static void lua_runtime_wsmessage(void *addr, struct connection *c, uint8_t op, const void *data, size_t len)
{

}
#endif


/****************************************************************
 *  Helper function inject log functions to LUA scripts
 ****************************************************************/
static int lua_cf_log( lua_State *L )
{
    int level;
    const char *msg;

    level = luaL_checkint(L, 1);

    if( level < LOG_EMERG || level > LOG_DEBUG )
    {
        msg = lua_pushfstring(L, "bad log level: %d", level);
        return luaL_argerror(L, 1, msg);
    }

    /* remove log-level param from stack */
    lua_remove(L, 1);

    return 0;
}
/****************************************************************
 *  Helper function inject log functions to LUA scripts
 ****************************************************************/
static void lua_inject_log_api( lua_State *L )
{
    lua_pushinteger(L, LOG_ERR);
    lua_setfield(L, -2, "LOG_ERR");

    lua_pushinteger(L, LOG_INFO);
    lua_setfield(L, -2, "LOG_INFO");

    lua_pushinteger(L, LOG_NOTICE);
    lua_setfield(L, -2, "LOG_NOTICE");

    lua_pushcfunction(L, lua_cf_log);
    lua_setfield(L, -2, "log");
}
/****************************************************************
 *  Helper function inject log functions to LUA scripts
 ****************************************************************/
static void lua_inject_http_req_api( lua_State *L )
{
    /* ngx.req table */

    lua_createtable(L, 0 /* narr */, 24 /* nrec */);    /* .req */
/*
    ngx_http_lua_inject_req_header_api(L);
    ngx_http_lua_inject_req_uri_api(log, L);
    ngx_http_lua_inject_req_args_api(L);
    ngx_http_lua_inject_req_body_api(L);
    ngx_http_lua_inject_req_socket_api(L);
    ngx_http_lua_inject_req_method_api(L);
    ngx_http_lua_inject_req_time_api(L);
    ngx_http_lua_inject_req_misc_api(L);
*/
    lua_setfield(L, -2, "req");
}
/****************************************************************
 *  Helper function to check LUA function is present
 ****************************************************************/
static int lua_script_is_function( lua_State *L, const char *name )
{
    int is_function = 0;
    lua_getglobal(L, name);
    is_function = lua_isfunction(L, -1);
    lua_pop(L, 1);
    return is_function;
}

static ALWAYS_INLINE struct http_request *userdata_as_request(lua_State *L, int n)
{
    return *((struct http_request **)luaL_checkudata(L, n, request_metatable_name));
}
/****************************************************************
 *  Helper function to check LUA function is present
 ****************************************************************/
static int req_set_response_cb( lua_State *L )
{
#ifndef CF_NO_HTTP
    size_t rs_str_len = 0;
    struct http_request *req = userdata_as_request(L, 1);
    const char *rs_str = lua_tolstring(L, -1, &rs_str_len);

    http_response(req, 200, rs_str, rs_str_len);
#endif
    return 0;
}
