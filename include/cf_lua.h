// cf_lua.h

#ifndef __CF_LUA_H_
#define __CF_LUA_H_

#if defined(__cplusplus)
extern "C" {
#endif


void cf_lua_init(void);
void cf_lua_cleanup(void);

extern struct cf_module_functions	cf_lua_module;
extern struct cf_runtime            cf_lua_runtime;


#if defined(__cplusplus)
}
#endif

#endif /* __CF_LUA_H_ */
