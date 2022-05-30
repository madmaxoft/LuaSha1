#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <lua.h>

LUALIB_API int luaopen_LuaSha1(lua_State * aState);

#ifdef __cplusplus
}
#endif
