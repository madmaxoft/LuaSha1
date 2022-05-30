# LuaSha1
Simple public-domain Lua module for calculating SHA-1

This library can be either linked statically to a Lua-enabled application, or into a dynamic library that can be loaded by standalone Lua interpreter. It provides a single API call that calculates the SHA-1 checksum of data:
```lua
local sha1 = require("LuaSha1")

-- Simple hashing:
local hash = sha1.calc("plaintext")

-- If given multiple strings, hashes a concatenation of them:
local hash2 = sha1.calc("plain", "t", "e", "x", "t")
assert(hash == hash2)
```

## Compilation
This library requires a modern C++ (17) compiler and cmake. It has no dependencies on other libraries.

To link to an application statically, add this folder to your app's `CMakeLists.txt` and link your app to `LuaSha1-static`. Note that this assumes that your internal Lua library is named `lua-static` in your CMake file.
```cmake
# In your app's CMakeLists.txt:
add_library(lua-static STATIC
  # Lua interpreter sources go here
)

add_subdirectory(path/to/LuaSha1 EXCLUDE_FROM_ALL)

target_link_libraries(MyApp
  lua-static
  LuaSha1
)
```

Then in your app when you create a Lua_State, open the lib:
```cpp
#include <LuaSha1.h>

// ...

lua_State * L = luaL_newstate();
luaopen_LuaSha1(L);
lua_pop(L, 1);
```

To create the dynamically-loadable library for plain Lua interpreter, simply run CMake and then make the `LuaSha1` target:
```sh
cd path/to/LuaSha1
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make LuaSha1
```
Note that on Windows the resulting DLL file depends on `lua.dll`; if you need a specific Lua version DLL, such as `lua5.1.dll`, you need to provide a proxy DLL that is named `lua.dll` and relays all calls to `lua5.1.dll`.
