# Simple CMakeLists.txt to build LuaSha1 as either a static library (assuming Lua is a static library as well) or a dynamic library
cmake_minimum_required(VERSION 3.8)
project (LuaSha1 CXX)

# We need C++17 features:
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)


if(MSVC)
	add_definitions(-D_CRT_SECURE_NO_DEPRECATE)
	add_definitions(-D_CRT_NONSTDC_NO_DEPRECATE)
endif()





# Static library:
add_library(LuaSha1-static STATIC
	LuaSha1.cpp
	LuaSha1.h
)

target_link_libraries(LuaSha1-static
	lua-static
)

target_include_directories(LuaSha1-static
	SYSTEM INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
)





# Dynamic library:
add_library(LuaSha1 SHARED
	LuaSha1.cpp
	LuaSha1.h
)

target_link_libraries(LuaSha1
	lua
)

target_include_directories(LuaSha1
	SYSTEM INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}
)
