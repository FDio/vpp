find_path(LUA54_INCLUDE_DIR NAMES lua.h PATH_SUFFIXES lua5.4)
find_library(LUA54_LIBRARY NAMES lua5.4 lua54)

if (NOT LUA54_INCLUDE_DIR OR NOT LUA54_LIBRARY)
  message(WARNING "-- liblua5.4 headers or library not found - lua plugin disabled")
  return()
endif()

message(STATUS "lua plugin needs liblua5.4 - include dir: ${LUA54_INCLUDE_DIR}, library: ${LUA54_LIBRARY}")


add_compile_options(-Wmissing-prototypes)
add_compile_options(-Wmissing-declarations)

add_vpp_plugin(lua
  SOURCES
  lua.c
  main.c
  LINK_LIBRARIES
  ${LUA54_LIBRARY}
)

target_include_directories(lua_plugin PRIVATE ${LUA54_INCLUDE_DIR})
