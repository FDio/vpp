## SPDX-License-Identifier: Apache-2.0
## Copyright (c) 2025 Damjan Marion

add_compile_options(-Wmissing-prototypes)
add_compile_options(-Wmissing-declarations)

set(VLUA_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../vlua)
if (NOT TARGET vlua)
  add_subdirectory(${VLUA_SRC_DIR} ${CMAKE_CURRENT_BINARY_DIR}/vlua)
endif()

if (NOT VPP_LUA_AVAILABLE OR NOT TARGET vlua)
  message(WARNING "-- Lua dependency missing - lua plugin disabled")
  return()
endif()

add_vpp_plugin(lua
  SOURCES
  main.c
  interface.c
  LINK_LIBRARIES
  vlua
)
