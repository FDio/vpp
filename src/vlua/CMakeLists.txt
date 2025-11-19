## SPDX-License-Identifier: Apache-2.0
## Copyright (c) 2025 Damjan Marion

option(VPP_LUA "Enable embedding Lua support" ON)

set(VPP_LUA_AVAILABLE FALSE CACHE BOOL "Lua dependency available" FORCE)

if (NOT VPP_LUA)
  message(STATUS "-- Lua support disabled via VPP_LUA=OFF")
  return()
endif()

find_package(Lua 5.3 QUIET)

if (NOT LUA_FOUND)
  message(WARNING "-- Lua headers or library not found - vlua disabled")
  return()
endif()

set(VPP_LUA_AVAILABLE TRUE CACHE BOOL "Lua dependency available" FORCE)

add_compile_options(-Wmissing-prototypes)
add_compile_options(-Wmissing-declarations)
add_definitions(-fvisibility=hidden)

set(VLUA_SOURCES
  core.c
  format.c
  helpers.c
  log.c
  method.c
  ns.c
  scheduler.c
  stats.c
  table.c
  value.c
  stub.c
)

add_vpp_library(vlua
  SOURCES ${VLUA_SOURCES}
  LINK_LIBRARIES ${LUA_LIBRARIES}
  INSTALL_HEADERS vlua.h
  COMPONENT libvlua
  LTO
)

target_include_directories(vlua
  PUBLIC
    ${LUA_INCLUDE_DIR}
)

target_include_directories(vlua_objs
  PRIVATE
    ${LUA_INCLUDE_DIR}
)
