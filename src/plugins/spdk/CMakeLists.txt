# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026

option(VPP_BUILD_SPDK_PLUGIN "Build the SPDK-in-VPP plugin." ON)
set(SPDK_LINK_LIBRARIES "" CACHE STRING
  "Additional libraries required by SPDK")
set(SPDK_PKG_CONFIG_MODULES
  "spdk_event;spdk_event_nvmf;spdk_bdev_modules;spdk_accel_modules;spdk_sock_modules;spdk_keyring_modules;spdk_scheduler_dynamic;spdk_syslibs"
  CACHE STRING "pkg-config modules used to link SPDK into the plugin")

if(NOT VPP_BUILD_SPDK_PLUGIN)
  return()
endif()

vpp_find_path(SPDK_INCLUDE_DIR
  NAMES spdk/event.h spdk/sock.h spdk_internal/sock_module.h
)

if(NOT SPDK_INCLUDE_DIR)
  message(WARNING "-- SPDK headers not found - spdk plugin disabled")
  return()
endif()

vpp_plugin_find_library(spdk SPDK_EVENT_LIBRARY "libspdk_event.a")
get_filename_component(SPDK_LIB_DIR "${SPDK_EVENT_LIBRARY}" DIRECTORY)
set(SPDK_PKG_CONFIG_PATH "${SPDK_LIB_DIR}/pkgconfig")

find_program(PKG_CONFIG_EXECUTABLE pkg-config)

if(PKG_CONFIG_EXECUTABLE AND EXISTS "${SPDK_PKG_CONFIG_PATH}/spdk_event_nvmf.pc")
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E env
      "PKG_CONFIG_PATH=${SPDK_PKG_CONFIG_PATH}:$ENV{PKG_CONFIG_PATH}"
      ${PKG_CONFIG_EXECUTABLE} --libs --static ${SPDK_PKG_CONFIG_MODULES}
    OUTPUT_VARIABLE _spdk_pkg_libs
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE _spdk_pkg_result
  )
  if(NOT _spdk_pkg_result EQUAL 0)
    message(WARNING "spdk plugin disabled: pkg-config could not resolve SPDK modules")
    return()
  endif()

  separate_arguments(_spdk_pkg_libs UNIX_COMMAND "${_spdk_pkg_libs}")
else()
  message(WARNING "spdk plugin disabled: installed SPDK pkg-config files not found")
  return()
endif()

set(SPDK_ARCHIVES)
set(SPDK_PKG_LINK_LIBRARIES)

foreach(_spdk_lib IN LISTS _spdk_pkg_libs)
  if(_spdk_lib MATCHES "^-lspdk_(.+)$")
    set(_spdk_archive "${SPDK_LIB_DIR}/libspdk_${CMAKE_MATCH_1}.a")
    if(EXISTS "${_spdk_archive}")
      list(APPEND SPDK_ARCHIVES "${_spdk_archive}")
    else()
      list(APPEND SPDK_PKG_LINK_LIBRARIES "${_spdk_lib}")
    endif()
  else()
    list(APPEND SPDK_PKG_LINK_LIBRARIES "${_spdk_lib}")
  endif()
endforeach()

list(REMOVE_DUPLICATES SPDK_ARCHIVES)
list(APPEND SPDK_PKG_LINK_LIBRARIES ${SPDK_LINK_LIBRARIES})

if(NOT SPDK_ARCHIVES)
  message(WARNING "spdk plugin disabled: no SPDK archives selected from pkg-config")
  return()
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${SPDK_INCLUDE_DIR})

add_vpp_plugin(spdk
  SOURCES
  spdk_plugin.c
  spdk_vpp_env.c
  spdk_vpp_sock.c

  LINK_LIBRARIES
  -Wl,--whole-archive
  ${SPDK_ARCHIVES}
  -Wl,--no-whole-archive
  ${SPDK_PKG_LINK_LIBRARIES}
  pthread
  dl
  uuid
  numa
  aio
  ssl
  crypto
  m
  rt

  SUPPORTED_OS_LIST
  Linux
)
