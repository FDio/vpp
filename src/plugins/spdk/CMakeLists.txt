# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026

option(VPP_BUILD_SPDK_PLUGIN "Build the SPDK-in-VPP plugin." OFF)
set(SPDK_ROOT "" CACHE PATH "SPDK source/build tree used by the spdk plugin")
set(SPDK_LINK_LIBRARIES "" CACHE STRING
  "Additional libraries required by SPDK")
set(SPDK_PKG_CONFIG_MODULES
  "spdk_event;spdk_event_nvmf;spdk_bdev_modules;spdk_accel_modules;spdk_sock_modules;spdk_keyring_modules;spdk_scheduler_dynamic;spdk_env_dpdk;spdk_env_dpdk_rpc;spdk_syslibs;libdpdk"
  CACHE STRING "pkg-config modules used to link SPDK into the plugin")
set(SPDK_PKG_CONFIG_PATH "${SPDK_ROOT}/build/lib/pkgconfig" CACHE PATH
  "pkg-config directory for the SPDK build")
set(SPDK_DPDK_PKG_CONFIG_PATH "${SPDK_ROOT}/dpdk/build/lib/pkgconfig" CACHE PATH
  "pkg-config directory for the DPDK build used by SPDK")

if(NOT VPP_BUILD_SPDK_PLUGIN)
  return()
endif()

if(NOT SPDK_ROOT)
  message(WARNING "spdk plugin disabled: set -DSPDK_ROOT=/path/to/spdk")
  return()
endif()

find_path(SPDK_INCLUDE_DIR
  NAMES spdk/event.h spdk/sock.h spdk_internal/sock_module.h
  HINTS ${SPDK_ROOT}/include
  NO_DEFAULT_PATH
)

if(NOT SPDK_INCLUDE_DIR)
  message(WARNING "spdk plugin disabled: SPDK headers not found under ${SPDK_ROOT}/include")
  return()
endif()

set(SPDK_LIB_DIR "${SPDK_ROOT}/build/lib")

find_program(PKG_CONFIG_EXECUTABLE pkg-config)

if(PKG_CONFIG_EXECUTABLE AND EXISTS "${SPDK_PKG_CONFIG_PATH}/spdk_event_nvmf.pc" AND
   EXISTS "${SPDK_DPDK_PKG_CONFIG_PATH}/libdpdk.pc")
  set(_spdk_saved_pkg_config_path "$ENV{PKG_CONFIG_PATH}")
  if(_spdk_saved_pkg_config_path)
    set(ENV{PKG_CONFIG_PATH}
      "${SPDK_PKG_CONFIG_PATH}:${SPDK_DPDK_PKG_CONFIG_PATH}:$ENV{PKG_CONFIG_PATH}")
  else()
    set(ENV{PKG_CONFIG_PATH} "${SPDK_PKG_CONFIG_PATH}:${SPDK_DPDK_PKG_CONFIG_PATH}")
  endif()
  execute_process(
    COMMAND ${PKG_CONFIG_EXECUTABLE} --libs --static ${SPDK_PKG_CONFIG_MODULES}
    OUTPUT_VARIABLE _spdk_pkg_libs
    OUTPUT_STRIP_TRAILING_WHITESPACE
    RESULT_VARIABLE _spdk_pkg_result
  )
  set(ENV{PKG_CONFIG_PATH} "${_spdk_saved_pkg_config_path}")
  if(NOT _spdk_pkg_result EQUAL 0)
    message(WARNING "spdk plugin disabled: pkg-config could not resolve SPDK modules")
    return()
  endif()

  separate_arguments(_spdk_pkg_libs UNIX_COMMAND "${_spdk_pkg_libs}")
else()
  message(WARNING "spdk plugin disabled: build SPDK first or set SPDK pkg-config paths")
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
  elseif(_spdk_lib MATCHES "^-lrte_")
    # libdpdk.pc emits static -l:librte_*.a entries first, followed by dynamic
    # -lrte_* fallbacks. Keep the static archives and avoid DT_NEEDED on DPDK.
    continue()
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
)
