# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2021 Cisco Systems, Inc.

find_path(LIBDAQ_INCLUDE_DIR NAMES daq_module_api.h daq_dlt.h daq_version.h)
find_library(LIBDAQ_LINK_LIBRARY NAMES libdaq.a)

if (NOT LIBDAQ_INCLUDE_DIR)
  message(WARNING "-- libdaq headers not found - snort plugin disabled")
  return()
endif()

file(STRINGS ${LIBDAQ_INCLUDE_DIR}/daq_version.h daq_version)
foreach(l ${daq_version})
  if (l MATCHES "^#define[\t ]*DAQ_")
    STRING(REGEX REPLACE "^#define[\t ]*([A-Z1-9_]+)[\t ]*(.+)" "\\1;\\2" v "${l}")
    list(GET v 0 name)
    list(GET v 1 value)
    set(${name} ${value})
  endif()
endforeach()

set(DAQ_VER "${DAQ_VERSION_MAJOR}.${DAQ_VERSION_MINOR}.${DAQ_VERSION_PATCH}")
if (${DAQ_VER} VERSION_LESS "3.0.21")
  message(WARNING "-- libdaq version ${DAQ_VER} is old - required 3.0.21 - snort3 DAQ disabled")
  return()
else()
  message(STATUS "snort plugin needs libdaq ${DAQ_VER} - found at ${LIBDAQ_LINK_LIBRARY}")
endif()

add_vpp_plugin(snort
  SOURCES
  cli.c
  dequeue.c
  enqueue.c
  format.c
  interface.c
  main.c
  snort_api.c
  socket.c

  API_FILES
  snort.api

  INSTALL_HEADERS
  daq_vpp_shared.h
  export.h

  MULTIARCH_SOURCES
  enqueue.c
  dequeue.c

  COMPONENT
  vpp-plugin-snort
)

add_library(daq_vpp SHARED daq/main.c daq/config.c daq/socket.c)
set_target_properties(daq_vpp PROPERTIES SOVERSION ${VPP_LIB_VERSION})
target_compile_options (daq_vpp PRIVATE "-fvisibility=hidden")
target_compile_options (daq_vpp PRIVATE "-DHAVE_VISIBILITY")
target_compile_options (daq_vpp PRIVATE "-I${LIBDAQ_INCLUDE_DIR}")
target_compile_options (daq_vpp PRIVATE "-I${VPP_INCLUDE_DIR}/vpp_plugins")
install(TARGETS daq_vpp DESTINATION ${VPP_LIBRARY_DIR}/daq COMPONENT vpp-plugin-snort)

