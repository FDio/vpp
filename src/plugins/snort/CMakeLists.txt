# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2021 Cisco Systems, Inc.

add_vpp_plugin(snort
  SOURCES
  enqueue.c
  dequeue.c
  main.c
  cli.c

  MULTIARCH_SOURCES
  enqueue.c
  dequeue.c

  COMPONENT
  vpp-plugin-snort
)

# DAQ

find_path(LIBDAQ_INCLUDE_DIR NAMES daq_module_api.h daq_dlt.h daq_version.h)

if (NOT LIBDAQ_INCLUDE_DIR)
  message(WARNING "-- libdaq headers not found - snort3 DAQ disabled")
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
message(STATUS "libdaq ${DAQ_VER} include files found at ${LIBDAQ_INCLUDE_DIR}")

if (NOT DAQ_VERSION_MAJOR MATCHES 3)
  message(WARNING "-- libdaq version not supported - snort3 DAQ disabled")
  return()
endif()

add_library(daq_vpp SHARED daq_vpp.c)
set_target_properties(daq_vpp PROPERTIES SOVERSION ${VPP_LIB_VERSION})
target_compile_options (daq_vpp PRIVATE "-fvisibility=hidden")
target_compile_options (daq_vpp PRIVATE "-DHAVE_VISIBILITY")
target_compile_options (daq_vpp PRIVATE "-I${LIBDAQ_INCLUDE_DIR}")
install(TARGETS daq_vpp DESTINATION ${VPP_LIBRARY_DIR}/daq COMPONENT vpp-plugin-snort)

