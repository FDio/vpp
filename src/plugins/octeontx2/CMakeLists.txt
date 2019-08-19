# Copyright (c) 2016 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Copyright (c) 2019 Marvell International Ltd.

##############################################################################
# Find lib and include files
##############################################################################
find_path(OCTEONTX2_INCLUDE_DIR PATH_SUFFIXES dpdk NAMES rte_config.h)
vpp_plugin_find_library(octeontx2 OCTEONTX2_LIB "libmarvelldpdk.a")

if (NOT OCTEONTX2_INCLUDE_DIR)
  message(WARNING "-- OCTEONTX2 headers not found - octeontx2 plugin disabled")
  return()
endif()

if (NOT OCTEONTX2_LIB)
  vpp_plugin_find_library(octeontx2 OCTEONTX2_SHLIB "libmarvelldpdk.so")
  if (OCTEONTX2_SHLIB)
    set(OCTEONTX2_IS_SHARED_LIB 1)
    message(WARNING "-- linking octeontx2 plugin against OCTEONTX2 shared libs")
  endif()
endif()

##############################################################################
# Parse DPDK config and version header files
##############################################################################

file(STRINGS ${OCTEONTX2_INCLUDE_DIR}/rte_config.h rte_config)
file(STRINGS ${OCTEONTX2_INCLUDE_DIR}/rte_version.h rte_version)

foreach(l ${rte_config} ${rte_version})
  if (l MATCHES "^#define[\t ]*RTE_")
    STRING(REGEX REPLACE "^#define[\t ]*([A-Z1-9_]+)[\t ]*(.+)" "\\1;\\2" v "${l}")
    list(GET v 0 name)
    list(GET v 1 value)
    set(OCTEONTX2_${name} ${value})
  endif()
endforeach()

set(OCTEONTX2_VERSION
    "${OCTEONTX2_RTE_VER_YEAR}.${OCTEONTX2_RTE_VER_MONTH}.${OCTEONTX2_RTE_VER_MINOR}")

##############################################################################
# verify headroom size
##############################################################################
if(NOT ${OCTEONTX2_RTE_PKTMBUF_HEADROOM} EQUAL ${PRE_DATA_SIZE})
  message(
    FATAL_ERROR
    "DPDK RTE_PKTMBUF_HEADROOM (${OCTEONTX2_RTE_PKTMBUF_HEADROOM}) "
     "must be equal to PRE_DATA_SIZE (${PRE_DATA_SIZE})"
  )
endif()

##############################################################################
# static or dynamic linking
##############################################################################
unset(OCTEONTX2_LINK_LIBRARIES)
unset(OCTEONTX2_LINK_FLAGS)
message(STATUS "Found Marvell-DPDK ${OCTEONTX2_VERSION} in ${OCTEONTX2_INCLUDE_DIR}")
include_directories (${OCTEONTX2_INCLUDE_DIR})

if(OCTEONTX2_IS_SHARED_LIB)
  get_filename_component(OCTEONTX2_LIB_DIR ${OCTEONTX2_SHLIB} DIRECTORY)
  string_append(OCTEONTX2_LINK_FLAGS "-L${OCTEONTX2_LIB_DIR}")
  list(APPEND OCTEONTX2_LINK_LIBRARIES ${OCTEONTX2_SHLIB})
else()
  get_filename_component(OCTEONTX2_LIB_DIR ${OCTEONTX2_LIB} DIRECTORY)
  string_append(OCTEONTX2_LINK_FLAGS "-L${OCTEONTX2_LIB_DIR}")
  string_append(OCTEONTX2_LINK_FLAGS "-Wl,--whole-archive,${OCTEONTX2_LIB},--no-whole-archive")
endif()

##############################################################################
# libnuma
##############################################################################
vpp_plugin_find_library(octeontx2 NUMA_LIB "numa")
list(APPEND OCTEONTX2_LINK_LIBRARIES ${NUMA_LIB})

##############################################################################
# OCTEONTX2 plugin
##############################################################################
add_vpp_plugin(octeontx2
  SOURCES
  buffer.c
  main.c
  thread.c
  device/cli.c
  device/common.c
  device/device.c
  device/format.c
  device/init.c
  device/node.c

  INSTALL_HEADERS
  device/octeontx2.h

  LINK_FLAGS
  "${OCTEONTX2_LINK_FLAGS}"

  LINK_LIBRARIES
  ${OCTEONTX2_LINK_LIBRARIES}

  COMPONENT
  vpp-plugin-octeontx2
)
