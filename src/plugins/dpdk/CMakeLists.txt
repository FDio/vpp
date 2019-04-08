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

##############################################################################
# Find lib and include files
##############################################################################
find_path(DPDK_INCLUDE_DIR PATH_SUFFIXES dpdk NAMES rte_config.h)
vpp_plugin_find_library(dpdk DPDK_LIB "libdpdk.a")

if (NOT DPDK_INCLUDE_DIR)
  message(WARNING "-- DPDK headers not found - dpdk plugin disabled")
  return()
endif()

if (NOT DPDK_LIB)
  vpp_plugin_find_library(dpdk DPDK_SHLIB "libdpdk.so")
  set(DPDK_IS_SHARED_LIB 1)
  message(WARNING "-- linking dpdk plugin against DPDK shared libs")
endif()

##############################################################################
# Parse DPDK config and version header files
##############################################################################

file(STRINGS ${DPDK_INCLUDE_DIR}/rte_config.h rte_config)
file(STRINGS ${DPDK_INCLUDE_DIR}/rte_version.h rte_version)

foreach(l ${rte_config} ${rte_version})
  if (l MATCHES "^#define[\t ]*RTE_")
    STRING(REGEX REPLACE "^#define[\t ]*([A-Z1-9_]+)[\t ]*(.+)" "\\1;\\2" v "${l}")
    list(GET v 0 name)
    list(GET v 1 value)
    set(DPDK_${name} ${value})
  endif()
endforeach()

set(DPDK_VERSION
    "${DPDK_RTE_VER_YEAR}.${DPDK_RTE_VER_MONTH}.${DPDK_RTE_VER_MINOR}")

##############################################################################
# verify headroom size
##############################################################################
if(NOT ${DPDK_RTE_PKTMBUF_HEADROOM} EQUAL ${PRE_DATA_SIZE})
  message(
    FATAL_ERROR
    "DPDK RTE_PKTMBUF_HEADROOM (${DPDK_RTE_PKTMBUF_HEADROOM}) "
     "must be equal to PRE_DATA_SIZE (${PRE_DATA_SIZE})"
  )
endif()

##############################################################################
# static or dynamic linking
##############################################################################
unset(DPDK_LINK_LIBRARIES)
unset(DPDK_LINK_FLAGS)
message(STATUS "Found DPDK ${DPDK_VERSION} in ${DPDK_INCLUDE_DIR}")
include_directories (${DPDK_INCLUDE_DIR})

if(DPDK_IS_SHARED_LIB)
  get_filename_component(DPDK_LIB_DIR ${DPDK_SHLIB} DIRECTORY)
  string_append(DPDK_LINK_FLAGS "-L${DPDK_LIB_DIR}")
  list(APPEND DPDK_LINK_LIBRARIES ${DPDK_SHLIB})
else()
  get_filename_component(DPDK_LIB_DIR ${DPDK_LIB} DIRECTORY)
  string_append(DPDK_LINK_FLAGS "-L${DPDK_LIB_DIR}")
  string_append(DPDK_LINK_FLAGS "-Wl,--whole-archive,${DPDK_LIB},--no-whole-archive")
endif()

##############################################################################
# libnuma
##############################################################################
vpp_plugin_find_library(dpdk NUMA_LIB "numa")
list(APPEND DPDK_LINK_LIBRARIES ${NUMA_LIB})

##############################################################################
# AESNI libraries
##############################################################################
if(DPDK_RTE_LIBRTE_PMD_AESNI_MB OR DPDK_RTE_LIBRTE_PMD_AESNI_GCM)
  if(DPDK_IS_SHARED_LIB)
    vpp_plugin_find_library(dpdk IPSECMB_LIB "libIPSec_MB.so")
    list(APPEND DPDK_LINK_LIBRARIES "${IPSECMB_LIB}")
  else()
    vpp_plugin_find_library(dpdk IPSECMB_LIB "libIPSec_MB.a")
    get_filename_component(IPSECMB_LIB_DIR ${IPSECMB_LIB} DIRECTORY)
    string_append(DPDK_LINK_FLAGS "-L${IPSECMB_LIB_DIR}")
    string_append(DPDK_LINK_FLAGS "-Wl,--exclude-libs,libIPSec_MB.a,-l:libIPSec_MB.a")
  endif()
endif()

##############################################################################
# Mellanox libraries
##############################################################################
if(DPDK_RTE_LIBRTE_MLX4_PMD OR DPDK_RTE_LIBRTE_MLX5_PMD)
  vpp_plugin_find_library(dpdk MNL_LIB "mnl")
  list(APPEND DPDK_LINK_LIBRARIES "${MNL_LIB}")
  if (DPDK_RTE_IBVERBS_LINK_DLOPEN)
    message(STATUS "DPDK depends on libmnl (Mellanox PMD requirement)")
  else()
    message(WARNING "unsupported DPDK configuration: DPDK Mellanox PMD requires RTE_IBVERBS_LINK_DLOPEN")
  endif()
endif()

##############################################################################
# DPDK plugin
##############################################################################
add_vpp_plugin(dpdk
  SOURCES
  buffer.c
  main.c
  thread.c
#  api/dpdk_api.c
#  api/dpdk_test.c
  device/cli.c
  device/common.c
  device/device.c
  device/flow.c
  device/format.c
  device/init.c
  device/node.c
#   hqos/hqos.c
  ipsec/cli.c
  ipsec/crypto_node.c
  ipsec/esp_decrypt.c
  ipsec/esp_encrypt.c
  ipsec/ipsec.c

  MULTIARCH_SOURCES
  buffer.c
  device/device.c
  device/node.c
  ipsec/crypto_node.c
  ipsec/esp_decrypt.c
  ipsec/esp_encrypt.c

#  API_FILES
#  api/dpdk.api

#  API_TEST_SOURCES
#  api/dpdk_test.c

  INSTALL_HEADERS
  device/dpdk.h
#  api/dpdk_all_api_h.h
  ipsec/ipsec.h

  LINK_FLAGS
  "${DPDK_LINK_FLAGS}"

  LINK_LIBRARIES
  ${DPDK_LINK_LIBRARIES}

  COMPONENT
  vpp-plugin-dpdk
)

