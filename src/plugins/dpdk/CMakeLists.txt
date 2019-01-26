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
# macros
##############################################################################
macro(dpdk_find_library var name)
  find_library(${var} NAMES ${name} ${ARGN})
if (NOT ${var})
  message(WARNING "-- ${name} library not found - dpdk_plugin disabled")
  return()
endif()
    message(STATUS "DPDK plugin needs ${name} library - found at ${${var}}")
endmacro()

##############################################################################
# Find lib and include files
##############################################################################
find_path(DPDK_INCLUDE_DIR PATH_SUFFIXES dpdk NAMES rte_config.h)
find_library(DPDK_LIB NAMES libdpdk.a)

if (NOT DPDK_INCLUDE_DIR)
  message(WARNING "-- DPDK headers not found - dpdk_plugin disabled")
  return()
endif()

if (NOT DPDK_LIB)
  dpdk_find_library(DPDK_SHLIB "libdpdk.so")
  set(DPDK_IS_SHARED_LIB 1)
  message(WARNING "-- linking dpdk plugin against DPDK shared libs")
endif()

##############################################################################
# Find DPDK Version
##############################################################################
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dpdk_vars.c
"
#include <stdio.h>
#include <rte_version.h>
int main()
{
  printf(\"VERSION=%s\\n\", strchr(rte_version(), ' ') + 1);
  printf(\"RTE_PKTMBUF_HEADROOM=%u\\n\", RTE_PKTMBUF_HEADROOM);
#ifdef RTE_LIBRTE_PMD_AESNI_MB
  printf(\"RTE_LIBRTE_PMD_AESNI_MB=%u\\n\", RTE_LIBRTE_PMD_AESNI_MB);
#endif
#ifdef RTE_LIBRTE_PMD_AESNI_GCM
  printf(\"RTE_LIBRTE_PMD_AESNI_GCM=%u\\n\", RTE_LIBRTE_PMD_AESNI_GCM);
#endif
#ifdef RTE_LIBRTE_MLX4_PMD
  printf(\"RTE_LIBRTE_MLX4_PMD=%u\\n\", RTE_LIBRTE_MLX4_PMD);
#endif
#ifdef RTE_LIBRTE_MLX5_PMD
  printf(\"RTE_LIBRTE_MLX5_PMD=%u\\n\", RTE_LIBRTE_MLX5_PMD);
#ifdef RTE_LIBRTE_MLX5_DLOPEN_DEPS
  printf(\"RTE_LIBRTE_MLX5_DLOPEN_DEPS=%u\\n\", RTE_LIBRTE_MLX5_DLOPEN_DEPS);
#endif
#endif
  return 0;
}
")

try_compile(DPDK_VARS_COMPILED
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}/dpdk_vars.c
  CMAKE_FLAGS
  -DINCLUDE_DIRECTORIES=${DPDK_INCLUDE_DIR}
  COPY_FILE ${CMAKE_CURRENT_BINARY_DIR}/dpdk_vars.bin
)

if(DPDK_VARS_COMPILED)
  execute_process(
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ./dpdk_vars.bin
    OUTPUT_VARIABLE DPDK_VARS
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  string(REPLACE "\n" ";" DPDK_VARS ${DPDK_VARS})
  foreach(v ${DPDK_VARS})
    string(REPLACE "=" ";" v ${v})
    list(GET v 0 name)
    list(GET v 1 value)
    set(DPDK_${name} ${value})
  endforeach()
endif()

file(REMOVE
  ${CMAKE_CURRENT_BINARY_DIR}/dpdk_vars.c
  ${CMAKE_CURRENT_BINARY_DIR}/dpdk_vars.bin
)

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
dpdk_find_library(NUMA_LIB "numa")
list(APPEND DPDK_LINK_LIBRARIES ${NUMA_LIB})

##############################################################################
# AESNI libraries
##############################################################################
if(DPDK_RTE_LIBRTE_PMD_AESNI_MB OR DPDK_RTE_LIBRTE_PMD_AESNI_GCM)
  if(DPDK_IS_SHARED_LIB)
    dpdk_find_library(IPSECMB_LIB "libIPSec_MB.so")
    list(APPEND DPDK_LINK_LIBRARIES "${IPSECMB_LIB}")
  else()
    dpdk_find_library(IPSECMB_LIB "libIPSec_MB.a")
    get_filename_component(IPSECMB_LIB_DIR ${IPSECMB_LIB} DIRECTORY)
    string_append(DPDK_LINK_FLAGS "-L${IPSECMB_LIB_DIR}")
    string_append(DPDK_LINK_FLAGS "-Wl,--exclude-libs,libIPSec_MB.a,-l:libIPSec_MB.a")
  endif()
endif()

##############################################################################
# Mellanox libraries
##############################################################################
if(DPDK_RTE_LIBRTE_MLX4_PMD OR DPDK_RTE_LIBRTE_MLX5_PMD)
  dpdk_find_library(MNL_LIB "mnl")
  list(APPEND DPDK_LINK_LIBRARIES "${MNL_LIB}")
  if (DPDK_RTE_LIBRTE_MLX5_DLOPEN_DEPS)
    message(STATUS "DPDK depends on libmnl (Mellanox PMD requirement)")
  else()
    dpdk_find_library(IBVERBS_LIB "ibverbs")
    list(APPEND DPDK_LINK_LIBRARIES "${IBVERBS_LIB}")
    dpdk_find_library(MLX5_LIB "mlx5")
    list(APPEND DPDK_LINK_LIBRARIES "${MLX5_LIB}")
    message(STATUS "DPDK depends on libmnl, libibverbs, libmlx5 (Mellanox PMD requirement)")
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
  api/dpdk_api.c
  api/dpdk_test.c
  device/cli.c
  device/common.c
  device/device.c
  device/flow.c
  device/format.c
  device/init.c
  device/node.c
  hqos/hqos.c
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

  API_FILES
  api/dpdk.api

  API_TEST_SOURCES
  api/dpdk_test.c

  INSTALL_HEADERS
  device/dpdk.h
  api/dpdk_all_api_h.h
  ipsec/ipsec.h

  LINK_FLAGS
  "${DPDK_LINK_FLAGS}"

  LINK_LIBRARIES
  ${DPDK_LINK_LIBRARIES}

  COMPONENT
  vpp-plugin-dpdk
)

