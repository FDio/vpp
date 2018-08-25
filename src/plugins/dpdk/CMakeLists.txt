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
find_path(DPDK_INCLUDE_DIR PATH_SUFFIXES dpdk NAMES rte_config.h HINTS
	  ${DPDK_INCLUDE_DIR_HINT})
find_library(DPDK_LIB NAMES libdpdk.a HINTS ${DPDK_LIB_DIR_HINT})

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
# DPDK plugin
##############################################################################
if(DPDK_INCLUDE_DIR AND DPDK_LIB)
  include_directories (${DPDK_INCLUDE_DIR})

  message(STATUS "Found DPDK ${DPDK_VERSION} in ${DPDK_INCLUDE_DIR}")
  get_filename_component(DPDK_LIB_DIR ${DPDK_LIB} DIRECTORY)
  set(DPDK_LINK_FLAGS "-L${DPDK_LIB_DIR} -Wl,--whole-archive,${DPDK_LIB},--no-whole-archive")
  if(DPDK_RTE_LIBRTE_PMD_AESNI_MB OR DPDK_RTE_LIBRTE_PMD_AESNI_GCM)
    set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,--exclude-libs,libIPSec_MB.a,-l:libIPSec_MB.a")
    message(STATUS "DPDK depends on IPSec MB library")
  endif()
  set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,-lnuma")
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

    API_FILES
    api/dpdk.api

    LINK_FLAGS
    ${DPDK_LINK_FLAGS}
  )
else()
  message(WARNING "DPDK not found - dpdk disabled")
endif()

