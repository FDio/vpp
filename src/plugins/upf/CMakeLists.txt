#
# Copyright (c) 2016 Cisco and/or its affiliates.
# Copyright (c) 2018 Travelping GmbH
#
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
find_library(DPDK_LIB NAMES libdpdk.a)

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
# UPF plugin
##############################################################################

if(DPDK_INCLUDE_DIR AND DPDK_LIB)
  message(STATUS "Looking for liburcu")
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(URCU REQUIRED liburcu-qsbr)

  include_directories (${URCU_INCLUDE_DIRS})
  include_directories (${DPDK_INCLUDE_DIR})

  message(STATUS "Found DPDK ${DPDK_VERSION} in ${DPDK_INCLUDE_DIR}")
  get_filename_component(DPDK_LIB_DIR ${DPDK_LIB} DIRECTORY)
  set(DPDK_LINK_FLAGS "-L${DPDK_LIB_DIR} -Wl,--whole-archive,${DPDK_LIB},--no-whole-archive")
  if(DPDK_RTE_LIBRTE_PMD_AESNI_MB OR DPDK_RTE_LIBRTE_PMD_AESNI_GCM)
    set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,--exclude-libs,libIPSec_MB.a,-l:libIPSec_MB.a")
    message(STATUS "DPDK depends on IPSec MB library")
  endif()
  if(DPDK_RTE_LIBRTE_MLX4_PMD OR DPDK_RTE_LIBRTE_MLX5_PMD)
    set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,-lmnl")
    message(STATUS "DPDK depends on libmnl (Mellanox PMD requirement)")
  endif()
  set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,-lnuma")
  add_vpp_plugin(upf
    SOURCES
    node.c
    upf.c
    upf_api.c
    gtpu_encap.c
    gtpu_decap.c
    upf_if_input.c
    upf_classify.c
    pfcp.c
    upf_pfcp.c
    upf_pfcp_api.c
    upf_pfcp_input.c
    upf_pfcp_server.c

    API_FILES
    upf.api

    INSTALL_HEADERS
    upf.h
    upf_all_api_h.h
    upf_msg_enum.h
    pfcp.h
    upf_pfcp.h
    upf_pfcp_api.h
    upf_pfcp_server.h

    LINK_LIBRARIES
    ${URCU_LIBRARIES}

    LINK_FLAGS
    ${DPDK_LINK_FLAGS}
    ${URCU_LDFLAGS}

    API_TEST_SOURCES
    upf_test.c
  )
else()
  message(WARNING "DPDK not found - GTP UPF disabled")
endif()
