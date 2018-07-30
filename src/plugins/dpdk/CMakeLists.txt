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
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/dpdk_version.c
"
#include <stdio.h>
#include <rte_version.h>
int main()
{
  puts(strchr(rte_version(), ' ') + 1);
  return 0;
}
")

try_compile(DPDK_VERSION_COMPILED
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}/dpdk_version.c
  CMAKE_FLAGS
  -DINCLUDE_DIRECTORIES=${DPDK_INCLUDE_DIR}
  COPY_FILE ${CMAKE_CURRENT_BINARY_DIR}/dpdk_version.bin
)

if(DPDK_VERSION_COMPILED)
  execute_process(
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ./dpdk_version.bin
    OUTPUT_VARIABLE DPDK_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
endif()

file(REMOVE
  ${CMAKE_CURRENT_BINARY_DIR}/dpdk_version.c
  ${CMAKE_CURRENT_BINARY_DIR}/dpdk_version.bin
)


##############################################################################
# DPDK plugin
##############################################################################
if(DPDK_INCLUDE_DIR AND DPDK_LIB)
  include_directories (${DPDK_INCLUDE_DIR})
  add_vpp_plugin(dpdk_plugin
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
    api/dpdk.api
  )

  vpp_library_set_multiarch_sources(dpdk_plugin
    buffer.c
    device/device.c
    device/node.c
  )

  get_filename_component(DPDK_LIB_DIR ${DPDK_LIB} DIRECTORY)
  set(DPDK_LINK_FLAGS "-L${DPDK_LIB_DIR} -Wl,--whole-archive,${DPDK_LIB},--no-whole-archive")
  set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,--exclude-libs,libIPSec_MB.a,-l:libIPSec_MB.a")
  set(DPDK_LINK_FLAGS "${DPDK_LINK_FLAGS} -Wl,-lnuma")
  set_target_properties(dpdk_plugin PROPERTIES LINK_FLAGS "${DPDK_LINK_FLAGS}")
  message("-- Found DPDK ${DPDK_VERSION}: ${DPDK_INCLUDE_DIR} ${DPDK_LIB}")
else()
  message("-- DPDK not found - dpdk_plugin disabled")
endif()

