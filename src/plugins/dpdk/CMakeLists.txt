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
pkg_check_modules(DPDK libdpdk>=20.08)

if (NOT DPDK_FOUND)
  message(WARNING "-- DPDK headers not found - dpdk plugin disabled")
  return()
endif()

##############################################################################
# Parse DPDK config and version header files
##############################################################################
file(STRINGS ${DPDK_INCLUDE_DIRS}/rte_config.h rte_config)
file(STRINGS ${DPDK_INCLUDE_DIRS}/rte_version.h rte_version)
file(STRINGS ${DPDK_INCLUDE_DIRS}/rte_build_config.h rte_build_config)

foreach(l ${rte_config} ${rte_build_config} ${rte_version}})
  if (l MATCHES "^#define[\t ]*RTE_")
    STRING(REGEX REPLACE "^#define[\t ]*([A-Z1-9_]+)[\t ]*(.+)" "\\1;\\2" v "${l}")
    list(GET v 0 name)
    list(GET v 1 value)
    set(DPDK_${name} ${value})
  endif()
endforeach()

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
# static linking
##############################################################################
unset(DPDK_LINK_LIBRARIES)
unset(DPDK_LINK_FLAGS)
message(STATUS "Found DPDK ${DPDK_VERSION} in ${DPDK_INCLUDE_DIRS}")
include_directories (${DPDK_INCLUDE_DIRS})
list(JOIN DPDK_STATIC_LDFLAGS " " DPDK_LINK_FLAGS)

##############################################################################
# DPDK plugin
##############################################################################

if (${DPDK_VERSION} VERSION_GREATER_EQUAL "20.8.0")
  set(DPDK_CRYPTODEV_SOURCE cryptodev_dp_api)
else ()
  set(DPDK_CRYPTODEV_SOURCE cryptodev)
endif ()

add_vpp_plugin(dpdk
  SOURCES
  buffer.c
  main.c
  thread.c
  device/cli.c
  device/common.c
  device/device.c
  device/flow.c
  device/format.c
  device/init.c
  device/node.c
  ipsec/cli.c
  ipsec/crypto_node.c
  ipsec/esp_decrypt.c
  ipsec/esp_encrypt.c
  ipsec/ipsec.c
  cryptodev/${DPDK_CRYPTODEV_SOURCE}.c

  MULTIARCH_SOURCES
  buffer.c
  device/device.c
  device/node.c
  ipsec/crypto_node.c
  ipsec/esp_decrypt.c
  ipsec/esp_encrypt.c

  INSTALL_HEADERS
  device/dpdk.h
  ipsec/ipsec.h

  LINK_FLAGS
  "${DPDK_LINK_FLAGS}"

  LINK_LIBRARIES
  ${DPDK_LINK_LIBRARIES}

  COMPONENT
  vpp-plugin-dpdk
)
