# Copyright (c) 2018 Cisco and/or its affiliates.
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

find_path(LIBNL3_INCLUDE_DIR NAMES libnl3/netlink/route/link/vlan.h)
find_path(LIBMNL_INCLUDE_DIR NAMES libmnl/libmnl.h)

if (NOT LIBNL3_INCLUDE_DIR)
  message(WARNING "-- libnl3 headers not found - linux-cp plugin disabled")
  return()
endif()

if (NOT LIBMNL_INCLUDE_DIR)
  message(WARNING "-- libmnl headers not found - linux-cp plugin disabled")
  return()
endif()


vpp_plugin_find_library(linux-cp LIBNL3_LIB libnl-3.so)
vpp_plugin_find_library(linux-cp LIBNL3_ROUTE_LIB libnl-route-3.so.200)
vpp_plugin_find_library(linux-cp LIBMNL_LIB libmnl.so)

include_directories(${LIBNL3_INCLUDE_DIR}/libnl3)
include_directories(${LIBMNL_INCLUDE_DIR})

add_vpp_plugin(linux_cp
  SOURCES
  lcp_api.c
  lcp_cli.c
  lcp_nl.c
  lcp_interface.c
  lcp_node.c
  lcp_routing.c
  lcp_adj.c

  API_FILES
  lcp.api

  API_TEST_SOURCES
  lcp_test.c

  INSTALL_HEADERS
  lcp_nl.h

  LINK_LIBRARIES
  ${LIBNL3_LIB}
  ${LIBNL3_ROUTE_LIB}
  ${LIBMNL_LIB}
)
