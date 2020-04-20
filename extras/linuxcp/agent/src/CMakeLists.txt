# Copyright (c) 2017 Cisco and/or its affiliates.
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

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/agent/src)
include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_BINARY_DIR}/vpp-api/vapi)

set(EXECUTABLE lcp)

find_library(VPPAPICLIENT_LIB NAMES vppapiclient REQUIRED)
find_path(VPPAPICLIENT_INCLUDE_DIR NAMES vpp-api/client/vppapiclient.h)
find_library(VAPICLIENT_LIB NAMES vapiclient REQUIRED)
find_path(VAPICLIENT_INCLUDE_DIR NAMES vapi/vapi.hpp)
find_library(VPPINFRA_LIB NAMES vppinfra REQUIRED)
find_path(VPPINFRA_INCLUDE_DIR NAMES vppinfra/vec.h)

find_path(JSONC_INCLUDE_DIR NAMES json-c/json.h)
find_library(JSONC_LIB NAMES json-c REQUIRED)

find_path(LIBNL_INCLUDE_DIR netlink/netlink.h
	/usr/include
	/usr/include/libnl3
	/usr/local/include
	/usr/local/include/libnl3
)
find_library(LIBNL_LIB NAMES nl3 nl-3 REQUIRED)
find_library(LIBNL_ROUTE_LIB NAMES nl-route-3 REQUIRED)

include_directories(${VPPAPICLIENT_INCLUDE_DIR})
include_directories(${VAPICLIENT_INCLUDE_DIR})
include_directories(${LIBNL_INCLUDE_DIR})
include_directories(${JSONC_INCLUDE_DIR})

add_executable(${EXECUTABLE}
  lcp_itf_pair.c
  lcp_log.c
  lcp_main.c
  lcp_nl.c
  lcp_ns.c
  lcp_router.c
  vc_conn.c
  vc_itf.c
  vc_keepalive.c
)
add_dependencies(${EXECUTABLE} linuxcp_plugin_api_headers)
target_link_libraries(${EXECUTABLE}
  ${VPPAPICLIENT_LIB}
  ${VAPICLIENT_LIB}
  ${VPPINFRA_LIB}
  ${LIBNL_ROUTE_LIB}
  ${LIBNL_LIB}
  ${JSONC_LIB}
  ${CMAKE_THREAD_LIBS_INIT}
)

install(TARGETS lcp DESTINATION bin COMPONENT lcp)
