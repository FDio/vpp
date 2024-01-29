# Copyright (c) 2018-2019 Cisco and/or its affiliates.
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
# FreeBSD - use epoll-shim
##############################################################################
set(FREEBSD_LIBS "")
if("${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
  find_path(EPOLL_SHIM_INCLUDE_DIR NAMES sys/epoll.h HINTS /usr/local/include/libepoll-shim)
  find_library(EPOLL_SHIM_LIB NAMES epoll-shim HINTS /usr/local/lib)

  if(EPOLL_SHIM_INCLUDE_DIR AND EPOLL_SHIM_LIB)
    message(STATUS "Found epoll-shim in ${EPOLL_SHIM_INCLUDE_DIR}")
    include_directories(${EPOLL_SHIM_INCLUDE_DIR})
    string(JOIN " " FREEBSD_LIBS "${EPOLL_SHIM_LIB}")
  endif()
endif()

##############################################################################
# vppcom shared library
##############################################################################
add_vpp_library(vppcom
  SOURCES
  vppcom.c
  vcl_bapi.c
  vcl_cfg.c
  vcl_private.c
  vcl_locked.c
  vcl_sapi.c

  LINK_LIBRARIES
  vppinfra svm vlibmemoryclient rt pthread

  DEPENDS
  api_headers
)

option(LDP_HAS_GNU_SOURCE "LDP configured to use _GNU_SOURCE" ON)
if (LDP_HAS_GNU_SOURCE)
  add_compile_definitions(HAVE_GNU_SOURCE)
endif(LDP_HAS_GNU_SOURCE)

add_vpp_library(vcl_ldpreload
  SOURCES
  ldp_socket_wrapper.c
  ldp.c

  LINK_LIBRARIES
  vppinfra svm vlibmemoryclient rt pthread vppcom dl
)

add_vpp_headers(vcl
  ldp.h
  ldp_glibc_socket.h
  vppcom.h
  vcl_locked.h
  ldp_socket_wrapper.h
)