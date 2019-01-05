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

  LINK_LIBRARIES
  vppinfra svm vlibmemoryclient rt pthread

  DEPENDS
  api_headers
)

add_vpp_library(vcl_ldpreload
  SOURCES
  ldp_socket_wrapper.c
  ldp.c

  LINK_LIBRARIES
  vppinfra svm vlibmemoryclient rt pthread vppcom dl
)

add_vpp_headers(vcl
  ldp.h
  sock_test.h
  ldp_glibc_socket.h
  vcl_test.h
  vppcom.h
  vcl_locked.h
  ldp_socket_wrapper.h
)

##############################################################################
# vcl tests
##############################################################################
option(VPP_BUILD_VCL_TESTS "Build vcl tests." ON)
if(VPP_BUILD_VCL_TESTS)
  foreach(test
    vcl_test_server
    vcl_test_client
    sock_test_server
    sock_test_client
  )
    add_vpp_executable(${test} SOURCES ${test}.c LINK_LIBRARIES vppcom pthread
		       NO_INSTALL)
  endforeach()
endif(VPP_BUILD_VCL_TESTS)

