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
add_library(vppcom SHARED
  vppcom.c
  vcl_bapi.c
  vcl_cfg.c
  vcl_event.c
  vcl_private.c
)
target_link_libraries(vppcom vppinfra svm vlibmemoryclient rt pthread)
install(TARGETS vppcom DESTINATION lib)

##############################################################################
# vcl headers
##############################################################################
vpp_add_header_files(vcl
  vcl_event.h
  vppcom.h
)

##############################################################################
# vcl tests
##############################################################################
option(VPP_BUILD_VCL_TESTS "Build vcl tests." ON)
if(VPP_BUILD_VCL_TESTS)
  set(VCL_TESTS
    vcl_test_server
    vcl_test_client
    sock_test_server
    sock_test_client
    test_vcl_listener_server
    test_vcl_listener_client
  )
  foreach(test ${VCL_TESTS})
    add_executable(${test} ${test}.c)
    target_link_libraries(${test} vppcom)
  endforeach()
endif(VPP_BUILD_VCL_TESTS)

