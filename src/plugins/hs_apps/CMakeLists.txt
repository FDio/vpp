# Copyright (c) 2019 Cisco and/or its affiliates.
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
# vpp builtin hs apps
##############################################################################
add_vpp_plugin(hs_apps
  SOURCES
  echo_client.c
  echo_server.c
  hs_apps.c
  http_cli.c
  proxy.c
)

##############################################################################
# vpp external hs apps that use the "raw" session layer api
##############################################################################
option(VPP_BUILD_HS_SAPI_APPS "Build hs apps that use the session api." ON)
if(VPP_BUILD_HS_SAPI_APPS)
  add_vpp_executable(vpp_echo
    SOURCES
    sapi/vpp_echo.c
    sapi/vpp_echo_common.c
    sapi/vpp_echo_bapi.c
    sapi/vpp_echo_proto_quic.c
    sapi/vpp_echo_proto_tcp.c
    sapi/vpp_echo_proto_udp.c
    LINK_LIBRARIES vlibmemoryclient svm vppinfra pthread m rt
    DEPENDS api_headers
  )
endif(VPP_BUILD_HS_SAPI_APPS)

##############################################################################
# vcl tests
##############################################################################
option(VPP_BUILD_VCL_TESTS "Build vcl tests." ON)
if(VPP_BUILD_VCL_TESTS)
  foreach(test
    sock_test_server
    sock_test_client
  )
    add_vpp_executable(${test}
      SOURCES "vcl/${test}.c"
      LINK_LIBRARIES vppcom pthread
      NO_INSTALL
    )
  endforeach()

  foreach(test
    vcl_test_server
    vcl_test_client
  )
    add_vpp_executable(${test}
      SOURCES
      "vcl/${test}.c"
      vcl/vcl_test_protos.c
      LINK_LIBRARIES vppcom pthread
      NO_INSTALL
    )
  endforeach()
endif(VPP_BUILD_VCL_TESTS)
