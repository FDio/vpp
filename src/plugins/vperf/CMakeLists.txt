# Copyright (c) 2026 Cisco and/or its affiliates.
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

if(NOT VPP_BUILD_VCL)
  return()
endif()

add_vpp_plugin(vperf
  SOURCES
  builtin/vperf_cli.c
  builtin/vperf_client.c
  builtin/vperf_server.c
  builtin/vperf_stats.c
  builtin/vperf_protos.c
  vperf.c
)

option(VPP_BUILD_VCL_TESTS "Build vcl tests." ON)
option(VPP_BUILD_VPERF_TESTS "Build vperf VCL tests." ${VPP_BUILD_VCL_TESTS})
if(VPP_BUILD_VCL_TESTS AND VPP_BUILD_VPERF_TESTS)
  foreach(test
    vperf_server
    vperf_client
  )
    add_vpp_test(${test}
      SOURCES
      "vcl/${test}.c"
      vcl/vperf_protos.c
      LINK_LIBRARIES vppcom pthread ${EPOLL_LIB}
    )
  endforeach()

  add_vpp_test(vperf_cl_udp SOURCES "vcl/vperf_cl_udp.c"
    LINK_LIBRARIES vppcom pthread ${EPOLL_LIB}
    NO_INSTALL
  )
endif()
