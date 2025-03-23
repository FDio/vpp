
# Copyright (c) 2024 InMon Corp.
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

if ("${CMAKE_SYSTEM_NAME}" STREQUAL "FreeBSD")
  message(WARNING "sflow is not supported on FreeBSD - sflow plugin disabled")
  return()
endif()

add_vpp_plugin(sflow
  SOURCES
  sflow.c
  node.c
  sflow_common.h
  sflow.h
  sflow_dlapi.h
  sflow_psample.c
  sflow_psample.h
  sflow_psample_fields.h
  sflow_usersock.c
  sflow_usersock.h
  sflow_dropmon.h
  sflow_dropmon.c
  sflow_netlink.c
  sflow_netlink.h

  MULTIARCH_SOURCES
  node.c

  API_FILES
  sflow.api

  API_TEST_SOURCES
  sflow_test.c

  LINK_LIBRARIES
  vppapiclient
  vapiclient
)
