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

include_directories (
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_BINARY_DIR}/..
)

add_vpp_library(vapiclient
  SOURCES
  vapi.c
  libvapiclient.map

  LINK_LIBRARIES vppinfra vlibmemoryclient svm pthread m rt
  DEPENDS api_headers
)

install(
  FILES
    vapi.h
    vapi_common.h
    vapi_dbg.h
    vapi.hpp
    vapi_internal.h
  DESTINATION
    include/vapi
  COMPONENT
    vpp-dev
)

install(
  FILES
    vapi_c_gen.py
    vapi_json_parser.py
    vapi_cpp_gen.py
  DESTINATION
    share/vpp
  COMPONENT
    vpp-dev
)

install(
  PROGRAMS
  vapi_c_gen.py
  vapi_cpp_gen.py
  vapi_json_parser.py

  DESTINATION bin
  COMPONENT vpp-dev
)
