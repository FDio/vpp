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
  ${CMAKE_CURRENT_BINARY_DIR}
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

  DESTINATION ${VPP_RUNTIME_DIR}
  COMPONENT vpp-dev
)

vpp_find_path(SUBUNIT_INCLUDE_DIR NAMES subunit/child.h)
vpp_find_library(SUBUNIT_LIB NAMES subunit)

if(SUBUNIT_INCLUDE_DIR AND SUBUNIT_LIB)
  message (STATUS "Found subunit in ${SUBUNIT_INCLUDE_DIR} and ${SUBUNIT_LIB}")

  add_custom_command(
    OUTPUT fake.api.vapi.h
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${PYENV} ${CMAKE_CURRENT_SOURCE_DIR}/vapi_c_gen.py
    ARGS --remove-path ${CMAKE_CURRENT_SOURCE_DIR}/fake.api.json
    DEPENDS fake.api.json
    COMMENT "Generating fake VAPI C header ${output_name}"
  )

  add_custom_command(
    OUTPUT fake.api.vapi.hpp
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${PYENV} ${CMAKE_CURRENT_SOURCE_DIR}/vapi_cpp_gen.py
    ARGS --remove-path ${CMAKE_CURRENT_SOURCE_DIR}/fake.api.json
    DEPENDS fake.api.json
    COMMENT "Generating fake VAPI C++ header ${output_name}"
  )

  add_custom_target(fake_api_vapi_h DEPENDS fake.api.vapi.h)
  add_custom_target(fake_api_vapi_hpp DEPENDS fake.api.vapi.hpp)

  set(libs vppinfra vlibmemoryclient svm pthread check rt m vapiclient ${SUBUNIT_LIB})

  add_vpp_executable(vapi_c_test
    SOURCES
    vapi_c_test.c
    DEPENDS fake_api_vapi_h
    LINK_LIBRARIES ${libs}
  )

  enable_language(CXX)
  add_vpp_executable(vapi_cpp_test
    SOURCES
    vapi_cpp_test.cpp
    DEPENDS fake_api_vapi_hpp
    LINK_LIBRARIES ${libs}
  )

else()
  message (WARNING "subunit library not found - vapi tests disabled")
endif()
