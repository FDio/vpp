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

unset(VAPICLIENT_API_C_HEADERS)
unset(VAPICLIENT_API_CPP_HEADERS)

get_property(VPP_API_FILES GLOBAL PROPERTY VPP_API_FILES)
foreach(f ${VPP_API_FILES})
  get_filename_component(output ${f}.vapi.h NAME)
  set(input ${CMAKE_BINARY_DIR}/${f}.json)

  # C VAPI Headers
  add_custom_command(
    OUTPUT ${output}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/vapi_c_gen.py
    ARGS --remove-path ${input}
    DEPENDS ${input} vapi_c_gen.py vapi_json_parser.py
    COMMENT "Generating VAPI C header ${output}"
  )
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${output} DESTINATION include/vapi)
  list(APPEND VAPICLIENT_API_CPP_HEADERS ${output})

  # C++ VAPI Headers
  get_filename_component(output ${f}.vapi.hpp NAME)
  add_custom_command(
    OUTPUT ${output}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/vapi_cpp_gen.py
    ARGS --remove-path ${input}
    DEPENDS ${input} vapi_cpp_gen.py vapi_json_parser.py
    COMMENT "Generating VAPI C++ header ${output}"
  )
  install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${output} DESTINATION include/vapi)
  list(APPEND VAPICLIENT_API_CPP_HEADERS ${output})
endforeach ()

add_custom_target(all-vapi-headers DEPENDS
  ${VAPICLIENT_API_C_HEADERS}
  ${VAPICLIENT_API_CPP_HEADERS}
)

add_vpp_library(vapiclient
  SOURCES
  vapi.c
  libvapiclient.map

  LINK_LIBRARIES vppinfra vlibmemoryclient svm pthread m rt
  DEPENDS all-vapi-headers
)

install(
  FILES
  vapi.h
  vapi_common.h
  vapi_dbg.h
  vapi.hpp
  vapi_internal.h

  DESTINATION include/vapi
)
