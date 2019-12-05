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
# API
##############################################################################
function(vpp_generate_api_c_header file)
  set (output_name ${CMAKE_CURRENT_BINARY_DIR}/${file}.h)
  get_filename_component(output_dir ${output_name} DIRECTORY)
  if(NOT VPP_APIGEN)
     set(VPP_APIGEN ${CMAKE_SOURCE_DIR}/tools/vppapigen/vppapigen)
  endif()
  if (VPP_INCLUDE_DIR)
    set(includedir "--includedir" ${VPP_INCLUDE_DIR})
  endif()
  add_custom_command (OUTPUT ${output_name}
    COMMAND mkdir -p ${output_dir}
    COMMAND ${VPP_APIGEN}
    ARGS ${includedir} --includedir ${CMAKE_SOURCE_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/${file} --outputdir ${output_dir} --output ${output_name}
    DEPENDS ${VPP_APIGEN} ${CMAKE_CURRENT_SOURCE_DIR}/${file}
    COMMENT "Generating API header ${output_name}"
  )
endfunction()

function(vpp_generate_api_json_header file dir component)
  set (output_name ${CMAKE_CURRENT_BINARY_DIR}/${file}.json)
  get_filename_component(output_dir ${output_name} DIRECTORY)
  if(NOT VPP_APIGEN)
     set(VPP_APIGEN ${CMAKE_SOURCE_DIR}/tools/vppapigen/vppapigen)
  endif()
  if (VPP_INCLUDE_DIR)
    set(includedir "--includedir" ${VPP_INCLUDE_DIR})
  endif()
  add_custom_command (OUTPUT ${output_name}
    COMMAND mkdir -p ${output_dir}
    COMMAND ${VPP_APIGEN}
    ARGS ${includedir} --includedir ${CMAKE_SOURCE_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/${file} JSON --output ${output_name}
    DEPENDS ${VPP_APIGEN} ${CMAKE_CURRENT_SOURCE_DIR}/${file}
    COMMENT "Generating API header ${output_name}"
  )
  install(
    FILES ${output_name}
    DESTINATION share/vpp/api/${dir}/
    COMPONENT ${component}
  )
endfunction()

##############################################################################
# VPP-API
##############################################################################
function(vpp_generate_vapi_c_header f)
  get_filename_component(output ${f}.vapi.h NAME)
  set (output_name ${CMAKE_BINARY_DIR}/vpp-api/vapi/${output})
  if(NOT VPP_VAPI_C_GEN)
    set(VPP_VAPI_C_GEN ${CMAKE_SOURCE_DIR}/vpp-api/vapi/vapi_c_gen.py)
    set(VPP_VAPI_C_GEN_DEPENDS
        ${CMAKE_SOURCE_DIR}/vpp-api/vapi/vapi_c_gen.py
        ${CMAKE_SOURCE_DIR}/vpp-api/vapi/vapi_json_parser.py
    )
  endif()

  # C VAPI Headers
  set(input ${CMAKE_CURRENT_BINARY_DIR}/${f}.json)
  add_custom_command(
    OUTPUT ${output_name}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/vpp-api/vapi
    COMMAND ${VPP_VAPI_C_GEN}
    ARGS --remove-path ${input}
    DEPENDS ${input} ${VPP_VAPI_C_GEN_DEPENDS}
    COMMENT "Generating VAPI C header ${output_name}"
  )
  install(
    FILES ${output_name}
    DESTINATION include/vapi
    COMPONENT vpp-dev
  )
endfunction ()

function (vpp_generate_vapi_cpp_header f)
  get_filename_component(output ${f}.vapi.hpp NAME)
  set (output_name ${CMAKE_BINARY_DIR}/vpp-api/vapi/${output})
  if(NOT VPP_VAPI_CPP_GEN)
    set(VPP_VAPI_CPP_GEN ${CMAKE_SOURCE_DIR}/vpp-api/vapi/vapi_cpp_gen.py)
    set(VPP_VAPI_CPP_GEN_DEPENDS
        ${CMAKE_SOURCE_DIR}/vpp-api/vapi/vapi_cpp_gen.py
        ${CMAKE_SOURCE_DIR}/vpp-api/vapi/vapi_json_parser.py
    )
  endif()
  # C++ VAPI Headers
  set(input ${CMAKE_CURRENT_BINARY_DIR}/${f}.json)
  add_custom_command(
    OUTPUT ${output_name}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}/vpp-api/vapi
    COMMAND ${VPP_VAPI_CPP_GEN}
    ARGS --gen-h-prefix=vapi --remove-path ${input}
    DEPENDS ${input} ${VPP_VAPI_CPP_GEN_DEPENDS}
    COMMENT "Generating VAPI C++ header ${output_name}"
  )
  install(
    FILES ${output_name}
    DESTINATION include/vapi
    COMPONENT vpp-dev
  )
endfunction ()


##############################################################################
# generate the .h and .json files for a .api file
#  @param file - the name of the .api
#  @param dir  - the install directory under ROOT/share/vpp/api to place the
#                generated .json file
##############################################################################
function(vpp_generate_api_header file dir component)
  vpp_generate_api_c_header (${file})
  vpp_generate_api_json_header (${file} ${dir} ${component})
  vpp_generate_vapi_c_header (${file})
  vpp_generate_vapi_cpp_header (${file})
endfunction()

function(vpp_add_api_files name dir component)
  unset(header_files)
  set(target ${name}_api_headers)
  file(RELATIVE_PATH rpath ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
  foreach(file ${ARGN})
    vpp_generate_api_header (${file} ${dir} ${component})
    # Basic api headers get installed in a subdirectory according to
    # their component name, but vapi is expected to be found directly under
    # "vapi". Both by in-source components (e.g. vpp-api/vapi/vapi.c), and
    # out-of-tree plugins use #include <vapi/component.api.vapi.h>.
    # ${file} contains the subdirectory, so strip it here.
    get_filename_component(name ${file} NAME)
    list(APPEND header_files
      ${file}.h
      ${file}.json
      ${CMAKE_BINARY_DIR}/vpp-api/vapi/${name}.vapi.h
      ${CMAKE_BINARY_DIR}/vpp-api/vapi/${name}.vapi.hpp
    )
  endforeach()
  add_custom_target(${target} DEPENDS ${header_files})
endfunction()

add_custom_target(api_headers
  DEPENDS vlibmemory_api_headers vnet_api_headers vpp_api_headers
)

