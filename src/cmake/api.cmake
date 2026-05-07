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

# Set the CMP0116 policy
if(POLICY CMP0116)
    cmake_policy(SET CMP0116 NEW)
endif()

##############################################################################
# API
##############################################################################
function(vpp_generate_api_c_header file)
  set (output_name ${CMAKE_CURRENT_BINARY_DIR}/${file}.h)
  set (dependency_file ${CMAKE_CURRENT_BINARY_DIR}/${file}.d)
  get_filename_component(output_dir ${output_name} DIRECTORY)
  if(NOT VPP_APIGEN)
    set(VPP_APIGEN ${CMAKE_SOURCE_DIR}/tools/vppapigen/vppapigen)
    set(VPPAPIGEN_SUBMODULES
      ${CMAKE_SOURCE_DIR}/tools/vppapigen/vppapigen_c.py
      ${CMAKE_SOURCE_DIR}/tools/vppapigen/vppapigen_json.py
    )
  endif()
  if (VPP_INCLUDE_DIR)
    set(includedir "--includedir" ${VPP_INCLUDE_DIR})
  endif()

  set(OUTPUT_HEADERS
    "${CMAKE_CURRENT_BINARY_DIR}/${file}.h"
    "${CMAKE_CURRENT_BINARY_DIR}/${file}_fromjson.h"
    "${CMAKE_CURRENT_BINARY_DIR}/${file}_tojson.h"
    "${CMAKE_CURRENT_BINARY_DIR}/${file}_enum.h"
    "${CMAKE_CURRENT_BINARY_DIR}/${file}_types.h"
    "${CMAKE_CURRENT_BINARY_DIR}/${file}.c"
    "${CMAKE_CURRENT_BINARY_DIR}/${file}_test.c"
    "${CMAKE_CURRENT_BINARY_DIR}/${file}_test2.c"
  )

  get_filename_component(barename ${file} NAME)

# Define a variable for common apigen arguments
set(COMMON_ARGS
  OUTPUT ${OUTPUT_HEADERS}
  COMMAND mkdir -p ${output_dir}
  COMMAND ${PYENV} ${VPP_APIGEN}
  ARGS ${includedir} --includedir ${CMAKE_SOURCE_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/${file} --outputdir ${output_dir} --output ${output_name} -MF ${dependency_file}
  DEPENDS ${VPP_APIGEN} ${CMAKE_CURRENT_SOURCE_DIR}/${file} ${VPPAPIGEN_SUBMODULES}
  COMMENT "Generating API header ${output_name}"
)

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.20")
  add_custom_command (
    ${COMMON_ARGS}
    DEPFILE ${dependency_file}
  )
else()
  message(WARNING "Your CMake version does not support DEPFILE. Consider upgrading to CMake 3.20 or later for improved dependency handling.")
  add_custom_command (
    ${COMMON_ARGS}
  )
endif()
  set(t ${barename}_deps)

  if (NOT TARGET ${t})
    add_custom_target(${t} ALL DEPENDS ${OUTPUT_HEADERS})
    add_dependencies(api_headers ${t})
  endif()

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
    COMMAND ${PYENV} ${VPP_APIGEN}
    ARGS ${includedir} --includedir ${CMAKE_SOURCE_DIR} --input ${CMAKE_CURRENT_SOURCE_DIR}/${file} JSON --outputdir ${output_dir} --output ${output_name}
    DEPENDS ${VPP_APIGEN} ${CMAKE_CURRENT_SOURCE_DIR}/${file}
    COMMENT "Generating API header ${output_name}"
  )
  install(
    FILES ${output_name}
    DESTINATION ${CMAKE_INSTALL_DATADIR}/vpp/api/${dir}/
    COMPONENT ${component}
  )
endfunction()

##############################################################################
# VPP-API
##############################################################################
function(vpp_generate_vapi_c_header f)
  get_filename_component(output ${f}.vapi.h NAME)
  set (output_name ${VPP_BINARY_DIR}/vpp-api/vapi/${output})
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
    WORKING_DIRECTORY ${VPP_BINARY_DIR}/vpp-api/vapi
    COMMAND ${PYENV} ${VPP_VAPI_C_GEN}
    ARGS --remove-path ${input}
    DEPENDS ${input} ${VPP_VAPI_C_GEN_DEPENDS}
    COMMENT "Generating VAPI C header ${output_name}"
  )
  install(
    FILES ${output_name}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vapi
    COMPONENT vpp-dev
  )
endfunction ()

function (vpp_generate_vapi_cpp_header f)
  get_filename_component(output ${f}.vapi.hpp NAME)
  set (output_name ${VPP_BINARY_DIR}/vpp-api/vapi/${output})
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
    WORKING_DIRECTORY ${VPP_BINARY_DIR}/vpp-api/vapi
    COMMAND ${PYENV} ${VPP_VAPI_CPP_GEN}
    ARGS --gen-h-prefix=vapi --remove-path ${input}
    DEPENDS ${input} ${VPP_VAPI_CPP_GEN_DEPENDS}
    COMMENT "Generating VAPI C++ header ${output_name}"
  )
  install(
    FILES ${output_name}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/vapi
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
    file(MAKE_DIRECTORY ${VPP_BINARY_DIR}/vpp-api/vapi)
    get_filename_component(name ${file} NAME)
    list(APPEND header_files
      ${file}.h
      ${file}_enum.h
      ${file}_types.h
      ${file}.json
      ${VPP_BINARY_DIR}/vpp-api/vapi/${name}.vapi.h
      ${VPP_BINARY_DIR}/vpp-api/vapi/${name}.vapi.hpp
    )
  endforeach()
  add_custom_target(${target} DEPENDS ${header_files})
  add_dependencies(api_headers ${target})

  # Out-of-tree plugin build: record this plugin's .api files so the combined
  # Python stubs (in-tree scan + these files) can be regenerated once the whole
  # project has been configured. See the external branch below.
  if(VPP_EXTERNAL_PROJECT)
    foreach(file ${ARGN})
      set_property(GLOBAL APPEND PROPERTY VPP_EXTERN_API_FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/${file}
      )
    endforeach()
  endif()
endfunction()

add_custom_target(api_headers
  DEPENDS vlibmemory_api_headers vnet_api_headers vpp_api_headers vlib_api_headers
)
add_custom_target(vapi_headers
)

##############################################################################
# Python type stubs (vapi_types.pyi, vpp_papi_provider.pyi)
#
# Regenerated automatically when any .api file or the generator scripts
# change. The script writes into the source tree, with a stamp file in the
# build tree used for incremental tracking.
#
# For out-of-tree plugin builds (VPP_EXTERNAL_PROJECT) the same generator is
# run, but it folds the plugin's own .api files on top of the in-tree scan and
# writes the combined stubs into the plugin build tree (see the external branch
# below).
##############################################################################

# Deferred to the end of project configuration so every plugin has registered
# its .api files (into VPP_EXTERN_API_FILES) before we build the stub target.
# A single regeneration that sees the full in-tree + plugin .api set avoids any
# cross-build merge of separately produced stubs.
#
# Scope: the generated stub covers the in-tree API plus every plugin built in
# *this* external project. Plugins built in separate external projects are not
# folded in (there is no shared registry of independently-built plugins); each
# such build produces its own stub of in-tree + its own plugins.
function(_vpp_generate_external_python_stubs)
  get_property(api_files GLOBAL PROPERTY VPP_EXTERN_API_FILES)
  if(NOT api_files)
    return()
  endif()

  # The generator is installed alongside the VPP tools; it derives the VPP
  # source checkout from its own (in-checkout) install path.
  find_file(VPP_GENERATE_PYTHON_STUBS
    NAMES generate_python_stubs.py
    PATH_SUFFIXES share/vpp
  )
  if(NOT VPP_GENERATE_PYTHON_STUBS)
    message(STATUS
      "generate_python_stubs.py not found; skipping plugin Python stubs")
    return()
  endif()

  set(stubs_out ${CMAKE_BINARY_DIR}/python-stubs)
  set(stamp ${CMAKE_BINARY_DIR}/python-api-stubs.stamp)
  set(extra_args "")
  foreach(f ${api_files})
    list(APPEND extra_args --extra-api-file ${f})
  endforeach()

  add_custom_command(
    OUTPUT ${stamp}
    COMMAND ${PYENV} ${VPP_GENERATE_PYTHON_STUBS} --quiet
      --stubs-output ${stubs_out} ${extra_args}
    COMMAND ${CMAKE_COMMAND} -E touch ${stamp}
    DEPENDS ${api_files} ${VPP_GENERATE_PYTHON_STUBS}
    COMMENT "Generating Python type stubs for out-of-tree plugins"
    VERBATIM
  )
  add_custom_target(python_api_stubs ALL DEPENDS ${stamp})
endfunction()

if(NOT VPP_EXTERNAL_PROJECT)
  set(GENERATE_PYTHON_STUBS
    ${CMAKE_SOURCE_DIR}/tools/vppapigen/generate_python_stubs.py
  )
  set(PYTHON_STUBS_STAMP ${CMAKE_BINARY_DIR}/python-api-stubs.stamp)
  # Glob without CONFIGURE_DEPENDS: with it, ninja prints
  # "Re-checking globbed directories..." on every build/install. Newly-added
  # .api files are picked up on reconfigure or via `make python-api-stubs`.
  file(GLOB_RECURSE PYTHON_STUBS_API_FILES
    ${CMAKE_SOURCE_DIR}/*.api
  )

  add_custom_command(
    OUTPUT ${PYTHON_STUBS_STAMP}
    COMMAND ${PYENV} ${GENERATE_PYTHON_STUBS} --quiet
    COMMAND ${CMAKE_COMMAND} -E touch ${PYTHON_STUBS_STAMP}
    DEPENDS
      ${PYTHON_STUBS_API_FILES}
      ${GENERATE_PYTHON_STUBS}
      ${CMAKE_SOURCE_DIR}/../test/vpp_papi_provider.py
    COMMENT "Generating Python type stubs (vapi_types.pyi, vpp_papi_provider.pyi)"
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    VERBATIM
  )
  add_custom_target(python_api_stubs ALL DEPENDS ${PYTHON_STUBS_STAMP})
else()
  cmake_language(DEFER CALL _vpp_generate_external_python_stubs)
endif()
