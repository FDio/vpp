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
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

macro(add_vpp_plugin plugin_name)
  set(api_headers)
  foreach(f ${ARGN})
     if(${f} MATCHES ".*\.api$")
       vpp_generate_api_header(${f} plugins)
       list(APPEND api_headers ${f}.h ${f}.json)
     endif()
  endforeach()
  add_library(${plugin_name} SHARED ${ARGN} ${api_headers})
  add_dependencies(${plugin_name} vpp_version_h api_headers)
  set_target_properties(${plugin_name} PROPERTIES
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/vpp_plugins)
  install(TARGETS ${plugin_name} DESTINATION lib/vpp_plugins COMPONENT plugins)
endmacro()

macro(add_vpp_api_test_plugin plugin_name)
  set(api_headers)
  foreach(f ${ARGN})
     if(${f} MATCHES ".*\.api$")
       vpp_generate_api_header(${f} plugins)
       list(APPEND api_headers ${f}.h)
     endif()
  endforeach()
  add_library(${plugin_name} SHARED ${ARGN} ${api_headers})
  add_dependencies(${plugin_name} api_headers)
  set_target_properties(${plugin_name} PROPERTIES PREFIX "")
  set_target_properties(${plugin_name} PROPERTIES
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}//vpp_api_test_plugins)
  install(TARGETS ${plugin_name} DESTINATION lib/vpp_api_test_plugins COMPONENT
	  plugins)
endmacro()

##############################################################################
# find and add all plugin subdirs
############################################################################
FILE(GLOB files RELATIVE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/*/CMakeLists.txt
)
foreach (f ${files})
  get_filename_component(dir ${f} DIRECTORY)
  add_subdirectory(${dir})
endforeach()
