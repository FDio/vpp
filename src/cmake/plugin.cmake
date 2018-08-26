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

macro(add_vpp_plugin name)
  cmake_parse_arguments(PLUGIN
    ""
    "LINK_FLAGS"
    "SOURCES;API_FILES;MULTIARCH_SOURCES;LINK_LIBRARIES;API_TEST_SOURCES"
    ${ARGN}
  )
  set(plugin_name ${name}_plugin)
  set(api_headers)
  file(RELATIVE_PATH rpath ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR})
  foreach(f ${PLUGIN_API_FILES})
    vpp_generate_api_header(${f} plugins)
    list(APPEND api_headers ${f}.h ${f}.json)
    set_property(GLOBAL APPEND PROPERTY VPP_API_FILES ${rpath}/${f})
  endforeach()
  add_library(${plugin_name} SHARED ${PLUGIN_SOURCES} ${api_headers})
  add_dependencies(${plugin_name} vpp_version_h api_headers)
  set_target_properties(${plugin_name} PROPERTIES
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/vpp_plugins)
  if(PLUGIN_MULTIARCH_SOURCES)
    vpp_library_set_multiarch_sources(${plugin_name} ${PLUGIN_MULTIARCH_SOURCES})
  endif()
  if(PLUGIN_LINK_LIBRARIES)
    target_link_libraries(${plugin_name} ${PLUGIN_LINK_LIBRARIES})
  endif()
  if(PLUGIN_LINK_FLAGS)
    set_target_properties(${plugin_name} PROPERTIES LINK_FLAGS "${PLUGIN_LINK_FLAGS}")
  endif()
  if(PLUGIN_API_TEST_SOURCES)
    set(test_plugin_name ${name}_test_plugin)
    add_library(${test_plugin_name} SHARED ${PLUGIN_API_TEST_SOURCES} ${api_headers})
    add_dependencies(${test_plugin_name} api_headers)
    set_target_properties(${test_plugin_name} PROPERTIES
      PREFIX ""
      LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/vpp_api_test_plugins)
    install(TARGETS ${test_plugin_name} DESTINATION ${VPP_LIB_DIR_NAME}/vpp_api_test_plugins COMPONENT
	    plugins)
  endif()
  install(TARGETS ${plugin_name} DESTINATION ${VPP_LIB_DIR_NAME}/vpp_plugins COMPONENT plugins)
endmacro()

