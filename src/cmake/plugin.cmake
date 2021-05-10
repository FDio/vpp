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
    "LINK_FLAGS;COMPONENT;DEV_COMPONENT"
    "SOURCES;API_FILES;MULTIARCH_SOURCES;MULTIARCH_FORCE_ON;LINK_LIBRARIES;INSTALL_HEADERS;API_TEST_SOURCES;"
    ${ARGN}
  )
  set(plugin_name ${name}_plugin)
  set(api_includes)
  if(NOT PLUGIN_COMPONENT)
    set(PLUGIN_COMPONENT vpp-plugin-core)
  endif()
  if(NOT PLUGIN_DEV_COMPONENT)
    if(NOT VPP_EXTERNAL_PROJECT)
      set(PLUGIN_DEV_COMPONENT vpp-dev)
    else()
      set(PLUGIN_DEV_COMPONENT ${PLUGIN_COMPONENT}-dev)
    endif()
  endif()

  vpp_add_api_files(${plugin_name} plugins ${PLUGIN_COMPONENT} ${PLUGIN_API_FILES})
  foreach(f ${PLUGIN_API_FILES})
    get_filename_component(dir ${f} DIRECTORY)
    list(APPEND api_includes ${f}.h ${f}_enum.h ${f}_types.h ${f}.json)
    install(
      FILES
      ${CMAKE_CURRENT_BINARY_DIR}/${f}.h
      ${CMAKE_CURRENT_BINARY_DIR}/${f}_enum.h
      ${CMAKE_CURRENT_BINARY_DIR}/${f}_types.h
      DESTINATION include/vpp_plugins/${name}/${dir}
      COMPONENT ${PLUGIN_DEV_COMPONENT}
    )
  endforeach()
  add_library(${plugin_name} SHARED ${api_includes} ${PLUGIN_SOURCES})
  target_compile_options(${plugin_name} PUBLIC ${VPP_DEFAULT_MARCH_FLAGS})
  set_target_properties(${plugin_name} PROPERTIES NO_SONAME 1)
  target_compile_options(${plugin_name} PRIVATE "-fvisibility=hidden")
  target_compile_options (${plugin_name} PRIVATE "-ffunction-sections")
  target_compile_options (${plugin_name} PRIVATE "-fdata-sections")
  target_link_libraries (${plugin_name} "-Wl,--gc-sections")
  set(deps "")
  if(NOT VPP_EXTERNAL_PROJECT)
    list(APPEND deps vpp_version_h api_headers)
  endif()
  if(PLUGIN_API_FILES)
    list(APPEND deps ${plugin_name}_api_headers)
  endif()
  if(deps)
    add_dependencies(${plugin_name} ${deps})
  endif()
  set_target_properties(${plugin_name} PROPERTIES
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/vpp_plugins)
  if(PLUGIN_MULTIARCH_SOURCES)
    vpp_library_set_multiarch_sources(${plugin_name}
      SOURCES ${PLUGIN_MULTIARCH_SOURCES}
      DEPENDS ${deps}
      FORCE_ON ${PLUGIN_MULTIARCH_FORCE_ON}
    )
  endif()
  if(PLUGIN_LINK_LIBRARIES)
    target_link_libraries(${plugin_name} ${PLUGIN_LINK_LIBRARIES})
  endif()
  if(PLUGIN_LINK_FLAGS)
    set_target_properties(${plugin_name} PROPERTIES LINK_FLAGS "${PLUGIN_LINK_FLAGS}")
  endif()
  if(PLUGIN_INSTALL_HEADERS)
    foreach(file ${PLUGIN_INSTALL_HEADERS})
      get_filename_component(dir ${file} DIRECTORY)
      install(
	FILES ${file}
	DESTINATION include/vpp_plugins/${name}/${dir}
	COMPONENT vpp-dev
      )
    endforeach()
  endif()
  if(PLUGIN_API_TEST_SOURCES)
    set(test_plugin_name ${name}_test_plugin)
    add_library(${test_plugin_name} SHARED ${PLUGIN_API_TEST_SOURCES}
		${api_includes})
    target_compile_options(${test_plugin_name} PUBLIC ${VPP_DEFAULT_MARCH_FLAGS})
    set_target_properties(${test_plugin_name} PROPERTIES NO_SONAME 1)
    if(NOT VPP_EXTERNAL_PROJECT)
      add_dependencies(${test_plugin_name} api_headers)
    endif()
    if(PLUGIN_API_FILES)
      add_dependencies(${test_plugin_name} ${plugin_name}_api_headers)
    endif()
    set_target_properties(${test_plugin_name} PROPERTIES
      PREFIX ""
      LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/vpp_api_test_plugins)
    install(
      TARGETS ${test_plugin_name}
      DESTINATION ${VPP_LIBRARY_DIR}/vpp_api_test_plugins
      COMPONENT ${PLUGIN_COMPONENT}
    )
  endif()
  if (PLUGIN_API_FILES)
    add_vpp_test_library(${name}_test_plugin ${PLUGIN_API_FILES})
  endif()

  install(
    TARGETS ${plugin_name}
    DESTINATION ${VPP_LIBRARY_DIR}/vpp_plugins
    COMPONENT ${PLUGIN_COMPONENT}
  )
endmacro()

macro(vpp_plugin_find_library plugin var name)
  find_library(${var} NAMES ${name} ${ARGN})
  mark_as_advanced(${var})
if (NOT ${var})
  message(WARNING "-- ${name} library not found - ${plugin} plugin disabled")
  return()
endif()
    message(STATUS "${plugin} plugin needs ${name} library - found at ${${var}}")
endmacro()
