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

macro(add_vpp_library lib)
  cmake_parse_arguments(ARG
    "LTO"
    "COMPONENT"
    "SOURCES;MULTIARCH_SOURCES;API_FILES;LINK_LIBRARIES;INSTALL_HEADERS;DEPENDS"
    ${ARGN}
  )

  set (lo ${lib}_objs)
  add_library(${lo} OBJECT ${ARG_SOURCES})
  set_target_properties(${lo} PROPERTIES POSITION_INDEPENDENT_CODE ON)
  target_compile_options(${lo} PUBLIC ${VPP_DEFAULT_MARCH_FLAGS})

  add_library(${lib} SHARED)
  target_sources(${lib} PRIVATE $<TARGET_OBJECTS:${lo}>)

  if(VPP_LIB_VERSION)
    set_target_properties(${lib} PROPERTIES SOVERSION ${VPP_LIB_VERSION})
  endif()

  # library deps
  if(ARG_LINK_LIBRARIES)
    target_link_libraries(${lib} ${ARG_LINK_LIBRARIES})
  endif()
  # install .so
  if(NOT ARG_COMPONENT)
    set(ARG_COMPONENT vpp)
  endif()
  install(
    TARGETS ${lib}
    DESTINATION ${VPP_LIBRARY_DIR}
    COMPONENT ${ARG_COMPONENT}
  )

  if (ARG_LTO AND VPP_USE_LTO)
     set_property(TARGET ${lo} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
     set_property(TARGET ${lib} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
     target_compile_options (${lib} PRIVATE "-ffunction-sections")
     target_compile_options (${lib} PRIVATE "-fdata-sections")
     target_link_libraries (${lib} "-Wl,--gc-sections")
     if(compiler_flag_no_stringop_overflow)
       target_link_libraries (${lib} "-Wno-stringop-overflow")
     endif()
  endif()

  if(ARG_MULTIARCH_SOURCES)
    vpp_library_set_multiarch_sources(${lib} DEPENDS ${ARG_DEPENDS} SOURCES ${ARG_MULTIARCH_SOURCES})
  endif()

  if(ARG_API_FILES)
    vpp_add_api_files(${lib} core vpp ${ARG_API_FILES})
    foreach(file ${ARG_API_FILES})
      get_filename_component(dir ${file} DIRECTORY)
      install(
	FILES ${file} ${CMAKE_CURRENT_BINARY_DIR}/${file}.h
	${CMAKE_CURRENT_BINARY_DIR}/${file}_enum.h
	${CMAKE_CURRENT_BINARY_DIR}/${file}_types.h
	${CMAKE_CURRENT_BINARY_DIR}/${file}_tojson.h
	${CMAKE_CURRENT_BINARY_DIR}/${file}_fromjson.h
	DESTINATION include/${lib}/${dir}
	COMPONENT vpp-dev
      )
    endforeach()
  endif()

  if(NOT VPP_EXTERNAL_PROJECT)
    add_dependencies(${lo} api_headers)
  endif()

  if(VPP_EXTERNAL_PROJECT AND ARG_API_FILES)
    add_dependencies(${lo} ${lib}_api_headers)
  endif()

  if(ARG_DEPENDS)
    add_dependencies(${lo} ${ARG_DEPENDS})
  endif()

  # install headers
  if(ARG_INSTALL_HEADERS)
    foreach(file ${ARG_INSTALL_HEADERS})
      get_filename_component(dir ${file} DIRECTORY)
      install(
	FILES ${file}
	DESTINATION include/${lib}/${dir}
	COMPONENT ${ARG_COMPONENT}-dev
      )
    endforeach()
  endif()
endmacro()

##############################################################################
# header files
##############################################################################
function (add_vpp_headers path)
  foreach(file ${ARGN})
    get_filename_component(dir ${file} DIRECTORY)
    install(
      FILES ${file}
      DESTINATION include/${path}/${dir}
      COMPONENT vpp-dev
    )
  endforeach()
endfunction()

macro(add_vat_test_library lib)
  cmake_parse_arguments(TEST
    ""
    ""
    ${ARGN}
  )

  foreach(file ${ARGN})
    get_filename_component(name ${file} NAME_WE)
    set(test_lib ${lib}_${name}_plugin)
    add_library(${test_lib} SHARED ${file})
    target_compile_options(${test_lib} PUBLIC ${VPP_DEFAULT_MARCH_FLAGS})
    if(NOT VPP_EXTERNAL_PROJECT)
      add_dependencies(${test_lib} api_headers)
    endif()
    include_directories(${CMAKE_CURRENT_BINARY_DIR})
    set_target_properties(${test_lib} PROPERTIES NO_SONAME 1)
    set_target_properties(${test_lib} PROPERTIES
      PREFIX ""
      LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/vpp_api_test_plugins)

    # install .so
    install(
      TARGETS ${test_lib}
      DESTINATION ${VPP_LIBRARY_DIR}/vpp_api_test_plugins
      COMPONENT ${ARG_COMPONENT}
    )
  endforeach()
endmacro()

macro(add_vpp_test_library lib)
  cmake_parse_arguments(TEST
    ""
    ""
    ${ARGN}
  )

  foreach(file ${ARGN})
    get_filename_component(name ${file} NAME_WE)
    set(test_lib ${lib}_${name}_plugin)
    add_library(${test_lib} SHARED ${file}_test2.c)
    target_compile_options(${test_lib} PUBLIC ${VPP_DEFAULT_MARCH_FLAGS})
    if(NOT VPP_EXTERNAL_PROJECT)
      add_dependencies(${test_lib} api_headers)
    endif()
    include_directories(${CMAKE_CURRENT_BINARY_DIR})
    set_target_properties(${test_lib} PROPERTIES NO_SONAME 1)
    set_target_properties(${test_lib} PROPERTIES
      PREFIX ""
      LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/vat2_plugins)

    # install .so
    install(
      TARGETS ${test_lib}
      DESTINATION ${VPP_LIBRARY_DIR}/vat2_plugins
      COMPONENT ${ARG_COMPONENT}
    )
  endforeach()
endmacro()

macro(vpp_find_library var)
  find_library(${var} ${ARGN})
  mark_as_advanced(${var})
endmacro()
macro(vpp_find_path var)
  find_path(${var} ${ARGN})
  mark_as_advanced(${var})
endmacro()
