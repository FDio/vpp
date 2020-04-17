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
    "SOURCES;MULTIARCH_SOURCES;BUILD_STATIC_LIBRARY;API_FILES;LINK_LIBRARIES;INSTALL_HEADERS;DEPENDS"
    ${ARGN}
  )

  if(ARG_BUILD_STATIC_LIBRARY)
    add_library(${lib} STATIC ${ARG_SOURCES})
  else()
    add_library(${lib} SHARED ${ARG_SOURCES})
  endif()
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
     set_property(TARGET ${lib} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
     target_compile_options (${lib} PRIVATE "-ffunction-sections")
     target_compile_options (${lib} PRIVATE "-fdata-sections")
     target_link_libraries (${lib} "-Wl,--gc-sections")
  endif()

  if(ARG_MULTIARCH_SOURCES)
    vpp_library_set_multiarch_sources(${lib} "${ARG_DEPENDS}" ${ARG_MULTIARCH_SOURCES})
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

  if(ARG_DEPENDS)
    add_dependencies(${lib} ${ARG_DEPENDS})
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
    if(NOT VPP_EXTERNAL_PROJECT)
      add_dependencies(${test_lib} api_headers)
    endif()
    include_directories(${CMAKE_CURRENT_BINARY_DIR})
    set_target_properties(${test_lib} PROPERTIES NO_SONAME 1)
    set_target_properties(${test_lib} PROPERTIES
      PREFIX ""
      LIBRARY_OUTPUT_DIRECTORY ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/vat2_plugins)

    # Later: Install and package
    # install .so
    #install(
    #  TARGETS ${test_lib}
    #  DESTINATION ${VPP_LIBRARY_DIR}/vat2_plugins
    #  #COMPONENT ${ARG_COMPONENT}
    #  )
  endforeach()
endmacro()
