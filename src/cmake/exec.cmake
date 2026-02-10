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

macro(add_vpp_executable exec)
  cmake_parse_arguments(ARG
    "ENABLE_EXPORTS;NO_INSTALL"
    ""
    "SOURCES;LINK_LIBRARIES;DEPENDS"
    ${ARGN}
  )

  add_executable(${exec} ${ARG_SOURCES})
  target_compile_options(${exec} PUBLIC ${VPP_DEFAULT_MARCH_FLAGS})
  if(ARG_LINK_LIBRARIES)
    target_link_libraries(${exec} ${ARG_LINK_LIBRARIES})
  endif()
  if(ARG_ENABLE_EXPORTS)
    set_target_properties(${exec} PROPERTIES ENABLE_EXPORTS 1)
  endif()
  if(ARG_DEPENDS)
    add_dependencies(${exec} ${ARG_DEPENDS})
  endif()
  if(NOT ARG_NO_INSTALL)
    install(TARGETS ${exec} DESTINATION ${VPP_RUNTIME_DIR})
  endif()
endmacro()

function(vpp_add_filtered_executable type name)
  cmake_parse_arguments(ARG
    "ENABLE_EXPORTS;NO_INSTALL"
    ""
    "SOURCES;LINK_LIBRARIES;DEPENDS"
    ${ARGN}
  )

  string(TOUPPER ${type} TYPE)
  if(DEFINED VPP_${TYPE}S AND NOT VPP_${TYPE}S STREQUAL "")
    if(VPP_${TYPE}S STREQUAL "none")
      return()
    endif()
    get_property(_filter GLOBAL PROPERTY VPP_${TYPE}S_FILTER)
    list(FIND _filter ${name} _idx)
    if(_idx EQUAL -1)
      return()
    endif()
    list(REMOVE_AT _filter ${_idx})
    set_property(GLOBAL PROPERTY VPP_${TYPE}S_FILTER "${_filter}")
  endif()

  set(_args "")
  if(ARG_ENABLE_EXPORTS)
    list(APPEND _args ENABLE_EXPORTS)
  endif()
  if(ARG_NO_INSTALL)
    list(APPEND _args NO_INSTALL)
  endif()

  add_vpp_executable(${name}
    SOURCES ${ARG_SOURCES}
    LINK_LIBRARIES ${ARG_LINK_LIBRARIES}
    DEPENDS ${ARG_DEPENDS}
    ${_args}
  )

  set_property(GLOBAL APPEND PROPERTY VPP_${TYPE}S_LIST ${name})
endfunction()

macro(add_vpp_tool name)
  vpp_add_filtered_executable(tool ${name} ${ARGN})
endmacro()

macro(add_vpp_test name)
  vpp_add_filtered_executable(test ${name} ${ARGN})
endmacro()