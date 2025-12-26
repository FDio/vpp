# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

include_directories (
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

set(VPP_DRIVERS
  ""
  CACHE
  STRING "Comma-separated list of drivers included in build"
)

set(_vpp_drivers_list "")
if(NOT VPP_DRIVERS STREQUAL "")
  if(VPP_DRIVERS STREQUAL "none")
    message(STATUS "VPP drivers explicitly disabled")
    set(_vpp_drivers_list "none")
    set(_vpp_drivers_list ${_vpp_drivers_list} PARENT_SCOPE)
    return()
  endif()

  string(REGEX REPLACE "[ \t]*,[ \t]*" ";" _vpp_drivers_list "${VPP_DRIVERS}")
  list(FILTER _vpp_drivers_list EXCLUDE REGEX "^$")

  foreach(d IN LISTS _vpp_drivers_list)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${d}/CMakeLists.txt")
      add_subdirectory("${d}")
    else()
      message(FATAL_ERROR
        "VPP driver '${d}' not found: expected '${CMAKE_CURRENT_SOURCE_DIR}/${d}/CMakeLists.txt'")
    endif()
  endforeach()
  list(SORT _vpp_drivers_list)
  set(_vpp_drivers_list ${_vpp_drivers_list} PARENT_SCOPE)
  return()
endif()

##############################################################################
# find and add all driver subdirs
##############################################################################
FILE(GLOB files RELATIVE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/*/CMakeLists.txt
)

foreach (f ${files})
  get_filename_component(dir ${f} DIRECTORY)
  list(APPEND _vpp_drivers_list ${dir})
  add_subdirectory(${dir})
endforeach()
if(_vpp_drivers_list)
  list(SORT _vpp_drivers_list)
endif()
set(_vpp_drivers_list ${_vpp_drivers_list} PARENT_SCOPE)
