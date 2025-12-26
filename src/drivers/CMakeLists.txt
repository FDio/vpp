# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

set(VPP_DRIVERS
  ""
  CACHE
  STRING "Comma-separated list of drivers included in build"
)

set(VPP_DRIVERS_FILTER "")

if(DEFINED VPP_DRIVERS AND NOT VPP_DRIVERS STREQUAL "")
  string(REGEX REPLACE "[ \t]*,[ \t]*" ";" VPP_DRIVERS_FILTER "${VPP_DRIVERS}")
  list(FILTER VPP_DRIVERS_FILTER EXCLUDE REGEX "^$")
endif()

set_property(GLOBAL PROPERTY VPP_DRIVERS_LIST "")
if(DEFINED VPP_DRIVERS AND NOT VPP_DRIVERS STREQUAL "" AND NOT VPP_DRIVERS STREQUAL "none")
  set(_vpp_drivers_filter ${VPP_DRIVERS_FILTER})
  list(APPEND _vpp_drivers_filter "__EOL__")
  set_property(GLOBAL PROPERTY VPP_DRIVERS_FILTER "${_vpp_drivers_filter}")
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
  if(NOT VPP_DRIVERS STREQUAL "")
    list(FIND VPP_DRIVERS_FILTER "${dir}" vpp_driver_idx)
    if(vpp_driver_idx EQUAL -1)
      continue()
    endif()
  endif()
  add_subdirectory(${dir})
endforeach()
get_property(_vpp_drivers_list GLOBAL PROPERTY VPP_DRIVERS_LIST)
list(REMOVE_DUPLICATES _vpp_drivers_list)
list(SORT _vpp_drivers_list)
set(VPP_DRIVERS_LIST ${_vpp_drivers_list} PARENT_SCOPE)

if(DEFINED VPP_DRIVERS AND NOT VPP_DRIVERS STREQUAL "" AND NOT VPP_DRIVERS STREQUAL "none")
  get_property(_vpp_drivers_filter GLOBAL PROPERTY VPP_DRIVERS_FILTER)
  list(REMOVE_ITEM _vpp_drivers_filter "__EOL__")
  if(_vpp_drivers_filter)
    message(FATAL_ERROR "VPP_DRIVERS requested but not found: ${_vpp_drivers_filter}")
  endif()
endif()
