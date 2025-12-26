# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

# Configure requested drivers list.
set(VPP_DRIVERS
  ""
  CACHE
  STRING "Comma-separated list of drivers included in build"
)

# Parse driver selection list.
set(VPP_DRIVERS_FILTER "")

# Allow explicit disable without scanning subdirs.
if(VPP_DRIVERS STREQUAL "none")
  message(STATUS "VPP crypto engines explicitly disabled")
  return()
endif()


if(DEFINED VPP_DRIVERS AND NOT VPP_DRIVERS STREQUAL "")
  string(REGEX REPLACE "[ \t]*,[ \t]*" ";" VPP_DRIVERS_FILTER "${VPP_DRIVERS}")
  list(FILTER VPP_DRIVERS_FILTER EXCLUDE REGEX "^$")
endif()

# Initialize built list and request sentinel for validation.
set_property(GLOBAL PROPERTY VPP_DRIVERS_LIST "")
if(DEFINED VPP_DRIVERS AND NOT VPP_DRIVERS STREQUAL "" AND NOT VPP_DRIVERS STREQUAL "none")
  set(_vpp_drivers_filter ${VPP_DRIVERS_FILTER})
  list(APPEND _vpp_drivers_filter "__EOL__")
  set_property(GLOBAL PROPERTY VPP_DRIVERS_FILTER "${_vpp_drivers_filter}")
endif()

# discover and add all driver subdirs
FILE(GLOB files RELATIVE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/*/CMakeLists.txt
)

foreach (f ${files})
  get_filename_component(dir ${f} DIRECTORY)
  add_subdirectory(${dir})
endforeach()

# Normalize the built drivers list for summary output.
get_property(_vpp_drivers_list GLOBAL PROPERTY VPP_DRIVERS_LIST)
list(REMOVE_DUPLICATES _vpp_drivers_list)
list(SORT _vpp_drivers_list)
set(VPP_DRIVERS_LIST ${_vpp_drivers_list} PARENT_SCOPE)

# Fail if any requested drivers were not found/registered.
get_property(_vpp_drivers_filter GLOBAL PROPERTY VPP_DRIVERS_FILTER)
vpp_check_consumed_list(_vpp_drivers_filter "VPP_DRIVERS requested but not found")
