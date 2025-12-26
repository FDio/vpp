# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

# Add local include paths for plugins.
include_directories (
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

# Configure requested plugins list.
set(VPP_PLUGINS
  ""
  CACHE
  STRING "Comma-separated list of plugins included in build"
)

# Configure excluded plugins list.
set(VPP_EXCLUDED_PLUGINS
  ""
  CACHE
  STRING "Comma-separated list of core plugins excluded from packaging and tests"
)

# Parse plugin selection lists.
set(VPP_PLUGINS_FILTER "")
set(VPP_PLUGINS_EXCLUDE "")

# Allow explicit disable without scanning subdirs.
if(VPP_PLUGINS STREQUAL "none")
  message(STATUS "VPP plugins explicitly disabled")
  return()
endif()

if(DEFINED VPP_PLUGINS AND NOT VPP_PLUGINS STREQUAL "")
  string(REGEX REPLACE "[ \t]*,[ \t]*" ";" VPP_PLUGINS_FILTER "${VPP_PLUGINS}")
  list(FILTER VPP_PLUGINS_FILTER EXCLUDE REGEX "^$")
endif()

if(DEFINED VPP_EXCLUDED_PLUGINS AND NOT VPP_EXCLUDED_PLUGINS STREQUAL "")
  string(REGEX REPLACE "[,]+" ";" VPP_PLUGINS_EXCLUDE "${VPP_EXCLUDED_PLUGINS}")
  list(FILTER VPP_PLUGINS_EXCLUDE EXCLUDE REGEX "^$")
endif()

# Initialize built list and request sentinels for validation.
set_property(GLOBAL PROPERTY VPP_PLUGINS_LIST "")
set_property(GLOBAL PROPERTY VPP_PLUGINS_ALL_LIST "")
if(DEFINED VPP_PLUGINS AND NOT VPP_PLUGINS STREQUAL "" AND NOT VPP_PLUGINS STREQUAL "none")
  set(_vpp_plugins_filter ${VPP_PLUGINS_FILTER})
  list(APPEND _vpp_plugins_filter "__EOL__")
  set_property(GLOBAL PROPERTY VPP_PLUGINS_FILTER "${_vpp_plugins_filter}")
endif()
if(DEFINED VPP_EXCLUDED_PLUGINS AND NOT VPP_EXCLUDED_PLUGINS STREQUAL "")
  set(_vpp_plugins_exclude ${VPP_PLUGINS_EXCLUDE})
  list(APPEND _vpp_plugins_exclude "__EOL__")
  set_property(GLOBAL PROPERTY VPP_PLUGINS_EXCLUDE "${_vpp_plugins_exclude}")
endif()

# Discover and add all plugin subdirs.
# find and add all plugin subdirs
FILE(GLOB files RELATIVE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/*/CMakeLists.txt
)

foreach (f ${files})
  get_filename_component(dir ${f} DIRECTORY)
  add_subdirectory(${dir})
endforeach()

# Normalize the built plugins list for summary output.
get_property(VPP_PLUGINS_LIST GLOBAL PROPERTY VPP_PLUGINS_LIST)
list(REMOVE_DUPLICATES VPP_PLUGINS_LIST)
list(SORT VPP_PLUGINS_LIST)
set(VPP_PLUGINS_LIST ${VPP_PLUGINS_LIST} PARENT_SCOPE)

# Fail if any requested plugins were not found/registered.
get_property(_vpp_plugins_filter GLOBAL PROPERTY VPP_PLUGINS_FILTER)
vpp_check_consumed_list(_vpp_plugins_filter "VPP_PLUGINS requested but not found")

# Fail if excluded plugin names were not found/registered.
get_property(_vpp_plugins_exclude GLOBAL PROPERTY VPP_PLUGINS_EXCLUDE)
vpp_check_consumed_list(_vpp_plugins_exclude "VPP_EXCLUDED_PLUGINS refers to unknown plugin(s)")
