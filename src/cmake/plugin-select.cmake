# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

# Used by the enable-plugin-<name> and disable-plugin-<name> targets:
#
#   cmake -DACTION=enable|disable -DPLUGIN=<name> -DVPP_PLUGINS=<list>
#         -DVPP_EXCLUDED_PLUGINS=<list> -DBUILD_DIR=<dir> -P plugin-select.cmake
#
# VPP_PLUGINS is the list of the plugins to build, when it is empty all
# plugins are built except the ones in VPP_EXCLUDED_PLUGINS, and "none"
# builds no plugin. The lists are changed so that the plugin is in or out of
# the build, and the build directory is configured again.

# the names of the plugins have dashes, underscores are accepted as well
string(REPLACE "_" "-" PLUGIN "${PLUGIN}")
string(REPLACE "_" "-" VPP_PLUGINS "${VPP_PLUGINS}")
string(REPLACE "_" "-" VPP_EXCLUDED_PLUGINS "${VPP_EXCLUDED_PLUGINS}")

string(REGEX REPLACE "[ \t]*,[ \t]*" ";" plugins "${VPP_PLUGINS}")
string(REGEX REPLACE "[ \t]*,[ \t]*" ";" excluded "${VPP_EXCLUDED_PLUGINS}")
list(FILTER plugins EXCLUDE REGEX "^$")
list(FILTER excluded EXCLUDE REGEX "^$")

if(plugins STREQUAL "none")
  set(mode none)
  set(plugins "")
elseif(plugins)
  set(mode list)
else()
  set(mode all)
endif()

if(ACTION STREQUAL "enable")
  if(mode STREQUAL "all")
    list(REMOVE_ITEM excluded ${PLUGIN})
  else()
    list(APPEND plugins ${PLUGIN})
  endif()
elseif(ACTION STREQUAL "disable")
  if(mode STREQUAL "all")
    list(APPEND excluded ${PLUGIN})
  else()
    list(REMOVE_ITEM plugins ${PLUGIN})
  endif()
else()
  message(FATAL_ERROR "ACTION must be enable or disable")
endif()

list(REMOVE_DUPLICATES plugins)
list(REMOVE_DUPLICATES excluded)

if(NOT mode STREQUAL "all" AND NOT plugins)
  set(plugins none)
endif()

string(REPLACE ";" "," plugins "${plugins}")
string(REPLACE ";" "," excluded "${excluded}")

execute_process(
  COMMAND ${CMAKE_COMMAND} -DVPP_PLUGINS=${plugins} -DVPP_EXCLUDED_PLUGINS=${excluded} .
  WORKING_DIRECTORY ${BUILD_DIR}
  RESULT_VARIABLE result
)

if(NOT result EQUAL 0)
  message(FATAL_ERROR "configuring the build with the new plugin list failed")
endif()

message(STATUS "${ACTION} ${PLUGIN}: VPP_PLUGINS='${plugins}' VPP_EXCLUDED_PLUGINS='${excluded}'")
message(STATUS "run ninja to build")
