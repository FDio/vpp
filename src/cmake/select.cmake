# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

# Used by the enable-<kind>-<name> and disable-<kind>-<name> targets:
#
#   cmake -DKIND=plugin|driver|crypto-engine|tool|test -DACTION=enable|disable
#         -DNAME=<name> -DSELECTED=<list> -DEXCLUDED=<list> -DALL=<list>
#         -DBUILD_DIR=<dir> -P select.cmake
#
# SELECTED is the list of the items to build (VPP_PLUGINS, VPP_DRIVERS,
# VPP_CRYPTO_ENGINES, VPP_TOOLS or VPP_TESTS), when it is empty everything is
# built, except the items in EXCLUDED (VPP_EXCLUDED_PLUGINS, plugins only), and
# "none" builds nothing.
# ALL is the list of all items, it is needed to take one out of a build which
# has no exclude list. The lists are changed so that the item is in or out of
# the build, and the build directory is configured again.

set(old_selected "${SELECTED}")
set(old_excluded "${EXCLUDED}")

if(KIND STREQUAL "plugin")
  set(selected_var VPP_PLUGINS)
  set(excluded_var VPP_EXCLUDED_PLUGINS)
  # the names of the plugins have dashes, underscores are accepted as well
  string(REPLACE "_" "-" NAME "${NAME}")
  string(REPLACE "_" "-" SELECTED "${SELECTED}")
  string(REPLACE "_" "-" EXCLUDED "${EXCLUDED}")
elseif(KIND STREQUAL "driver")
  set(selected_var VPP_DRIVERS)
elseif(KIND STREQUAL "crypto-engine")
  set(selected_var VPP_CRYPTO_ENGINES)
elseif(KIND STREQUAL "tool")
  set(selected_var VPP_TOOLS)
elseif(KIND STREQUAL "test")
  set(selected_var VPP_TESTS)
else()
  message(FATAL_ERROR "KIND must be plugin, driver, crypto-engine, tool or test")
endif()

string(REGEX REPLACE "[ \t]*,[ \t]*" ";" items "${SELECTED}")
string(REGEX REPLACE "[ \t]*,[ \t]*" ";" excluded "${EXCLUDED}")
string(REGEX REPLACE "[ \t]*,[ \t]*" ";" all "${ALL}")
list(FILTER items EXCLUDE REGEX "^$")
list(FILTER excluded EXCLUDE REGEX "^$")

if(items STREQUAL "none")
  set(mode none)
  set(items "")
elseif(items)
  set(mode list)
else()
  set(mode all)
endif()

if(ACTION STREQUAL "enable")
  if(mode STREQUAL "all")
    list(REMOVE_ITEM excluded ${NAME})
  else()
    list(APPEND items ${NAME})
  endif()
elseif(ACTION STREQUAL "disable")
  if(mode STREQUAL "all" AND excluded_var)
    list(APPEND excluded ${NAME})
  elseif(mode STREQUAL "all")
    set(items ${all})
    list(REMOVE_ITEM items ${NAME})
  else()
    list(REMOVE_ITEM items ${NAME})
  endif()
else()
  message(FATAL_ERROR "ACTION must be enable or disable")
endif()

list(REMOVE_DUPLICATES items)
list(REMOVE_DUPLICATES excluded)

if(NOT mode STREQUAL "all" AND NOT items)
  set(items none)
elseif(mode STREQUAL "all" AND NOT excluded_var AND ACTION STREQUAL "disable" AND NOT items)
  set(items none)
endif()

string(REPLACE ";" "," items "${items}")
string(REPLACE ";" "," excluded "${excluded}")

set(defs -D${selected_var}=${items})
if(excluded_var)
  list(APPEND defs -D${excluded_var}=${excluded})
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} ${defs} .
  WORKING_DIRECTORY ${BUILD_DIR}
  RESULT_VARIABLE result
)

if(NOT result EQUAL 0)
  # do not leave the build directory with lists which do not configure
  set(defs -D${selected_var}=${old_selected})
  if(excluded_var)
    list(APPEND defs -D${excluded_var}=${old_excluded})
  endif()
  execute_process(COMMAND ${CMAKE_COMMAND} ${defs} . WORKING_DIRECTORY ${BUILD_DIR}
                  OUTPUT_QUIET ERROR_QUIET)
  message(FATAL_ERROR "${ACTION} ${KIND} ${NAME} failed, the build is not changed")
endif()

message(STATUS "${ACTION} ${KIND} ${NAME}: ${selected_var}='${items}'")
if(excluded_var)
  message(STATUS "${excluded_var}='${excluded}'")
endif()
message(STATUS "run ninja to build")
