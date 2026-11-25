# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

# Add local include paths for crypto engines.
include_directories (
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

# Configure requested crypto engines list.
set(VPP_CRYPTO_ENGINES
  ""
  CACHE
  STRING "Comma-separated list of crypto engines included in build"
)

# Parse crypto engine selection list.
set(VPP_CRYPTO_ENGINES_FILTER "")

# Allow explicit disable without scanning subdirs.
if(VPP_CRYPTO_ENGINES STREQUAL "none")
  message(STATUS "VPP crypto engines explicitly disabled")
  return()
endif()

if(DEFINED VPP_CRYPTO_ENGINES AND NOT VPP_CRYPTO_ENGINES STREQUAL "")
  string(REGEX REPLACE "[ \t]*,[ \t]*" ";" VPP_CRYPTO_ENGINES_FILTER "${VPP_CRYPTO_ENGINES}")
  list(FILTER VPP_CRYPTO_ENGINES_FILTER EXCLUDE REGEX "^$")
endif()

# Initialize built list and request sentinel for validation.
set_property(GLOBAL PROPERTY VPP_CRYPTO_ENGINES_LIST "")
if(DEFINED VPP_CRYPTO_ENGINES AND NOT VPP_CRYPTO_ENGINES STREQUAL "" AND NOT VPP_CRYPTO_ENGINES STREQUAL "none")
  set(_vpp_crypto_engines_filter ${VPP_CRYPTO_ENGINES_FILTER})
  list(APPEND _vpp_crypto_engines_filter "__EOL__")
  set_property(GLOBAL PROPERTY VPP_CRYPTO_ENGINES_FILTER "${_vpp_crypto_engines_filter}")
endif()

# discover and add all crypto engine subdirs
FILE(GLOB files RELATIVE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/*/CMakeLists.txt
)

foreach (f ${files})
  get_filename_component(dir ${f} DIRECTORY)
  add_subdirectory(${dir})
endforeach()

# Normalize the built crypto engines list for summary output.
get_property(VPP_CRYPTO_ENGINES_LIST GLOBAL PROPERTY VPP_CRYPTO_ENGINES_LIST)
list(REMOVE_DUPLICATES VPP_CRYPTO_ENGINES_LIST)
list(SORT VPP_CRYPTO_ENGINES_LIST)
set(VPP_CRYPTO_ENGINES_LIST ${VPP_CRYPTO_ENGINES_LIST} PARENT_SCOPE)

# ninja enable-crypto-engine-<name> and ninja disable-crypto-engine-<name> change the list of
# crypto engines to build. The engines which are not built on this platform are not in the list
# of all engines.
vpp_find_registered_names(_vpp_engine_names add_vpp_crypto_engine ${CMAKE_CURRENT_SOURCE_DIR})
string(REPLACE ";" "," _vpp_engines_built "${VPP_CRYPTO_ENGINES_LIST}")
foreach(_name ${_vpp_engine_names})
  vpp_add_select_targets(crypto-engine ${_name} ${_name} "${VPP_CRYPTO_ENGINES}" "" "${_vpp_engines_built}")
endforeach()

# Fail if any requested crypto engines were not found/registered.
get_property(_vpp_crypto_engines_filter GLOBAL PROPERTY VPP_CRYPTO_ENGINES_FILTER)
vpp_check_consumed_list(_vpp_crypto_engines_filter "VPP_CRYPTO_ENGINES requested but not found")
