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

include_directories (
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
)

set(VPP_CRYPTO_ENGINES
  ""
  CACHE
  STRING "Comma-separated list of crypto engines included in build"
)

set(VPP_CRYPTO_ENGINES_FILTER "")

if(DEFINED VPP_CRYPTO_ENGINES AND NOT VPP_CRYPTO_ENGINES STREQUAL "")
  string(REGEX REPLACE "[ \t]*,[ \t]*" ";" VPP_CRYPTO_ENGINES_FILTER "${VPP_CRYPTO_ENGINES}")
  list(FILTER VPP_CRYPTO_ENGINES_FILTER EXCLUDE REGEX "^$")
endif()

set_property(GLOBAL PROPERTY VPP_CRYPTO_ENGINES_LIST "")
if(DEFINED VPP_CRYPTO_ENGINES AND NOT VPP_CRYPTO_ENGINES STREQUAL "" AND NOT VPP_CRYPTO_ENGINES STREQUAL "none")
  set(_vpp_crypto_engines_filter ${VPP_CRYPTO_ENGINES_FILTER})
  list(APPEND _vpp_crypto_engines_filter "__EOL__")
  set_property(GLOBAL PROPERTY VPP_CRYPTO_ENGINES_FILTER "${_vpp_crypto_engines_filter}")
endif()
if(NOT VPP_CRYPTO_ENGINES STREQUAL "")
  if(VPP_CRYPTO_ENGINES STREQUAL "none")
    message(STATUS "VPP crypto engines explicitly disabled")
    set(VPP_CRYPTO_ENGINES_LIST "none")
    set(VPP_CRYPTO_ENGINES_LIST ${VPP_CRYPTO_ENGINES_LIST} PARENT_SCOPE)
    return()
  endif()

  foreach(e IN LISTS VPP_CRYPTO_ENGINES_FILTER)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${e}/CMakeLists.txt")
      add_subdirectory("${e}")
    else()
      message(FATAL_ERROR
        "VPP crypto engine '${e}' not found: expected '${CMAKE_CURRENT_SOURCE_DIR}/${e}/CMakeLists.txt'")
    endif()
  endforeach()
  get_property(VPP_CRYPTO_ENGINES_LIST GLOBAL PROPERTY VPP_CRYPTO_ENGINES_LIST)
  list(REMOVE_DUPLICATES VPP_CRYPTO_ENGINES_LIST)
  list(SORT VPP_CRYPTO_ENGINES_LIST)
  set(VPP_CRYPTO_ENGINES_LIST ${VPP_CRYPTO_ENGINES_LIST} PARENT_SCOPE)
  get_property(_vpp_crypto_engines_filter GLOBAL PROPERTY VPP_CRYPTO_ENGINES_FILTER)
  list(REMOVE_ITEM _vpp_crypto_engines_filter "__EOL__")
  if(_vpp_crypto_engines_filter)
    message(FATAL_ERROR "VPP_CRYPTO_ENGINES requested but not found: ${_vpp_crypto_engines_filter}")
  endif()
  return()
endif()

##############################################################################
# find and add all crypto engine subdirs
##############################################################################
FILE(GLOB files RELATIVE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/*/CMakeLists.txt
)

foreach (f ${files})
  get_filename_component(dir ${f} DIRECTORY)
  if(NOT VPP_CRYPTO_ENGINES STREQUAL "")
    list(FIND VPP_CRYPTO_ENGINES_FILTER "${dir}" vpp_crypto_idx)
    if(vpp_crypto_idx EQUAL -1)
      continue()
    endif()
  endif()
  add_subdirectory(${dir})
endforeach()
get_property(VPP_CRYPTO_ENGINES_LIST GLOBAL PROPERTY VPP_CRYPTO_ENGINES_LIST)
list(REMOVE_DUPLICATES VPP_CRYPTO_ENGINES_LIST)
list(SORT VPP_CRYPTO_ENGINES_LIST)
set(VPP_CRYPTO_ENGINES_LIST ${VPP_CRYPTO_ENGINES_LIST} PARENT_SCOPE)

if(DEFINED VPP_CRYPTO_ENGINES AND NOT VPP_CRYPTO_ENGINES STREQUAL "" AND NOT VPP_CRYPTO_ENGINES STREQUAL "none")
  get_property(_vpp_crypto_engines_filter GLOBAL PROPERTY VPP_CRYPTO_ENGINES_FILTER)
  list(REMOVE_ITEM _vpp_crypto_engines_filter "__EOL__")
  if(_vpp_crypto_engines_filter)
    message(FATAL_ERROR "VPP_CRYPTO_ENGINES requested but not found: ${_vpp_crypto_engines_filter}")
  endif()
endif()
