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

set(_vpp_crypto_engines_list "")
if(NOT VPP_CRYPTO_ENGINES STREQUAL "")
  if(VPP_CRYPTO_ENGINES STREQUAL "none")
    message(STATUS "VPP crypto engines explicitly disabled")
    set(_vpp_crypto_engines_list "none")
    set(_vpp_crypto_engines_list ${_vpp_crypto_engines_list} PARENT_SCOPE)
    return()
  endif()

  string(REGEX REPLACE "[ \t]*,[ \t]*" ";" _vpp_crypto_engines_list "${VPP_CRYPTO_ENGINES}")
  list(FILTER _vpp_crypto_engines_list EXCLUDE REGEX "^$")

  foreach(e IN LISTS _vpp_crypto_engines_list)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${e}/CMakeLists.txt")
      add_subdirectory("${e}")
    else()
      message(FATAL_ERROR
        "VPP crypto engine '${e}' not found: expected '${CMAKE_CURRENT_SOURCE_DIR}/${e}/CMakeLists.txt'")
    endif()
  endforeach()
  list(SORT _vpp_crypto_engines_list)
  set(_vpp_crypto_engines_list ${_vpp_crypto_engines_list} PARENT_SCOPE)
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
  list(APPEND _vpp_crypto_engines_list ${dir})
  add_subdirectory(${dir})
endforeach()
if(_vpp_crypto_engines_list)
  list(SORT _vpp_crypto_engines_list)
endif()
set(_vpp_crypto_engines_list ${_vpp_crypto_engines_list} PARENT_SCOPE)
