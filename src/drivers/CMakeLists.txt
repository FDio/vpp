# Copyright (c) 2025 Cisco Systems, Inc.
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

set(VPP_DRIVERS
  ""
  CACHE
  STRING "Comma-separated list of drivers included in build"
)

if(NOT VPP_DRIVERS STREQUAL "")
  if(VPP_DRIVERS STREQUAL "none")
    message(STATUS "VPP drivers explicitly disabled")
    return()
  endif()

  string(REGEX REPLACE "[ \t]*,[ \t]*" ";" _drivers "${VPP_DRIVERS}")
  list(FILTER _drivers EXCLUDE REGEX "^$")

  foreach(d IN LISTS _drivers)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${d}/CMakeLists.txt")
      add_subdirectory("${d}")
    else()
      message(FATAL_ERROR
        "VPP driver '${d}' not found: expected '${CMAKE_CURRENT_SOURCE_DIR}/${d}/CMakeLists.txt'")
    endif()
  endforeach()
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
  add_subdirectory(${dir})
endforeach()
