# Copyright (c) 2018-2019 Cisco and/or its affiliates.
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

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(memif)
set(CMAKE_C_STANDARD 11)

include(CheckCCompilerFlag)
include(CheckFunctionExists)

set(VPP_SRC "${CMAKE_CURRENT_SOURCE_DIR}/../../src")
execute_process(
  COMMAND find ${VPP_SRC} -type d -name "cmake"
  OUTPUT_VARIABLE CMAKE_DEPS_FOLDER
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
include(${CMAKE_DEPS_FOLDER}/library.cmake)
include(${CMAKE_DEPS_FOLDER}/pack.cmake)

if (NOT CMAKE_BUILD_TYPE)
  message(STATUS "No build type selected, default to Release")
  set(CMAKE_BUILD_TYPE "Release")
endif ()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -DMEMIF_DBG -DICMP_DBG")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib)
set(CMAKE_INSTALL_MESSAGE NEVER)

find_package(Threads REQUIRED)
include_directories(${CMAKE_THREADS_INCLUDE_DIRS})

check_function_exists(memfd_create HAVE_MEMFD_CREATE)
if(${HAVE_MEMFD_CREATE})
  add_definitions(-DHAVE_MEMFD_CREATE)
endif()

include_directories(src)
set(LIBMEMIF memif)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(Check 0.10.0)
if (CHECK_FOUND)
  include_directories(${CHECK_INCLUDE_DIR})
  add_definitions(-DMEMIF_UNIT_TEST)
  add_subdirectory(test)
  enable_testing()
endif ()

add_subdirectory(src)
add_subdirectory(examples)

add_vpp_packaging(
  NAME "memif"
  VENDOR "fd.io"
  DESCRIPTION "Shared Memory Interface"
)
