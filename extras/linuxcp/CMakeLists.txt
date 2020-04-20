# Copyright (c) 2017 Cisco and/or its affiliates.
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

project(linxcp)
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
  message(STATUS "No build type selected, default to Debug")
  set(CMAKE_BUILD_TYPE "Debug")
endif ()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -Werror -Wall")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib)
set(CMAKE_INSTALL_MESSAGE NEVER)

find_package(VPP)
find_package(Threads REQUIRED)
include_directories(${CMAKE_THREADS_INCLUDE_DIRS})

add_subdirectory(agent)
add_subdirectory(plugin)

add_vpp_packaging(
  NAME "linuxcp"
  VENDOR "fd.io"
  DESCRIPTION "Linux Control Plane Integration"
)
