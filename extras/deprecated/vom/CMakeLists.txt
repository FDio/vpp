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

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project(vom)

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

unset (VOM_LIB_VERSION)
execute_process(
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  COMMAND bash -c "git describe | cut -f1 -d- | cut -dv -f2"
  OUTPUT_VARIABLE VOM_LIB_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib)
set(CMAKE_INSTALL_MESSAGE NEVER)

find_package(VPP)
find_package(Threads REQUIRED)
find_package(Boost OPTIONAL_COMPONENTS system filesystem)

add_subdirectory(vom)
add_subdirectory(cmake)

add_vpp_packaging(
  NAME "vom"
  VENDOR "fd.io"
  DESCRIPTION "VPP Object Model"
)
