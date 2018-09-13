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

project(japi VERSION 18.10)

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib)
set(CMAKE_INSTALL_MESSAGE NEVER)

find_package(Threads REQUIRED)
find_package(Java REQUIRED)

message("Java_FOUND " ${Java_FOUND})
message("Found javah at: " ${Java_JAVAH_EXECUTABLE})
string(REGEX MATCH "(.*)bin\/javah.*" Java_root ${Java_JAVAH_EXECUTABLE})
message("Found java root at: " ${CMAKE_MATCH_1})
set(JAVA_DIR "${CMAKE_MATCH_1}")

add_subdirectory(java)
