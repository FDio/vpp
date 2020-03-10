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

set(HEADERS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/icmp_proto)

set(COMMON_SOURCE_FILES
    icmp_proto/icmp_proto.c)

list(APPEND EXAMPLES_LIST
  ping_responder/main.c
  ping_responder-per_thread/main.c
  ping/main.c
)

foreach (EXAMPLE_SRC ${EXAMPLES_LIST})
  string(FIND ${EXAMPLE_SRC} "/" INDEX)
  string(SUBSTRING ${EXAMPLE_SRC} 0 ${INDEX} EXECUTABLE)

  if(${EXECUTABLE} STREQUAL  ping)
    add_executable(${EXECUTABLE} ping/parser.c ping/set_events.c ${COMMON_SOURCE_FILES} ${EXAMPLE_SRC})
  else()
    add_executable(${EXECUTABLE} ${COMMON_SOURCE_FILES} ${EXAMPLE_SRC})
  endif()

  target_include_directories(${EXECUTABLE} PRIVATE $<BUILD_INTERFACE:${HEADERS_DIR}>)
  target_link_libraries(${EXECUTABLE} memif ${CMAKE_THREAD_LIBS_INIT})
endforeach()
