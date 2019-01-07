# Copyright (c) 2019 Cisco and/or its affiliates.
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

set(HEADERS_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(TEST_NAME libmemif-test)
set(TEST_LIBS m rt)

find_package(Subunit QUIET)
if (NOT SUBUNIT_LIBRARY)
  set(SUBUNIT_LIBRARY "")
endif ()

set(SOURCE_FILES
  main_test.c
  socket_test.c
  unit_test.c
)

add_executable(${TEST_NAME} ${SOURCE_FILES})
target_include_directories(${TEST_NAME} PRIVATE $<BUILD_INTERFACE:${HEADERS_DIR}>)
target_link_libraries(${TEST_NAME} ${LIBMEMIF} ${CHECK_LIBRARY} ${SUBUNIT_LIBRARY} ${TEST_LIBS} ${CMAKE_THREAD_LIBS_INIT})

add_test(unit_test unit-test)