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
include(CheckFunctionExists)

set(HEADERS_DIR ${CMAKE_CURRENT_SOURCE_DIR})

list(APPEND MEMIF_HEADERS
  libmemif.h
  memif.h
)

list(APPEND MEMIF_PRIVATE_HEADERS
  memif_private.h
  socket.h
)

list(APPEND MEMIF_SOURCES
  main.c
  socket.c
)

include_directories(${HEADERS_DIR})
if (NOT CMAKE_LIBRARY_OUTPUT_DIRECTORY)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY /usr/lib)
endif ()

check_function_exists(memfd_create HAVE_MEMFD_CREATE)
if(${HAVE_MEMFD_CREATE})
  add_definitions(-DHAVE_MEMFD_CREATE)
endif()

add_library(memif SHARED ${MEMIF_SOURCES})
target_link_libraries(memif ${CMAKE_THREAD_LIBS_INIT})
foreach(file ${MEMIF_HEADERS})
  get_filename_component(dir ${file} DIRECTORY)
     install(
	FILES ${file}
	DESTINATION include/${lib}/${dir}
	COMPONENT libmemif-dev
      )
endforeach()

install(TARGETS memif DESTINATION lib COMPONENT libmemif)
