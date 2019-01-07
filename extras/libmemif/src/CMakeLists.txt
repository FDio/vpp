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

add_vpp_library(${LIBMEMIF}
  SOURCES ${MEMIF_SOURCES}

  INSTALL_HEADERS ${MEMIF_HEADERS}

  LINK_LIBRARIES ${CMAKE_THREAD_LIBS_INIT}

  COMPONENT libmemif
)
