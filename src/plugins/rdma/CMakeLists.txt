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

message(STATUS "RDMA plugins - looking for ibverbs")

find_path(IBVERBS_INCLUDE_DIR NAMES infiniband/verbs.h)
find_library(IBVERBS_LIB NAMES libibverbs.a)
find_library(MLX5_LIB NAMES libmlx5.a)

if (NOT IBVERBS_LIB OR NOT MLX5_LIB)
  message(WARNING "RDMA plugins - ibverbs not found - rdma_plugin disabled")
  return()
endif()

if (MLX5_LIB)
  string_append(RDMA_LINK_FLAGS "-Wl,--whole-archive,${MLX5_LIB},--no-whole-archive")
endif()

set(CMAKE_REQUIRED_FLAGS "-fPIC -shared ${IBVERBS_LIB} ${RDMA_LINK_FLAGS}")
CHECK_C_SOURCE_COMPILES("" IBVERBS_COMPILES_CHECK)

if (NOT IBVERBS_COMPILES_CHECK)
  message(WARNING "RDMA plugins - no working ibverbs found - rdma_plugin disabled")
  return()
endif()

message(STATUS "RDMA plugins - found ${IBVERBS_INCLUDE_DIR}")
message(STATUS "RDMA plugins - found ${IBVERBS_LIB}")
message(STATUS "RDMA plugins - found ${MLX5_LIB}")

include_directories(${IBVERBS_INCLUDE_DIR})

add_vpp_plugin(rdma
  SOURCES
  cli.c
  device.c
  format.c
  plugin.c
  input.c
  output.c

  MULTIARCH_SOURCES
  input.c
  output.c

  LINK_FLAGS
  "${RDMA_LINK_FLAGS}"

  LINK_LIBRARIES
  ${IBVERBS_LIB}
)
