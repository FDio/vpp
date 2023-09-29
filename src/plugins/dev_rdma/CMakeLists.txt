# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

vpp_find_path(IBVERBS_INCLUDE_DIR NAMES infiniband/verbs.h)

if (NOT IBVERBS_INCLUDE_DIR)
  message(WARNING "-- rdma headers not found - rdma plugin disabled")
  return()
endif()

vpp_plugin_find_library(rdma IBVERBS_LIB libibverbs.a)
vpp_plugin_find_library(rdma MLX5_LIB libmlx5.a)

if (NOT IBVERBS_LIB OR NOT MLX5_LIB)
  message(WARNING "rdma plugin - ibverbs not found - rdma plugin disabled")
  return()
endif()

string_append(RDMA_LINK_FLAGS "-Wl,--whole-archive,${MLX5_LIB},--no-whole-archive -Wl,--exclude-libs,ALL")

set(CMAKE_REQUIRED_FLAGS "-fPIC -shared -pthread -Wno-unused-command-line-argument ${RDMA_LINK_FLAGS} ${IBVERBS_LIB}")
set(CMAKE_REQUIRED_INCLUDES "${IBVERBS_INCLUDE_DIR}")
set(CMAKE_REQUIRED_LIBRARIES "c") # force linkage by including libc explicitely
CHECK_C_SOURCE_COMPILES("
#include <infiniband/verbs.h>
int main(void)
{
    return 0 != ibv_get_device_list(0);
}" IBVERBS_COMPILES_CHECK)

if (NOT IBVERBS_COMPILES_CHECK)
  message(WARNING "rdma plugins - no working ibverbs found - rdma plugin disabled")
  return()
endif()

include_directories(${IBVERBS_INCLUDE_DIR})

add_vpp_plugin(dev_rdma
  SOURCES
  bus.c
  common.c
  generic.c
  mlx5.c
  plugin.c

  LINK_FLAGS
  "${RDMA_LINK_FLAGS}"

  LINK_LIBRARIES
  ${IBVERBS_LIB}
)

