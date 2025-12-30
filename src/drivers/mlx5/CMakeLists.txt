# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

vpp_find_path(IBVERBS_INCLUDE_DIR NAMES infiniband/verbs.h)

if (NOT IBVERBS_INCLUDE_DIR)
  message(WARNING "-- rdma headers not found - mlx5 plugin disabled")
  return()
endif()

vpp_plugin_find_library(rdma IBVERBS_LIB libibverbs.a)
vpp_plugin_find_library(rdma MLX5_LIB libmlx5.a)

if (NOT IBVERBS_LIB OR NOT MLX5_LIB)
  message(WARNING "mlx5 plugin - ibverbs/mlx5 not found - mlx5 plugin disabled")
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
  message(WARNING "mlx5 plugin - no working ibverbs found - mlx5 plugin disabled")
  return()
endif()

add_vpp_driver(mlx5
  SOURCES
  common.c
  flow.c
  format.c
  init.c
  port.c
  queue.c
  rx_node.c
  tx_node.c
  plugin.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c

  INCLUDE_DIRECTORIES
  ${IBVERBS_INCLUDE_DIR}

  LINK_FLAGS
  "${RDMA_LINK_FLAGS}"

  LINK_LIBRARIES
  ${IBVERBS_LIB}
)
