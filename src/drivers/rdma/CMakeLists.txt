# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

vpp_find_path(IBVERBS_INCLUDE_DIR NAMES infiniband/verbs.h)

if (NOT IBVERBS_INCLUDE_DIR)
  message(WARNING "-- rdma headers not found - rdma driver disabled")
  return()
endif()

vpp_driver_find_library(rdma IBVERBS_LIB libibverbs.a)
vpp_driver_find_library(rdma MLX4_LIB libmlx4.a)
vpp_driver_find_library(rdma MLX5_LIB libmlx5.a)

if (NOT IBVERBS_LIB OR NOT MLX4_LIB OR NOT MLX5_LIB)
  message(WARNING "rdma driver - ibverbs/mlx4/mlx5 not found - rdma driver disabled")
  return()
endif()

string_append(RDMA_LINK_FLAGS "-Wl,--whole-archive,${MLX4_LIB},${MLX5_LIB},--no-whole-archive -Wl,--exclude-libs,ALL")

set(CMAKE_REQUIRED_FLAGS "-fPIC -shared -pthread -Wno-unused-command-line-argument ${RDMA_LINK_FLAGS} ${IBVERBS_LIB}")
set(CMAKE_REQUIRED_INCLUDES "${IBVERBS_INCLUDE_DIR}")
set(CMAKE_REQUIRED_LIBRARIES "c")
CHECK_C_SOURCE_COMPILES("
#include <infiniband/verbs.h>
int main(void)
{
    return 0 != ibv_get_device_list(0);
}" IBVERBS_COMPILES_CHECK)

if (NOT IBVERBS_COMPILES_CHECK)
  message(WARNING "rdma driver - no working ibverbs found - rdma driver disabled")
  return()
endif()

add_vpp_driver(rdma
  SOURCES
  common/format.c
  common/flow.c
  common/port.c
  common/queue.c
  common/sysfs.c
  ibv/format.c
  ibv/init.c
  ibv/port.c
  ibv/queue.c
  ibv/rx_node.c
  ibv/tx_node.c
  mlx5/common.c
  mlx5/counters.c
  mlx5/format.c
  mlx5/init.c
  mlx5/port.c
  mlx5/queue.c
  mlx5/rx_node_base.c
  mlx5/rx_node_mini_cqe.c
  mlx5/rx_node_striding.c
  mlx5/tx_node_empw.c
  mlx5/tx_node_mpw.c
  init.c

  MULTIARCH_SOURCES
  ibv/rx_node.c
  ibv/tx_node.c
  mlx5/rx_node_base.c
  mlx5/rx_node_mini_cqe.c
  mlx5/rx_node_striding.c
  mlx5/tx_node_empw.c
  mlx5/tx_node_mpw.c

  INCLUDE_DIRECTORIES
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/ibv
  ${CMAKE_CURRENT_SOURCE_DIR}/mlx5
  ${IBVERBS_INCLUDE_DIR}

  LINK_FLAGS
  "${RDMA_LINK_FLAGS}"

  LINK_LIBRARIES
  ${IBVERBS_LIB}
)
