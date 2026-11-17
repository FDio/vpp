# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Damjan Marion

include(${CMAKE_CURRENT_LIST_DIR}/../../common/rdma/rdma.cmake)
rdma_driver_prereqs(mlx5)

add_vpp_driver(mlx5
  SOURCES
  counters.c
  format.c
  init.c
  port.c
  queue.c
  rx_node_legacy.c
  rx_node_striding.c
  tx_node.c
  ${RDMA_COMMON_SOURCES}

  MULTIARCH_SOURCES
  rx_node_legacy.c
  rx_node_striding.c
  tx_node.c

  INCLUDE_DIRECTORIES
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${RDMA_COMMON_INCLUDE_DIR}
  ${IBVERBS_INCLUDE_DIR}

  LINK_FLAGS
  "${RDMA_LINK_FLAGS}"

  LINK_LIBRARIES
  ${IBVERBS_LIB}
)
