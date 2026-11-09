# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022-2026 Cisco Systems, Inc.

include(${CMAKE_CURRENT_LIST_DIR}/../../common/octeon/octeon.cmake)
octeon_driver_prereqs(octeon_net)

add_vpp_driver(octeon_net
  SOURCES
  init.c
  format.c
  port.c
  queue.c
  rx_node.c
  tx_node.c
  flow.c
  counter.c
  tm.c
  ${OCTEON_COMMON_SOURCES}

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c

  INCLUDE_DIRECTORIES
  ${OCTEON_COMMON_DIR}

  LINK_LIBRARIES
  ${OCTEON_ROC_LIB}
)
