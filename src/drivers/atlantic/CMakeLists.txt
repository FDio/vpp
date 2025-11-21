# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2024 Cisco Systems, Inc.

add_vpp_driver(atlantic
  SOURCES
  atlantic.c
  port.c
  queue.c
  rx_node.c
  tx_node.c
  format.c
  utils.c
  counters.c
  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)
