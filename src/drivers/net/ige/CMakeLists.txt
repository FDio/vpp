# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2024 Cisco Systems, Inc.

add_vpp_driver(ige
  SOURCES
  counters.c
  ige.c
  format.c
  phy.c
  port.c
  queue.c
  reg.c
  rx_node.c
  tx_node.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)

