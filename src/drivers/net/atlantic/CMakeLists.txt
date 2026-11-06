# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Damjan Marion

add_vpp_driver(atlantic
  SOURCES
  atlantic.c
  regs.c
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
