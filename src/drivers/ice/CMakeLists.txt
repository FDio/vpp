# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Damjan Marion

add_vpp_driver(ice
  SOURCES
  ice.c
  adminq.c
  port.c
  rss.c
  counters.c
  queue.c
  rx_node.c
  tx_node.c
  format.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)
