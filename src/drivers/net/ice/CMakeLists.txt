# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Damjan Marion

add_vpp_driver(ice
  SOURCES
  adminq.c
  adminq_format.c
  cli.c
  counters.c
  format.c
  init.c
  phy.c
  phy_format.c
  port.c
  queue.c
  rss.c
  rss_format.c
  rx_node.c
  tx_node.c
  vsi_format.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)
