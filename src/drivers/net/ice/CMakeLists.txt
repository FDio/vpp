# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Damjan Marion

add_vpp_driver(ice
  SOURCES
  adminq.c
  cli.c
  counters.c
  format.c
  init.c
  phy.c
  phy_format.c
  port.c
  profile.c
  profile_format.c
  queue.c
  rss.c
  rss_format.c
  rss_profile.c
  rx_node.c
  tx_node.c
  vsi_format.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)
