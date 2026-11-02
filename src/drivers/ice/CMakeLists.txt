# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Damjan Marion

add_vpp_driver(ice
  SOURCES
  init.c
  cli.c
  adminq.c
  vsi_format.c
  port.c
  phy.c
  flow.c
  flow_pattern.c
  fdir.c
  profile.c
  rss.c
  rss_profile.c
  counters.c
  queue.c
  rx_node.c
  tx_node.c
  format.c
  phy_format.c
  fdir_format.c
  profile_format.c
  rss_format.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)
