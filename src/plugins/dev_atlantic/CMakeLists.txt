# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2024 Cisco Systems, Inc.

add_vpp_plugin(dev_atlantic
  SOURCES
  atlantic.c
  port.c
  rx_node.c
  tx_node.c
  format.c
  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)
