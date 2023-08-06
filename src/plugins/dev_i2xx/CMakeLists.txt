# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

add_vpp_plugin(dev_i2xx
  SOURCES
  i2xx.c
  format.c
  rx_node.c
  tx_node.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)

