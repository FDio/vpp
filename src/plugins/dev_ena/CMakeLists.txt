# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

add_vpp_plugin(dev_ena
  SOURCES
  ena.c
  format.c
  rx_node.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)

