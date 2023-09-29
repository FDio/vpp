# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

add_vpp_plugin(dev_ena
  SOURCES
  aq.c
  aenq.c
  ena.c
  format.c
  format_aq.c
  queue.c
  rx_node.c
  tx_node.c
  reg.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)

