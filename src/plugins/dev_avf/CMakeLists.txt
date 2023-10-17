# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

add_vpp_plugin(dev_avf
  SOURCES
  adminq.c
  avf.c
  counters.c
  format.c
  port.c
  queue.c
  rx_node.c
  tx_node.c
  virtchnl.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)

