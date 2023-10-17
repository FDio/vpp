# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

add_vpp_plugin(dev_iavf
  SOURCES
  adminq.c
  counters.c
  format.c
  iavf.c
  port.c
  queue.c
  rx_node.c
  tx_node.c
  virtchnl.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)

