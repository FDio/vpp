# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

add_vpp_driver(virtio_net
  SOURCES
  format.c
  init.c
  port.c
  queue.c
  rx_node.c
  tx_node.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)
