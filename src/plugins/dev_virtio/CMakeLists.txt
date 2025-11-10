# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Cisco Systems, Inc.

add_vpp_plugin(dev_virtio
  SOURCES
  virtio.c
  pci.c
  virtio_pci.c
  pre_input.c
  port.c
  format.c
  queue.c
  rx_node.c
  tx_node.c

  MULTIARCH_SOURCES
  rx_node.c
  tx_node.c
)
