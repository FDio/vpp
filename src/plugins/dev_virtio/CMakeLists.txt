# SPDX-License-Identifier: Apache-2.0

add_vpp_plugin(dev_virtio
  SOURCES
    virtio.c
    pci.c
    port.c
    queue.c
    rx_node.c
    tx_node.c
    format.c
  MULTIARCH_SOURCES
    rx_node.c
    tx_node.c
)
