# SPDX-License-Identifier: Apache-2.0
add_vpp_driver(virtio-net-pci
  SOURCES
  control.c
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
