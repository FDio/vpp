# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

add_vpp_driver(qppe
  SOURCES
  init.c
  port.c
  queue.c
  rx_node.c
  tx_node.c
  format.c
)
