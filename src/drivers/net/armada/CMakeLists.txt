# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Cisco Systems, Inc.

if (NOT VPP_PLATFORM_NAME STREQUAL "cn913x")
  return()
endif()

add_vpp_driver(armada
  SOURCES
  bpool.c
  classifier.c
  counters.c
  flow_control.c
  format.c
  gop.c
  hif.c
  init.c
  loopback.c
  netdev.c
  parser.c
  port.c
  rx.c
  rx_queue.c
  rss.c
  tx.c
  tx_queue.c
  tx_sched.c
)
