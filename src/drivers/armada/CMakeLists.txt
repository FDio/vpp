# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

add_vpp_driver(armada
  SOURCES
  pp2/bpool.c
  pp2/classifier.c
  pp2/counters.c
  pp2/flow_control.c
  pp2/format.c
  pp2/gop.c
  pp2/hif.c
  pp2/init.c
  pp2/loopback.c
  pp2/netdev.c
  pp2/parser.c
  pp2/port.c
  pp2/queue.c
  pp2/rx.c
  pp2/rx_queue.c
  pp2/rss.c
  pp2/tx.c
  pp2/tx_queue.c
  pp2/tx_sched.c
)
