# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Cisco Systems, Inc.

add_vpp_driver(armada
  SOURCES
  pp2/counters.c
  pp2/init.c
  pp2/format.c
  pp2/port.c
  pp2/queue.c
  pp2/rx.c
  pp2/tx.c

  musdk.c
  musdk_bm.c
  musdk_of.c
  musdk_uio.c
)
