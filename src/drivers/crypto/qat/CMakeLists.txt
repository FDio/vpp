# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2026 Damjan Marion

add_vpp_driver(qat
  SOURCES
  algs.c
  cli.c
  deq.c
  enq.c
  format.c
  init.c
  pfvf.c
  queue.c
  session.c

  MULTIARCH_SOURCES
  deq.c
  enq.c
)
