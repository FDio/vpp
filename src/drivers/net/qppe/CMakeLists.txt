# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cisco Systems, Inc.

add_vpp_driver(qppe
  SOURCES
  init.c
  bm.c
  bm_format.c
  ac_format.c
  acl.c
  acl_format.c
  cli.c
  qm.c
  qm_format.c
  sched.c
  sched_format.c
  edma.c
  edma_rxfill.c
  edma_format.c
  fdb.c
  fdb_format.c
  vsi.c
  vsi_format.c
  counters.c
  pcs.c
  port.c
  port_format.c
  mac.c
  mac_format.c
  queue.c
  rx_node.c
  rss.c
  rss_format.c
  tx_node.c
  format.c
)
