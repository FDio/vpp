/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <qppe.h>

VNET_DEV_NODE_FN (qppe_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  /* TODO: poll the PPE RX descriptor ring(s) for this queue and enqueue
   * received packets. No queues are set up yet, so there is nothing to
   * poll. */
  return 0;
}
