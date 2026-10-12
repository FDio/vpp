/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <qppe.h>

VNET_DEV_NODE_FN (qppe_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 *from = vlib_frame_vector_args (frame);
  u16 n_left = frame->n_vectors;

  /* TODO: submit packets to the PPE TX descriptor ring for this queue.
   * Until that is implemented, free the buffers so the node has
   * well-defined behavior instead of leaking them. */
  vlib_buffer_free (vm, from, n_left);

  return n_left;
}
