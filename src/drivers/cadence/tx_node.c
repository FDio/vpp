/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

#include <cadence.h>

VNET_DEV_NODE_FN (cdn_tx_node)
(vlib_main_t *vm __clib_unused, vlib_node_runtime_t *node __clib_unused, vlib_frame_t *frame)
{
  return frame->n_vectors;
}
