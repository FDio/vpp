/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_ena/ena.h>

VNET_DEV_NODE_FN (ena_tx_node_fn)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  fformat (stderr, "%u: %u\n", vm->thread_index, frame->n_vectors);
  return 0;
}
