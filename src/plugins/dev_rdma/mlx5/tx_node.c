/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <dev_rdma/mlx5/mlx5.h>

VNET_DEV_NODE_FN (rdma_mlx5_tx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_pkts = frame->n_vectors;

  if (n_pkts)
    vlib_buffer_free (vm, vlib_frame_vector_args (frame), n_pkts);

  return n_pkts;
}
