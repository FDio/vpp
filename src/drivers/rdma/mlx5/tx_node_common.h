/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#pragma once

#include <mlx5.h>
#include <vnet/dev/counters.h>

static_always_inline u8
mlx5_tx_buffer_prepare (vlib_main_t *vm, vlib_buffer_t *b)
{
  if (PREDICT_TRUE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0))
    return 1;

  if (PREDICT_FALSE (vlib_buffer_chain_linearize (vm, b) == 0))
    return 0;

  return (b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0;
}

static_always_inline void
mlx5_tx_wqe_set_csum_flags (mlx5_wqe_t *wqe, vlib_buffer_t *b, u8 cksum_off)
{
  u8 cs_flags = 0;
  vnet_buffer_oflags_t oflags;

  if (PREDICT_TRUE (cksum_off == 0 || (b->flags & VNET_BUFFER_F_OFFLOAD) == 0))
    return;

  oflags = vnet_buffer (b)->oflags;
  if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
    cs_flags |= MLX5_ETH_WQE_L3_CSUM;
  if (oflags & (VNET_BUFFER_OFFLOAD_F_TCP_CKSUM | VNET_BUFFER_OFFLOAD_F_UDP_CKSUM))
    cs_flags |= MLX5_ETH_WQE_L4_CSUM;

  wqe->eseg.cs_flags = cs_flags;
}

static_always_inline mlx5_tx_trace_t *
mlx5_txq_trace_one (vlib_main_t *vm, vlib_node_runtime_t *node, u32 bi, u8 n_sge, u8 cs_flags)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  mlx5_tx_trace_t *tr;

  if ((b->flags & VLIB_BUFFER_IS_TRACED) == 0)
    return 0;

  tr = vlib_add_trace (vm, node, b, sizeof (*tr));
  tr->qid = txq->queue_id;
  tr->n_sge = n_sge;
  tr->cs_flags = cs_flags;
  tr->dropped = n_sge == 0;
  tr->hw_if_index = vnet_dev_get_tx_queue_if_hw_if_index (txq);
  tr->buffer_index = bi;
  tr->data_len = b->current_length;
  return tr;
}

static_always_inline void
mlx5_txq_doorbell (mlx5_txq_t *tq, mlx5_wqe_t *last, u16 tail)
{
  last->ctrl.fm_ce_se = MLX5_WQE_CTRL_CQ_UPDATE;
  __atomic_store_n (&tq->dv_sq_dbrec[MLX5_SND_DBR], clib_host_to_net_u32 (tail), __ATOMIC_RELEASE);
  __atomic_store_n (&tq->dv_sq_db[0], *(u64 *) last, __ATOMIC_RELEASE);
}

static_always_inline void
mlx5_txq_update_counters (vlib_main_t *vm, vnet_dev_tx_queue_t *txq, u32 n_pkts, u32 n_bytes,
			  u32 n_drops)
{
  vnet_dev_counter_t *txq_counters = txq->counter_main ? txq->counter_main->counters : 0;

  if (PREDICT_FALSE (txq_counters == 0))
    return;

  if (n_pkts)
    {
      vnet_dev_counter_value_add (vm, txq_counters + MLX5_TXQ_CTR_PACKETS, n_pkts);
      vnet_dev_counter_value_add (vm, txq_counters + MLX5_TXQ_CTR_BYTES, n_bytes);
    }
  if (n_drops)
    vnet_dev_counter_value_add (vm, txq_counters + MLX5_TXQ_CTR_DROPS, n_drops);
}
