/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <mlx5.h>
#include <tx_node_common.h>

static_always_inline void
mlx5_txq_deq (vlib_main_t *vm, vnet_dev_tx_queue_t *txq)
{
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  u32 cq_mask = tq->dv_cq_size - 1;
  u32 mask = txq->size - 1;
  u32 log2_cq_size = tq->dv_cq_log2;
  u16 idx = tq->dv_cq_idx;
  struct mlx5_cqe64 *cqes = tq->dv_cq_cqes;
  struct mlx5_cqe64 *cur;
  u8 op_own;
  u16 tail;
  u16 n_free;

  for (;;)
    {
      cur = cqes + (idx & cq_mask);
      op_own = __atomic_load_n (&cur->op_own, __ATOMIC_ACQUIRE);
      if (((idx >> log2_cq_size) & MLX5_CQE_OWNER_MASK) != (op_own & MLX5_CQE_OWNER_MASK) ||
	  (op_own >> 4) == MLX5_CQE_INVALID)
	break;
      idx++;
    }

  if (idx == tq->dv_cq_idx)
    return;

  cur = cqes + ((idx - 1) & cq_mask);
  cur->op_own = 0xf0;
  tail = clib_net_to_host_u16 (cur->wqe_counter);
  n_free = tail - tq->head;
  if (n_free)
    vlib_buffer_free_from_ring (vm, tq->buffers, tq->head & mask, txq->size, n_free);
  tq->head = tail;

  tq->dv_cq_idx = idx;
  __atomic_store_n (&tq->dv_cq_dbrec[0], clib_host_to_net_u32 (idx), __ATOMIC_RELEASE);
}

static_always_inline void
mlx5_wqe_init (mlx5_wqe_t *wqe, const void *tmpl, vlib_buffer_t *b, u16 tail, u8 cksum_off)
{
  u16 sz = b->current_length;
  const void *cur = vlib_buffer_get_current (b);
  uword addr = pointer_to_uword (cur);

  clib_memcpy_fast (wqe, tmpl, RDMA_MLX5_WQE_SZ);
  mlx5_tx_wqe_set_csum_flags (wqe, b, cksum_off);
  clib_memcpy_fast (wqe->eseg.inline_hdr_start, cur, MLX5_ETH_L2_INLINE_HEADER_SIZE);

  wqe->wqe_index_lo = tail;
  wqe->wqe_index_hi = tail >> 8;
  if (PREDICT_TRUE (sz >= MLX5_ETH_L2_INLINE_HEADER_SIZE))
    {
      wqe->dseg.byte_count = clib_host_to_net_u32 (sz - MLX5_ETH_L2_INLINE_HEADER_SIZE);
      wqe->dseg.addr = clib_host_to_net_u64 (addr + MLX5_ETH_L2_INLINE_HEADER_SIZE);
    }
  else
    {
      wqe->eseg.inline_hdr_sz = clib_host_to_net_u16 (sz);
    }
}

static_always_inline u32
mlx5_txq_enq (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_tx_queue_t *txq, u32 *from,
	      u32 n_left, u32 *n_bytes)
{
  mlx5_txq_t *tq = vnet_dev_get_tx_queue_data (txq);
  vlib_buffer_t *b[VLIB_FRAME_SIZE];
  u32 mask = txq->size - 1;
  u32 sq_mask = txq->size - 1;
  u32 n = clib_min (n_left, txq->size - (tq->tail - tq->head));
  u32 i;
  u16 tail;
  u8 trace = node->flags & VLIB_NODE_FLAG_TRACE;
  u8 cksum_off = txq->port->attr.tx_offloads.ip4_cksum;
  mlx5_wqe_t *wqe;

  if (n == 0)
    return 0;

  vlib_get_buffers (vm, from, b, n);
  tail = tq->tail;
  for (i = 0; i < n; i++)
    {
      if (PREDICT_FALSE (mlx5_tx_buffer_prepare (vm, b[i]) == 0))
	{
	  vlib_error_count (vm, node->node_index, RDMA_MLX5_TX_NODE_CTR_BUFFER_PREPARE_FAIL, 1);
	  if (PREDICT_FALSE (trace))
	    mlx5_txq_trace_one (vm, node, from[i], 0, 0);
	  break;
	}

      wqe = tq->dv_sq_wqes + (tail & sq_mask);
      mlx5_wqe_init (wqe, tq->dv_wqe_tmpl, b[i], tail, cksum_off);
      if (PREDICT_FALSE (trace))
	mlx5_txq_trace_one (vm, node, from[i], 1, wqe->eseg.cs_flags);
      tq->buffers[tail & mask] = from[i];
      *n_bytes += b[i]->current_length;
      tail++;
    }

  if (i == 0)
    return 0;

  mlx5_txq_doorbell (tq, wqe, tail);
  tq->tail = tail;
  return i;
}

VNET_DEV_NODE_FN (mlx5_tx_node_mpw)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vnet_dev_tx_node_runtime_t *rt = vnet_dev_get_tx_node_runtime (node);
  vnet_dev_tx_queue_t *txq = rt->tx_queue;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_pkts = 0;
  u32 n_bytes = 0;
  int n_retries = 2;

  vnet_dev_tx_queue_lock_if_needed (txq);

  while (n_retries-- && n_left)
    {
      u32 n;
      mlx5_txq_deq (vm, txq);
      n = mlx5_txq_enq (vm, node, txq, from, n_left, &n_bytes);
      from += n;
      n_left -= n;
      n_pkts += n;
      if (n == 0)
	break;
    }

  vnet_dev_tx_queue_unlock_if_needed (txq);

  if (n_left)
    vlib_buffer_free (vm, from, n_left);
  mlx5_txq_update_counters (vm, txq, n_pkts, n_bytes, n_left);

  vlib_increment_combined_counter (vnet_get_main ()->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_TX,
				   vm->thread_index, rt->hw_if_index, n_pkts, n_bytes);

  return n_pkts;
}
