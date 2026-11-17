/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <rx_node_common.h>

static_always_inline u32
mlx5_rxq_refill_legacy_multiseg (vlib_main_t *vm, vlib_node_runtime_t *node,
				 vnet_dev_rx_queue_t *rxq, u32 tail)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u16 mask = rxq->size - 1, ring_space = rxq->size - (tail - mq->head);
  u32 *buffers = mq->buffers;
  mlx5dv_wqe_ds_t *dv_sq_wqes = mq->dv_sq_wqes;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  const u32 bsz = RDMA_MLX5_RXQ_REFILL_BATCH_SZ;
  const u32 alloc_sz = bsz * RDMA_RXQ_LEGACY_MODE_MAX_CHAIN_SZ;
  u64 va[alloc_sz] __clib_aligned (64);
  u32 log_wqe_sz = mq->log_wqe_sz, n_ds_per_wqe = mq->n_ds_per_wqe, n_tail = n_ds_per_wqe - 1;
  u32 all_bufs[alloc_sz], *second_bufs = mq->second_bufs;

  while (ring_space >= bsz)
    {
      u32 slot = tail & mask, n_total = bsz * n_ds_per_wqe,
	  n_now = clib_min (bsz, rxq->size - slot);

      ASSERT (n_total <= alloc_sz);

      if (PREDICT_FALSE (
	    !vlib_buffer_strict_alloc_from_pool (vm, all_bufs, n_total, buffer_pool_index)))
	{
	  vlib_error_count (vm, node->node_index, RDMA_MLX5_RX_NODE_CTR_BUFFER_ALLOC, 1);
	  break;
	}

      vlib_get_buffers_with_offset (vm, all_bufs, (void **) va, n_total, sizeof (vlib_buffer_t));
      mlx5_va_to_be (va, n_total);

      vlib_buffer_copy_indices (buffers + slot, all_bufs, n_now);
      if (n_now != bsz)
	vlib_buffer_copy_indices (buffers, all_bufs + n_now, bsz - n_now);

      for (u32 i = 0; i < bsz; i++)
	{
	  u32 base = (slot + i) * n_tail, extra_base = bsz + i * n_tail;
	  mlx5dv_wqe_ds_t *wqe = dv_sq_wqes + ((slot + i) << log_wqe_sz);

	  wqe[0].addr = va[i];

	  for (u32 j = 0; j < n_tail; j++)
	    {
	      second_bufs[base + j] = all_bufs[extra_base + j];
	      wqe[j + 1].addr = va[extra_base + j];
	    }
	}

      tail += bsz;
      ring_space -= bsz;
    }

  return tail;
}

static_always_inline u32
mlx5_rxq_refill_legacy (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq,
			u32 tail)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u16 mask = rxq->size - 1, ring_space = rxq->size - (tail - mq->head);
  u32 *buffers = mq->buffers;
  mlx5dv_wqe_ds_t *dv_sq_wqes = mq->dv_sq_wqes;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  const u32 bsz = RDMA_MLX5_RXQ_REFILL_BATCH_SZ;
  u64 va[bsz] __clib_aligned (64);

  for (; ring_space >= bsz; tail += bsz, ring_space -= bsz)
    {
      u32 slot = tail & mask, *bufs = buffers + slot;
      mlx5dv_wqe_ds_t *wqe = dv_sq_wqes + slot;

      if (PREDICT_FALSE (!vlib_buffer_strict_alloc_from_pool (vm, bufs, bsz, buffer_pool_index)))
	{
	  vlib_error_count (vm, node->node_index, RDMA_MLX5_RX_NODE_CTR_BUFFER_ALLOC, 1);
	  break;
	}

      vlib_get_buffers_with_offset (vm, bufs, (void **) va, bsz, sizeof (vlib_buffer_t));
      mlx5_va_to_be (va, bsz);

      for (u32 i = 0; i < bsz; i++)
	wqe[i].addr = va[i];
    }

  return tail;
}

static_always_inline void
mlx5_rxq_refill_legacy_mode (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u32 tail = mq->tail, new_tail;

  if (mq->single_buffer)
    new_tail = mlx5_rxq_refill_legacy (vm, node, rxq, tail);
  else
    new_tail = mlx5_rxq_refill_legacy_multiseg (vm, node, rxq, tail);

  if (new_tail == tail)
    return;

  mq->tail = new_tail;
  __atomic_store_n (&mq->dv_sq_dbrec[MLX5_RCV_DBR], clib_host_to_net_u32 (new_tail & 0xffff),
		    __ATOMIC_RELEASE);
}

static_always_inline void
mlx5_legacy_input (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 *to_next, u32 *bc, u16 *cf,
		   int l4_ok, u32 n_rx_packets, u32 mask, u32 n_ds_per_wqe, vlib_buffer_t **bufs)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  vlib_buffer_t **b = bufs;
  u32 n_left = n_rx_packets, *len = bc;
  mlx5_rx_tmpl_t t;

  vlib_buffer_copy_indices_from_ring (to_next, mq->buffers, mq->head & mask, rxq->size,
				      n_rx_packets);
  vlib_get_buffers (vm, to_next, bufs, n_rx_packets);
  vlib_buffers_prefetch_pad (bufs, n_rx_packets, 4);
  mq->head += n_rx_packets;

  if (l4_ok)
    bt.flags |= VNET_BUFFER_F_L4_CHECKSUM_COMPUTED | VNET_BUFFER_F_L4_CHECKSUM_CORRECT;

  t = mlx5_rx_tmpl_load (&bt);

  for (; n_left >= 4; n_left -= 4, b += 4, len += 4)
    {
      vlib_buffer_t *b0 = b[0], *b1 = b[1], *b2 = b[2], *b3 = b[3];

      clib_prefetch_store (b[4]);
      clib_prefetch_store (b[5]);
      clib_prefetch_store (b[6]);
      clib_prefetch_store (b[7]);
      mlx5_rx_tmpl_store (b0, t, len[0]);
      mlx5_rx_tmpl_store (b1, t, len[1]);
      mlx5_rx_tmpl_store (b2, t, len[2]);
      mlx5_rx_tmpl_store (b3, t, len[3]);
    }

  for (; n_left; n_left--, b++, len++)
    mlx5_rx_tmpl_store (b[0], t, len[0]);

  if (!l4_ok)
    for (u32 i = 0; i < n_rx_packets; i++)
      bufs[i]->flags |= mlx5_cqe_l4_flags (clib_net_to_host_u16 (cf[i]));

  if (n_ds_per_wqe > 1)
    {
      u32 buf_sz = mq->buf_sz, n_tail = n_ds_per_wqe - 1;
      u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
      uword slot = (mq->head - n_rx_packets) & mask;
      u32 *extra = mq->second_bufs + (slot * n_tail);
      u32 n_wrap_around = (slot + n_rx_packets) & (mask + 1) ? (slot + n_rx_packets) & mask : 0;
      u32 n_fix = n_rx_packets - n_wrap_around;

    wrap_around:
      for (; n_fix; n_fix--, bufs++, extra += n_tail)
	{
	  vlib_buffer_t *cb = bufs[0];
	  u32 total_length = cb->current_length, seg = 0;

	  if (total_length > buf_sz)
	    {
	      total_length -= buf_sz;
	      cb->current_length = buf_sz;
	      cb->total_length_not_including_first_buffer = total_length;
	      cb->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

	      for (; total_length && seg < n_tail; seg++)
		{
		  cb->flags |= VLIB_BUFFER_NEXT_PRESENT;
		  cb->next_buffer = extra[seg];
		  cb = vlib_get_buffer (vm, extra[seg]);
		  cb->template = bt;
		  cb->current_length = clib_min (buf_sz, total_length);
		  total_length -= cb->current_length;
		}
	    }

	  if (seg < n_tail)
	    vlib_buffer_unalloc_to_pool (vm, extra + seg, n_tail - seg, buffer_pool_index);
	}

      if (PREDICT_FALSE (n_wrap_around))
	{
	  n_fix = n_wrap_around;
	  n_wrap_around = 0;
	  extra = mq->second_bufs;
	  goto wrap_around;
	}
    }
}

static_always_inline void
mlx5_rx_trace_legacy (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq,
		      u32 next_index, u32 *to_next, u32 n_rx_packets, mlx5_rx_cqe_copy_t *tc,
		      u32 rq_head)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u32 n_trace = vlib_get_trace_count (vm, node), mask = rxq->size - 1;
  u32 n_ds = clib_min (mq->n_ds_per_wqe, MLX5_RX_TRACE_MAX_DS);

  for (u32 i = 0; i < n_rx_packets && n_trace; i++)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, to_next[i]);
      u32 slot = (rq_head + i) & mask;
      mlx5_rx_legacy_trace_t *tr;

      if (!vlib_trace_buffer (vm, node, next_index, b, 0))
	continue;

      tr = vlib_add_trace (vm, node, b, sizeof (*tr) + n_ds * sizeof (tr->ds[0]));
      *tr = (mlx5_rx_legacy_trace_t) {
	.qid = rxq->queue_id,
	.next_index = next_index,
	.hw_if_index = hw_if_index,
	.length = vlib_buffer_length_in_chain (vm, b),
	.buffer_flags = b->flags,
	.wqe_index = slot,
	.n_ds = n_ds,
	.cqe = tc[i],
      };
      for (u32 j = 0; j < n_ds; j++)
	tr->ds[j] = mq->dv_sq_wqes[(slot << mq->log_wqe_sz) + j];
      n_trace--;
    }
  vlib_set_trace_count (vm, node, n_trace);
}

static_always_inline u32
mlx5_rx_one_queue_legacy (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  vnet_main_t *vnm = vnet_get_main ();
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE + 4];
  u32 bc[VLIB_FRAME_SIZE];
  u16 cf[VLIB_FRAME_SIZE];
  mlx5_rx_cqe_copy_t tc[VLIB_FRAME_SIZE];
  u32 next_index = vnet_dev_get_rx_queue_if_next_index (rxq), *to_next, n_left_to_next;
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u32 n_trace = vlib_get_trace_count (vm, node), n_ds_per_wqe = mq->n_ds_per_wqe;
  u32 mask = rxq->size - 1, n_rx_packets;
  mlx5_rx_finish_t fr;

  if (PREDICT_FALSE (n_trace))
    n_rx_packets = mlx5_rxq_poll (vm, node, rxq, bc, cf, tc);
  else
    n_rx_packets = mlx5_rxq_poll (vm, node, rxq, bc, cf, 0);

  if (n_rx_packets == 0)
    return 0;

  fr = mlx5_rx_cqe_finish (bc, cf, n_rx_packets, 0);
  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  if (mq->single_buffer)
    mlx5_legacy_input (vm, rxq, to_next, bc, cf, fr.l4_ok, n_rx_packets, mask, 1, bufs);
  else
    mlx5_legacy_input (vm, rxq, to_next, bc, cf, fr.l4_ok, n_rx_packets, mask, n_ds_per_wqe, bufs);

  if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      vlib_frame_t *f = vlib_get_frame (vm, nf->frame);
      ethernet_input_frame_t *ef = vlib_frame_scalar_args (f);

      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
      if (!fr.ip4_bad)
	f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = hw_if_index;
      vlib_frame_no_append (f);
    }

  if (PREDICT_FALSE (n_trace))
    mlx5_rx_trace_legacy (vm, node, rxq, next_index, to_next, n_rx_packets, tc,
			  mq->head - n_rx_packets);

  vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx_packets);

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_RX,
				   vm->thread_index, sw_if_index, n_rx_packets, fr.n_bytes);

  return n_rx_packets;
}

VNET_DEV_NODE_FN (mlx5_rx_node_legacy)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame __clib_unused)
{
  u32 rv = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      rv += mlx5_rx_one_queue_legacy (vm, node, rxq);
      mlx5_rxq_refill_legacy_mode (vm, node, rxq);
    }

  return rv;
}
