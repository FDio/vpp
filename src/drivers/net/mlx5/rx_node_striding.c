/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <rx_node_common.h>

static_always_inline void
mlx5_rxq_refill_striding (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u32 tail = mq->tail, *buffers = mq->buffers;
  u16 mask = rxq->size - 1, ring_space = rxq->size - (tail - mq->head);
  mlx5dv_wqe_ds_t *dv_sq_wqes = mq->dv_sq_wqes;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  const u32 bsz = RDMA_MLX5_RXQ_REFILL_BATCH_SZ;
  u64 va[bsz] __clib_aligned (64);
  u32 log_stride_per_wqe = mq->log_stride_per_wqe, log_wqe_sz = mq->log_wqe_sz;
  u32 wqe_sz = 1 << log_wqe_sz, stride_per_wqe = 1 << log_stride_per_wqe, new_tail;

  for (new_tail = tail; ring_space >= bsz; new_tail += bsz, ring_space -= bsz)
    {
      u32 slot = new_tail & mask, *bufs = buffers + slot;
      mlx5dv_wqe_ds_t *wqe;

      if (PREDICT_FALSE (!vlib_buffer_strict_alloc_from_pool (vm, bufs, bsz, buffer_pool_index)))
	{
	  vlib_error_count (vm, node->node_index, RDMA_MLX5_RX_NODE_CTR_BUFFER_ALLOC, 1);
	  break;
	}

      vlib_get_buffers_with_offset (vm, bufs, (void **) va, bsz, sizeof (vlib_buffer_t));
      mlx5_va_to_be (va, bsz);

      wqe = dv_sq_wqes + (slot << (log_wqe_sz - log_stride_per_wqe));

      for (u32 i = 0; i < bsz; i += stride_per_wqe)
	{
	  for (u32 j = 0; j < stride_per_wqe; j++)
	    wqe[j + 1].addr = va[i + j];
	  wqe += wqe_sz;
	}
    }

  if (new_tail == tail)
    return;

  mq->tail = new_tail;
  mq->striding_wqe_tail += (new_tail - tail) >> log_stride_per_wqe;
  __atomic_store_n (&mq->dv_sq_dbrec[MLX5_RCV_DBR], clib_host_to_net_u32 (mq->striding_wqe_tail),
		    __ATOMIC_RELEASE);
}

static_always_inline void
mlx5_striding_rq_fast_input (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 *to_next, u32 n_rx_segs,
			     u32 *bc, u16 *cf, int l4_ok, vlib_buffer_t **bufs)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  vlib_buffer_t **b = bufs;
  u32 mask = rxq->size - 1, n_left = n_rx_segs;
  mlx5_rx_tmpl_t t;

  vlib_buffer_copy_indices_from_ring (to_next, mq->buffers, mq->head & mask, rxq->size, n_rx_segs);
  vlib_get_buffers (vm, to_next, bufs, n_rx_segs);
  vlib_buffers_prefetch_pad (bufs, n_rx_segs, 4);
  mq->head += n_rx_segs;

  if (l4_ok)
    bt.flags |= VNET_BUFFER_F_L4_CHECKSUM_COMPUTED | VNET_BUFFER_F_L4_CHECKSUM_CORRECT;

  t = mlx5_rx_tmpl_load (&bt);

  for (; n_left >= 4; n_left -= 4, b += 4, bc += 4)
    {
      vlib_buffer_t *b0 = b[0], *b1 = b[1], *b2 = b[2], *b3 = b[3];

      clib_prefetch_store (b[4]);
      clib_prefetch_store (b[5]);
      clib_prefetch_store (b[6]);
      clib_prefetch_store (b[7]);
      mlx5_rx_tmpl_store (b0, t, bc[0]);
      mlx5_rx_tmpl_store (b1, t, bc[1]);
      mlx5_rx_tmpl_store (b2, t, bc[2]);
      mlx5_rx_tmpl_store (b3, t, bc[3]);
    }

  for (; n_left; n_left--, b++, bc++)
    mlx5_rx_tmpl_store (b[0], t, bc[0]);

  if (!l4_ok)
    for (u32 i = 0; i < n_rx_segs; i++)
      bufs[i]->flags |= mlx5_cqe_l4_flags (clib_net_to_host_u16 (cf[i]));
}

static_always_inline u32
mlx5_striding_rq_slow_input (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 *to_next, u32 n_rx_segs,
			     u32 *bc, u16 *cf, u32 *n_rx_packets)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_t *pkt_head = 0, *pkt_prev = 0;
  vlib_buffer_template_t bt_local = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 *bc0 = bc, *next_in_frame = to_next, mask = rxq->size - 1, n_pkts = *n_rx_packets;
  u32 n_rx_bytes = 0, n_bytes_remaining = 0, n_segs_remaining = 0, pkt_head_idx = 0;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  int filler_pkt = 0;

  bt_local.current_length = mq->buf_sz;

  while (n_rx_segs > 0)
    {
      u32 n_left = clib_min (n_rx_segs, (u32) VLIB_FRAME_SIZE);
      u32 current_segs[VLIB_FRAME_SIZE];
      u32 to_free_buffers[VLIB_FRAME_SIZE];
      vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **pkt = bufs;
      u32 *next_to_free = to_free_buffers, i = 0, remaining = n_left;

      vlib_buffer_copy_indices_from_ring (current_segs, mq->buffers, mq->head & mask, rxq->size,
					  n_left);
      mq->head += n_left;
      vlib_get_buffers (vm, current_segs, bufs, n_left);

      while (remaining)
	{
	  int new_pkt = 0;

	  if (!n_segs_remaining)
	    {
	      n_segs_remaining =
		(bc[0] & CQE_BC_CONSUMED_STRIDES_MASK) >> CQE_BC_CONSUMED_STRIDES_SHIFT;
	      filler_pkt = !!(bc[0] & CQE_BC_FILLER_MASK);
	      if (filler_pkt)
		{
		  u32 n_now = clib_min (n_segs_remaining, remaining);

		  vlib_buffer_copy_indices (next_to_free, current_segs + i, n_now);
		  next_to_free += n_now;
		  n_segs_remaining -= n_now;
		  i += n_now;
		  pkt += n_now;
		  remaining -= n_now;
		  if (!n_segs_remaining)
		    {
		      bc++;
		      n_pkts--;
		      filler_pkt = 0;
		    }
		  continue;
		}

	      pkt_head = pkt[0];
	      pkt_head_idx = current_segs[pkt - bufs];
	      n_bytes_remaining = bc[0] & CQE_BC_BYTE_COUNT_MASK;
	      new_pkt = 1;
	    }

	  if (filler_pkt)
	    {
	      u32 n_now = clib_min (n_segs_remaining, remaining);

	      vlib_buffer_copy_indices (next_to_free, current_segs + i, n_now);
	      next_to_free += n_now;
	      n_segs_remaining -= n_now;
	      i += n_now;
	      pkt += n_now;
	      remaining -= n_now;
	      if (!n_segs_remaining)
		{
		  bc++;
		  n_pkts--;
		  filler_pkt = 0;
		}
	      continue;
	    }

	  pkt[0]->template = bt_local;

	  if (new_pkt)
	    {
	      pkt_head->flags |= mlx5_cqe_l4_flags (clib_net_to_host_u16 (cf[bc - bc0]));
	      pkt_head->total_length_not_including_first_buffer =
		n_segs_remaining > 1 ? n_bytes_remaining - pkt[0]->current_length : 0;
	      pkt_head->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
	    }
	  else
	    {
	      pkt_prev->next_buffer = current_segs[pkt - bufs];
	      pkt_prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      pkt[0]->flags &= ~VLIB_BUFFER_TOTAL_LENGTH_VALID;
	    }

	  if (n_segs_remaining == 1)
	    {
	      pkt[0]->current_length = n_bytes_remaining;
	      (next_in_frame++)[0] = pkt_head_idx;
	      n_rx_bytes +=
		pkt_head->current_length + pkt_head->total_length_not_including_first_buffer;
	      bc++;
	    }
	  else
	    {
	      n_bytes_remaining -= pkt[0]->current_length;
	      pkt_prev = pkt[0];
	    }

	  n_segs_remaining--;
	  pkt++;
	  i++;
	  remaining--;
	}

      vlib_buffer_unalloc_to_pool (vm, to_free_buffers, next_to_free - to_free_buffers,
				   buffer_pool_index);
      n_rx_segs -= n_left;
    }

  *n_rx_packets = n_pkts;
  return n_rx_bytes;
}

static_always_inline u32
mlx5_rx_one_queue_striding (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
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
  u32 n_trace = vlib_get_trace_count (vm, node), n_rx_bytes, n_rx_packets, n_rx_segs, n_cqes;
  mlx5_rx_finish_t fr;

  if (PREDICT_FALSE (n_trace))
    n_rx_packets = mlx5_rxq_poll (vm, node, rxq, bc, cf, tc);
  else
    n_rx_packets = mlx5_rxq_poll (vm, node, rxq, bc, cf, 0);

  if (n_rx_packets == 0)
    return 0;

  n_cqes = n_rx_packets;
  fr = mlx5_rx_cqe_finish (bc, cf, n_cqes, 1);
  n_rx_segs = fr.n_segs;
  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  if (PREDICT_FALSE (fr.filler || n_rx_segs != n_cqes))
    n_rx_bytes = mlx5_striding_rq_slow_input (vm, rxq, to_next, n_rx_segs, bc, cf, &n_rx_packets);
  else
    {
      mlx5_striding_rq_fast_input (vm, rxq, to_next, n_rx_segs, bc, cf, fr.l4_ok, bufs);
      n_rx_bytes = fr.n_bytes;
    }

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
    {
      u32 mask = rxq->size - 1, stride = mq->head - n_rx_segs, pkt = 0;
      u32 log_stride = mq->log_stride_per_wqe, stride_mask = (1 << log_stride) - 1;

      for (u32 i = 0; i < n_cqes && n_trace && pkt < n_rx_packets; i++)
	{
	  mlx5_rx_cqe_copy_t *c = tc + i;
	  u32 bc = clib_net_to_host_u32 (c->compressed ? c->mini_cqe.byte_count : c->cqe.byte_cnt);
	  u32 n = (bc & CQE_BC_CONSUMED_STRIDES_MASK) >> CQE_BC_CONSUMED_STRIDES_SHIFT;
	  u32 first = stride;
	  mlx5_rx_striding_trace_t *tr;
	  vlib_buffer_t *b;

	  stride += n;
	  if (bc & CQE_BC_FILLER_MASK)
	    continue;

	  b = vlib_get_buffer (vm, to_next[pkt++]);
	  if (!vlib_trace_buffer (vm, node, next_index, b, 0))
	    continue;

	  n = clib_min (n, MLX5_RX_TRACE_MAX_DS);
	  tr = vlib_add_trace (vm, node, b, sizeof (*tr) + n * sizeof (tr->stride_ds[0]));
	  *tr = (mlx5_rx_striding_trace_t) {
	    .qid = rxq->queue_id,
	    .next_index = next_index,
	    .hw_if_index = hw_if_index,
	    .length = vlib_buffer_length_in_chain (vm, b),
	    .buffer_flags = b->flags,
	    .first_stride = first & mask,
	    .n_strides = n,
	    .log_stride_per_wqe = log_stride,
	    .cqe = *c,
	  };

	  for (u32 j = 0; j < n; j++)
	    {
	      u32 s = (first + j) & mask;
	      tr->stride_ds[j] =
		mq->dv_sq_wqes[((s >> log_stride) << mq->log_wqe_sz) + 1 + (s & stride_mask)];
	    }

	  n_trace--;
	}

      vlib_set_trace_count (vm, node, n_trace);
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx_packets);

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_RX,
				   vm->thread_index, sw_if_index, n_rx_packets, n_rx_bytes);

  return n_rx_packets;
}

VNET_DEV_NODE_FN (mlx5_rx_node_striding)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame __clib_unused)
{
  u32 rv = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      rv += mlx5_rx_one_queue_striding (vm, node, rxq);
      mlx5_rxq_refill_striding (vm, node, rxq);
    }

  return rv;
}
