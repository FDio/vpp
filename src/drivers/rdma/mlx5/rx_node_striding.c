/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/counters.h>
#include <vnet/devices/devices.h>
#include <vnet/ethernet/ethernet.h>
#include <mlx5.h>

#define RDMA_MLX5_RXQ_REFILL_BATCH_SZ 32

static_always_inline void
mlx5_process_mini_cqes (mlx5_rxq_t *mq, u32 skip, u32 n_left, u32 cq_ci, u32 mask, u32 *byte_cnt)
{
  mlx5dv_mini_cqe_t *mcqe;
  u32 mcqe_array_index;
  u32 n;
  u32 i;

  mcqe_array_index = (cq_ci + 1) & mask;
  mcqe = (mlx5dv_mini_cqe_t *) (mq->dv_cq_cqes + mcqe_array_index);

  mcqe_array_index = cq_ci;

  if (skip)
    {
      n = skip & ~7;

      if (n)
	{
	  mcqe_array_index = (mcqe_array_index + n) & mask;
	  mcqe = (mlx5dv_mini_cqe_t *) (mq->dv_cq_cqes + mcqe_array_index);
	  skip -= n;
	}

      if (skip)
	{
	  n = clib_min (8 - skip, n_left);
	  for (i = 0; i < n; i++)
	    byte_cnt[i] = clib_net_to_host_u32 (mcqe[skip + i].byte_count);
	  mcqe_array_index = (mcqe_array_index + 8) & mask;
	  mcqe = (mlx5dv_mini_cqe_t *) (mq->dv_cq_cqes + mcqe_array_index);
	  n_left -= n;
	  byte_cnt += n;
	}
    }

  while (n_left >= 8)
    {
      for (i = 0; i < 8; i++)
	byte_cnt[i] = clib_net_to_host_u32 (mcqe[i].byte_count);

      n_left -= 8;
      byte_cnt += 8;
      mcqe_array_index = (mcqe_array_index + 8) & mask;
      mcqe = (mlx5dv_mini_cqe_t *) (mq->dv_cq_cqes + mcqe_array_index);
    }

  if (n_left)
    for (i = 0; i < n_left; i++)
      byte_cnt[i] = clib_net_to_host_u32 (mcqe[i].byte_count);
}

static_always_inline void
mlx5_cqe_set_owner (mlx5dv_cqe_t *cqe, u32 n_left, u8 owner)
{
  while (n_left >= 8)
    {
      cqe[0].opcode_cqefmt_se_owner = owner;
      cqe[1].opcode_cqefmt_se_owner = owner;
      cqe[2].opcode_cqefmt_se_owner = owner;
      cqe[3].opcode_cqefmt_se_owner = owner;
      cqe[4].opcode_cqefmt_se_owner = owner;
      cqe[5].opcode_cqefmt_se_owner = owner;
      cqe[6].opcode_cqefmt_se_owner = owner;
      cqe[7].opcode_cqefmt_se_owner = owner;
      n_left -= 8;
      cqe += 8;
    }

  while (n_left)
    {
      cqe[0].opcode_cqefmt_se_owner = owner;
      n_left--;
      cqe++;
    }
}

static_always_inline void
mlx5_compressed_cqe_reset_owner (mlx5_rxq_t *mq, u32 n_mini_cqes, u32 cq_ci, u32 mask,
				 u32 log2_cq_size)
{
  mlx5dv_cqe_t *cqes = (mlx5dv_cqe_t *) mq->dv_cq_cqes;
  u8 owner;
  u32 offset;
  u32 cq_size;
  u32 n;

  cq_size = 1 << log2_cq_size;

  /* first CQE is reset by hardware */
  cq_ci++;
  n_mini_cqes--;

  offset = cq_ci & mask;
  owner = 0xf0 | ((cq_ci >> log2_cq_size) & 1);

  if (offset + n_mini_cqes < cq_size)
    {
      mlx5_cqe_set_owner (cqes + offset, n_mini_cqes, owner);
    }
  else
    {
      n = cq_size - offset;
      mlx5_cqe_set_owner (cqes + offset, n, owner);
      mlx5_cqe_set_owner (cqes, n_mini_cqes - n, owner ^ 1);
    }
}

static_always_inline u32
mlx5_rxq_poll_striding (vnet_dev_rx_queue_t *rxq, u32 *byte_cnt, u32 *n_rx_segs, int *slow_path,
			u32 *ip4_badp)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  mlx5dv_cqe_t *cqes = (mlx5dv_cqe_t *) mq->dv_cq_cqes;
  u32 log2_cq_size = mq->dv_cq_log2;
  u32 mask = mq->dv_cq_size - 1;
  u32 dv_cq_idx = mq->dv_cq_idx;
  u32 n_rx = 0;
  u32 n_segs = 0;
  int filler = 0;
  u32 ip4_bad = 0;
  u16 cqe_flags;

  while (n_rx < VLIB_FRAME_SIZE)
    {
      mlx5dv_cqe_t *cqe = cqes + (dv_cq_idx & mask);
      u8 owner = (dv_cq_idx >> log2_cq_size) & 1;
      u8 cqe_last_byte = cqe->opcode_cqefmt_se_owner;

      if ((cqe_last_byte & 0x1) != owner)
	break;

      cqe_last_byte &= 0xfc; /* remove owner and solicited bits */

      if (cqe_last_byte == 0x2c)
	{
	  u32 n_mini_cqes = clib_net_to_host_u32 (cqe->mini_cqe_num);
	  u32 n_left = VLIB_FRAME_SIZE - n_rx;
	  u32 i;

	  ASSERT (n_mini_cqes <= VLIB_FRAME_SIZE);
	  if (n_left < n_mini_cqes)
	    break;

	  cqe_flags = (u16) mlx5_get_bits (cqe, 0x1c, 31, 16);
	  ip4_bad +=
	    n_mini_cqes * ((CQE_FLAG_L3_HDR_TYPE (cqe_flags) == CQE_FLAG_L3_HDR_TYPE_IP4) &&
			   ((cqe_flags & CQE_FLAG_L3_OK) == 0));

	  mlx5_process_mini_cqes (mq, 0, n_mini_cqes, dv_cq_idx, mask, byte_cnt);
	  mlx5_compressed_cqe_reset_owner (mq, n_mini_cqes, dv_cq_idx, mask, log2_cq_size);

	  for (i = 0; i < n_mini_cqes; i++)
	    {
	      n_segs +=
		(byte_cnt[i] & CQE_BC_CONSUMED_STRIDES_MASK) >> CQE_BC_CONSUMED_STRIDES_SHIFT;
	      filler |= !!(byte_cnt[i] & CQE_BC_FILLER_MASK);
	    }

	  n_rx += n_mini_cqes;
	  byte_cnt += n_mini_cqes;
	  dv_cq_idx += n_mini_cqes;
	  continue;
	}

      if (cqe_last_byte == 0x20)
	{
	  byte_cnt[0] = clib_net_to_host_u32 (cqe->byte_cnt);
	  cqe_flags = (u16) mlx5_get_bits (cqe, 0x1c, 31, 16);
	  ip4_bad += (CQE_FLAG_L3_HDR_TYPE (cqe_flags) == CQE_FLAG_L3_HDR_TYPE_IP4) &&
		     ((cqe_flags & CQE_FLAG_L3_OK) == 0);
	  n_segs += (byte_cnt[0] & CQE_BC_CONSUMED_STRIDES_MASK) >> CQE_BC_CONSUMED_STRIDES_SHIFT;
	  filler |= !!(byte_cnt[0] & CQE_BC_FILLER_MASK);
	  n_rx++;
	  dv_cq_idx++;
	  byte_cnt++;
	  continue;
	}

      break;
    }

  if (n_rx)
    {
      mq->dv_cq_idx = dv_cq_idx;
      __atomic_store_n (&mq->dv_cq_dbrec[0], clib_host_to_net_u32 (dv_cq_idx), __ATOMIC_RELEASE);
    }

  if (n_rx && n_rx != n_segs)
    filler = 1;

  *n_rx_segs = n_segs;
  *slow_path = filler;
  *ip4_badp = ip4_bad;

  return n_rx;
}

static_always_inline u32
mlx5_rxq_refill_striding_rq (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 tail)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u16 mask = rxq->size - 1;
  u16 ring_space = rxq->size - (tail - mq->head);
  u32 *buffers = mq->buffers;
  mlx5dv_wqe_ds_t *dv_sq_wqes = mq->dv_sq_wqes;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  const u32 bsz = RDMA_MLX5_RXQ_REFILL_BATCH_SZ;
  u64 va[bsz] __clib_aligned (64);
  u32 log_stride_per_wqe = mq->log_stride_per_wqe;
  u32 log_wqe_sz = mq->log_wqe_sz;
  u32 wqe_sz = 1 << log_wqe_sz;
  u32 stride_per_wqe = 1 << log_stride_per_wqe;

  for (; ring_space >= bsz; tail += bsz, ring_space -= bsz)
    {
      u32 slot = tail & mask;
      u32 *bufs = buffers + slot;
      u32 n = vlib_buffer_alloc_from_pool (vm, bufs, bsz, buffer_pool_index);
      mlx5dv_wqe_ds_t *wqe;

      if (PREDICT_FALSE (n != bsz))
	{
	  vlib_buffer_unalloc_to_pool (vm, bufs, n, buffer_pool_index);
	  break;
	}

      vlib_get_buffers_with_offset (vm, bufs, (void **) va, bsz, sizeof (vlib_buffer_t));

      wqe = dv_sq_wqes + (slot << (log_wqe_sz - log_stride_per_wqe));

      for (u32 i = 0; i < bsz; i += stride_per_wqe)
	{
	  for (u32 j = 0; j < stride_per_wqe; j++)
	    wqe[j + 1].addr = clib_host_to_net_u64 (va[i + j]);
	  wqe += wqe_sz;
	}
    }

  return tail;
}

static_always_inline void
mlx5_rxq_refill_striding (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u32 tail = mq->tail;
  u32 new_tail;

  new_tail = mlx5_rxq_refill_striding_rq (vm, rxq, tail);
  if (new_tail == tail)
    return;

  mq->tail = new_tail;
  mq->striding_wqe_tail += (new_tail - tail) >> mq->log_stride_per_wqe;
  __atomic_store_n (&mq->dv_sq_dbrec[MLX5_RCV_DBR], clib_host_to_net_u32 (mq->striding_wqe_tail),
		    __ATOMIC_RELEASE);
}

static_always_inline u32
mlx5_striding_rq_fast_input (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 *to_next, u32 n_rx_segs,
			     u32 *bc, vlib_buffer_t **bufs)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 mask = rxq->size - 1;
  u32 n_rx_bytes = 0;
  u32 i;

  vlib_buffer_copy_indices_from_ring (to_next, mq->buffers, mq->head & mask, rxq->size, n_rx_segs);
  vlib_get_buffers (vm, to_next, bufs, n_rx_segs);
  mq->head += n_rx_segs;

  for (i = 0; i < n_rx_segs; i++)
    {
      bufs[i]->template = bt;
      bufs[i]->current_length = bc[i] & CQE_BC_BYTE_COUNT_MASK;
      n_rx_bytes += bufs[i]->current_length;
    }

  return n_rx_bytes;
}

static_always_inline u32
mlx5_striding_rq_slow_input (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 *to_next, u32 n_rx_segs,
			     u32 *bc, u32 *n_rx_packets)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_t *pkt_head = 0;
  vlib_buffer_t *pkt_prev = 0;
  vlib_buffer_template_t bt_local = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 mask = rxq->size - 1;
  u32 n_rx_bytes = 0;
  u32 *next_in_frame = to_next;
  u32 n_pkts = *n_rx_packets;
  u32 n_bytes_remaining = 0;
  u32 n_segs_remaining = 0;
  u32 pkt_head_idx = 0;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  int filler_pkt = 0;

  bt_local.current_length = mq->buf_sz;

  while (n_rx_segs > 0)
    {
      u32 n_left = clib_min (n_rx_segs, (u32) VLIB_FRAME_SIZE);
      u32 current_segs[VLIB_FRAME_SIZE];
      u32 to_free_buffers[VLIB_FRAME_SIZE];
      vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
      vlib_buffer_t **pkt;
      u32 *next_to_free = to_free_buffers;
      u32 i;
      u32 remaining;

      vlib_buffer_copy_indices_from_ring (current_segs, mq->buffers, mq->head & mask, rxq->size,
					  n_left);
      mq->head += n_left;
      vlib_get_buffers (vm, current_segs, bufs, n_left);

      pkt = bufs;
      i = 0;
      remaining = n_left;
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
	    pkt_head->total_length_not_including_first_buffer =
	      n_segs_remaining > 1 ? n_bytes_remaining - pkt[0]->current_length : 0;
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
  vnet_main_t *vnm = vnet_get_main ();
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u32 bc[VLIB_FRAME_SIZE];
  u32 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 *to_next;
  u32 n_left_to_next;
  u32 n_rx_bytes = 0;
  u32 n_rx_packets;
  u32 n_rx_segs;
  int slow_path = 0;
  u32 ip4_bad = 0;
  vnet_dev_counter_t *rxq_counters = rxq->counter_main ? rxq->counter_main->counters : 0;
  u8 bufs_valid = 0;
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u32 n_trace;

  n_rx_packets = mlx5_rxq_poll_striding (rxq, bc, &n_rx_segs, &slow_path, &ip4_bad);
  if (n_rx_packets == 0)
    return 0;
  if (ip4_bad)
    vlib_error_count (vm, node->node_index, RDMA_MLX5_RX_NODE_CTR_IP4_CKSUM_BAD, 1);

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  if (slow_path)
    {
      n_rx_bytes = mlx5_striding_rq_slow_input (vm, rxq, to_next, n_rx_segs, bc, &n_rx_packets);
    }
  else
    {
      n_rx_bytes = mlx5_striding_rq_fast_input (vm, rxq, to_next, n_rx_segs, bc, bufs);
      bufs_valid = 1;
    }

  if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      vlib_frame_t *f = vlib_get_frame (vm, nf->frame);
      ethernet_input_frame_t *ef = vlib_frame_scalar_args (f);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
      if (!ip4_bad)
	f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = hw_if_index;
      vlib_frame_no_append (f);
    }

  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      if (!bufs_valid)
	vlib_get_buffers (vm, to_next, bufs, n_rx_packets);
      u32 n_left = n_rx_packets;
      u32 i = 0;
      while (n_trace && n_left)
	{
	  if (vlib_trace_buffer (vm, node, next_index, bufs[i], 0))
	    {
	      mlx5_rx_trace_t *tr = vlib_add_trace (vm, node, bufs[i], sizeof (*tr));
	      tr->next_index = next_index;
	      tr->qid = rxq->queue_id;
	      tr->hw_if_index = hw_if_index;
	      tr->length = bufs[i]->current_length;
	      n_trace--;
	    }
	  n_left--;
	  i++;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx_packets);

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_RX,
				   vm->thread_index, sw_if_index, n_rx_packets, n_rx_bytes);
  if (PREDICT_TRUE (rxq_counters != 0))
    {
      vnet_dev_counter_value_add (vm, rxq_counters + MLX5_RXQ_CTR_PACKETS, n_rx_packets);
      vnet_dev_counter_value_add (vm, rxq_counters + MLX5_RXQ_CTR_BYTES, n_rx_bytes);
      if (PREDICT_FALSE (ip4_bad))
	vnet_dev_counter_value_add (vm, rxq_counters + MLX5_RXQ_CTR_IP4_CKSUM_BAD, ip4_bad);
    }

  return n_rx_packets;
}

VNET_DEV_NODE_FN (mlx5_rx_node_striding)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame __clib_unused)
{
  u32 rv = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      rv += mlx5_rx_one_queue_striding (vm, node, rxq);
      mlx5_rxq_refill_striding (vm, rxq);
    }

  return rv;
}
