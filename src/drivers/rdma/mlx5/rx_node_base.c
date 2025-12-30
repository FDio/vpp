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

static_always_inline u32
mlx5_rxq_refill_legacy_multiseg (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 tail)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u16 mask = rxq->size - 1;
  u16 ring_space = rxq->size - (tail - mq->head);
  u32 *buffers = mq->buffers;
  mlx5dv_wqe_ds_t *dv_sq_wqes = mq->dv_sq_wqes;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  const u32 bsz = RDMA_MLX5_RXQ_REFILL_BATCH_SZ;
  const u32 alloc_sz = bsz * RDMA_RXQ_LEGACY_MODE_MAX_CHAIN_SZ;
  u64 va[alloc_sz] __clib_aligned (64);
  u32 log_wqe_sz = mq->log_wqe_sz;
  u32 n_ds_per_wqe = mq->n_ds_per_wqe;
  u32 n_tail = n_ds_per_wqe - 1;
  u32 all_bufs[alloc_sz];

  for (; ring_space >= bsz;)
    {
      u32 slot = tail & mask;
      mlx5dv_wqe_ds_t *wqe = dv_sq_wqes + (slot << log_wqe_sz);
      u32 n_total = bsz * n_ds_per_wqe;
      u32 n_now = clib_min (bsz, rxq->size - slot);
      ASSERT (n_total <= alloc_sz);
      u32 n = vlib_buffer_alloc_from_pool (vm, all_bufs, n_total, buffer_pool_index);

      if (PREDICT_FALSE (n != n_total))
	{
	  if (n)
	    vlib_buffer_unalloc_to_pool (vm, all_bufs, n, buffer_pool_index);
	  break;
	}

      vlib_get_buffers_with_offset (vm, all_bufs, (void **) va, n_total, sizeof (vlib_buffer_t));

      vlib_buffer_copy_indices (buffers + slot, all_bufs, n_now);
      if (n_now != bsz)
	vlib_buffer_copy_indices (buffers, all_bufs + n_now, bsz - n_now);

      for (u32 i = 0; i < bsz; i++)
	{
	  u32 idx = i * n_tail;
	  u32 base = (slot + i) * n_tail;
	  u32 extra_base = bsz + idx;
	  wqe = dv_sq_wqes + ((slot + i) << log_wqe_sz);
	  wqe[0].addr = clib_host_to_net_u64 (va[i]);
	  for (u32 j = 0; j < n_tail; j++)
	    {
	      u32 bi = all_bufs[extra_base + j];
	      mq->second_bufs[base + j] = bi;
	      wqe[j + 1].addr = clib_host_to_net_u64 (va[extra_base + j]);
	    }
	  mq->n_used_per_chain[slot + i] = (u8) n_tail;
	}
      mq->n_total_additional_segs += bsz * n_tail;

      tail += bsz;
      ring_space -= bsz;
    }

  return tail;
}

static_always_inline u32
mlx5_rxq_refill_legacy (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 tail)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u16 mask = rxq->size - 1;
  u16 ring_space = rxq->size - (tail - mq->head);
  u32 *buffers = mq->buffers;
  mlx5dv_wqe_ds_t *dv_sq_wqes = mq->dv_sq_wqes;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  const u32 bsz = RDMA_MLX5_RXQ_REFILL_BATCH_SZ;
  u64 va[bsz] __clib_aligned (64);

  for (; ring_space >= bsz; tail += bsz, ring_space -= bsz)
    {
      u32 slot = tail & mask;
      u32 *bufs = buffers + slot;
      mlx5dv_wqe_ds_t *wqe = dv_sq_wqes + slot;
      u32 n = vlib_buffer_alloc_from_pool (vm, bufs, bsz, buffer_pool_index);

      if (PREDICT_FALSE (n != bsz))
	{
	  vlib_buffer_unalloc_to_pool (vm, bufs, n, buffer_pool_index);
	  break;
	}

      vlib_get_buffers_with_offset (vm, bufs, (void **) va, bsz, sizeof (vlib_buffer_t));

      for (u32 i = 0; i < bsz; i++)
	wqe[i].addr = clib_host_to_net_u64 (va[i]);
    }

  return tail;
}

static_always_inline void
mlx5_rxq_refill_legacy_mode (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  u32 tail = mq->tail;
  u32 new_tail;

  if (mq->n_ds_per_wqe > 1)
    new_tail = mlx5_rxq_refill_legacy_multiseg (vm, rxq, tail);
  else
    new_tail = mlx5_rxq_refill_legacy (vm, rxq, tail);
  if (new_tail == tail)
    return;

  mq->tail = new_tail;
  __atomic_store_n (&mq->dv_sq_dbrec[MLX5_RCV_DBR], clib_host_to_net_u32 (new_tail),
		    __ATOMIC_RELEASE);
}

static_always_inline u32
mlx5_legacy_input (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, u32 *to_next, u32 *bc,
		   u32 n_rx_packets, u32 mask, u32 n_ds_per_wqe, vlib_buffer_t **bufs)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 n_rx_bytes = 0;
  u32 i;

  vlib_buffer_copy_indices_from_ring (to_next, mq->buffers, mq->head & mask, rxq->size,
				      n_rx_packets);
  vlib_get_buffers (vm, to_next, bufs, n_rx_packets);
  mq->head += n_rx_packets;

  for (i = 0; i < n_rx_packets; i++)
    {
      bufs[i]->template = bt;
      bufs[i]->current_length = bc[i];
      n_rx_bytes += bc[i];
    }
  if (n_ds_per_wqe > 1)
    {
      u32 buf_sz = mq->buf_sz;
      u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
      u32 n_tail = n_ds_per_wqe - 1;
      uword slot = (mq->head - n_rx_packets) & mask;
      u32 *extra = mq->second_bufs + (slot * n_tail);
      u32 n_wrap_around = (slot + n_rx_packets) & (mask + 1) ? (slot + n_rx_packets) & mask : 0;
      u8 *n_used_per_chain = &mq->n_used_per_chain[slot];
      u32 n_fix = n_rx_packets - n_wrap_around;
      u32 total_length;
      u32 n_extra_used;
      u32 seg;
      u8 extras_alloc;
      vlib_buffer_t *current_buf;

    wrap_around:
      while (n_fix > 0)
	{
	  total_length = bufs[0]->current_length;
	  extras_alloc = n_used_per_chain[0];

	  if (extras_alloc)
	    {
	      if (total_length > buf_sz)
		{
		  current_buf = bufs[0];
		  n_extra_used = (total_length + buf_sz - 1) / buf_sz;
		  if (n_extra_used)
		    n_extra_used -= 1;
		  if (n_extra_used > n_tail)
		    n_extra_used = n_tail;

		  current_buf->current_length = buf_sz;
		  total_length -= buf_sz;
		  current_buf->total_length_not_including_first_buffer = total_length;
		  current_buf->flags |= VLIB_BUFFER_NEXT_PRESENT;
		  current_buf->next_buffer = extra[0];

		  for (seg = 0; seg < n_extra_used; seg++)
		    {
		      current_buf = vlib_get_buffer (vm, current_buf->next_buffer);
		      current_buf->template = bt;
		      current_buf->current_length = clib_min (buf_sz, total_length);
		      total_length -= current_buf->current_length;
		      if (seg + 1 < n_extra_used)
			{
			  current_buf->flags |= VLIB_BUFFER_NEXT_PRESENT;
			  current_buf->next_buffer = extra[seg + 1];
			}
		      else
			{
			  current_buf->flags &= ~VLIB_BUFFER_NEXT_PRESENT;
			  current_buf->next_buffer = 0;
			}
		    }

		  if (n_extra_used < n_tail)
		    vlib_buffer_unalloc_to_pool (vm, extra + n_extra_used, n_tail - n_extra_used,
						 buffer_pool_index);
		}
	      else
		{
		  vlib_buffer_unalloc_to_pool (vm, extra, n_tail, buffer_pool_index);
		}

	      if (mq->n_total_additional_segs >= extras_alloc)
		mq->n_total_additional_segs -= extras_alloc;
	      n_used_per_chain[0] = 0;
	    }
	  bufs++;
	  extra += n_tail;
	  n_used_per_chain++;
	  n_fix--;
	}
      if (PREDICT_FALSE (n_wrap_around))
	{
	  n_fix = n_wrap_around;
	  n_wrap_around = 0;
	  extra = mq->second_bufs;
	  n_used_per_chain = mq->n_used_per_chain;
	  goto wrap_around;
	}
    }

  return n_rx_bytes;
}

static_always_inline u32
mlx5_rxq_poll (vnet_dev_rx_queue_t *rxq, u32 *byte_cnt, u32 *ip4_badp)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  mlx5dv_cqe_t *cqes = (mlx5dv_cqe_t *) mq->dv_cq_cqes;
  u32 log2_cq_size = mq->dv_cq_log2;
  u32 mask = mq->dv_cq_size - 1;
  u32 dv_cq_idx = mq->dv_cq_idx;
  u32 n_rx = 0;
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

      if (cqe_last_byte == 0x20)
	{
	  byte_cnt[0] = clib_net_to_host_u32 (cqe->byte_cnt);
	  cqe_flags = (u16) mlx5_get_bits (cqe, 0x1c, 31, 16);
	  ip4_bad += (CQE_FLAG_L3_HDR_TYPE (cqe_flags) == CQE_FLAG_L3_HDR_TYPE_IP4) &&
		     ((cqe_flags & CQE_FLAG_L3_OK) == 0);
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

  *ip4_badp = ip4_bad;
  return n_rx;
}

static_always_inline u32
mlx5_rx_one_queue_base (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  mlx5_rxq_t *mq = vnet_dev_get_rx_queue_data (rxq);
  vnet_main_t *vnm = vnet_get_main ();
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];
  u32 bc[VLIB_FRAME_SIZE];
  u32 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 *to_next;
  u32 n_left_to_next;
  u32 n_rx_bytes = 0;
  u32 n_rx_packets;
  u32 mask = rxq->size - 1;
  u32 ip4_bad = 0;
  vnet_dev_counter_t *rxq_counters = rxq->counter_main ? rxq->counter_main->counters : 0;
  u8 bufs_valid = 0;
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u32 n_trace;

  n_rx_packets = mlx5_rxq_poll (rxq, bc, &ip4_bad);

  if (n_rx_packets == 0)
    return 0;
  if (ip4_bad)
    vlib_error_count (vm, node->node_index, RDMA_MLX5_RX_NODE_CTR_IP4_CKSUM_BAD, 1);
  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  u32 n_ds_per_wqe = mq->n_ds_per_wqe;

  if (n_ds_per_wqe == 1)
    n_rx_bytes = mlx5_legacy_input (vm, rxq, to_next, bc, n_rx_packets, mask, 1, bufs);
  else
    n_rx_bytes = mlx5_legacy_input (vm, rxq, to_next, bc, n_rx_packets, mask, n_ds_per_wqe, bufs);
  bufs_valid = 1;

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

VNET_DEV_NODE_FN (mlx5_rx_node_base)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame __clib_unused)
{
  u32 rv = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      rv += mlx5_rx_one_queue_base (vm, node, rxq);
      mlx5_rxq_refill_legacy_mode (vm, rxq);
    }

  return rv;
}
