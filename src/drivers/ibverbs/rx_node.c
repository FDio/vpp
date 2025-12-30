/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/devices/devices.h>
#include <vnet/ethernet/ethernet.h>
#include <ibverbs.h>

static_always_inline void
ibv_rxq_refill (vlib_main_t *vm, vlib_node_runtime_t *node,
		vnet_dev_rx_queue_t *rxq)
{
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u16 mask = rxq->size - 1;
  u16 ring_space = rxq->size - (iq->tail - iq->head);
  u32 slot = iq->tail & mask;
  u32 slot_orig = slot;
  u32 n_wr = 1u << RDMA_IBV_RX_REFILL_LOG2_BATCH_SZ;
  u32 n_alloc = clib_min (n_wr, ring_space);
  u32 n, i;
  u32 extras_per = iq->n_ds_per_wqe - 1;
  u32
    extra_bufs[RDMA_IBV_RX_REFILL_BATCH_SZ * (RDMA_IBV_RXQ_MAX_CHAIN_SZ - 1)];
  u32 n_extra;
  u32 n_extra_alloc;
  u32 n_full;
  u32 n_free;
  u32 base;
  u32 idx;
  u32 j;
  u32 *bufs = iq->buffers + slot;
  ibv_rx_refill_entry_t *re = iq->refill_entries;
  struct ibv_recv_wr *next_wr, *bad_wr = 0;
  int rv_ibv;
  u8 buffer_pool_index = vnet_dev_get_rx_queue_buffer_pool_index (rxq);

  if (n_alloc < 16)
    return;

  n_alloc = clib_min (n_alloc, rxq->size - slot);
  n_alloc &= ~(8 - 1);

  n = vlib_buffer_alloc_to_ring_from_pool (vm, iq->buffers, slot, rxq->size,
					   n_alloc, buffer_pool_index);
  if (PREDICT_FALSE (n != n_alloc))
    {
      u32 n_free;
      if (n < 8)
	{
	  if (n)
	    vlib_buffer_free_from_ring (vm, iq->buffers, slot, rxq->size, n);
	  return;
	}

      n_free = n & (8 - 1);
      n -= n_free;
      if (n_free)
	vlib_buffer_free_from_ring (vm, iq->buffers, (slot + n) & mask,
				    rxq->size, n_free);
    }

  n_alloc = n;
  if (extras_per && n_alloc)
    {
      n_extra = n_alloc * extras_per;
      n_extra_alloc = vlib_buffer_alloc_from_pool (vm, extra_bufs, n_extra,
						   buffer_pool_index);
      if (PREDICT_FALSE (n_extra_alloc != n_extra))
	{
	  n_full = n_extra_alloc / extras_per;
	  n_full &= ~(8 - 1);
	  n_free = n_extra_alloc - (n_full * extras_per);
	  if (n_free)
	    vlib_buffer_free (vm, extra_bufs + (n_full * extras_per), n_free);
	  if (n_full == 0)
	    {
	      vlib_buffer_free_from_ring (vm, iq->buffers, slot, rxq->size,
					  n_alloc);
	      return;
	    }
	  if (n_full != n_alloc)
	    vlib_buffer_free_from_ring (vm, iq->buffers, slot + n_full,
					rxq->size, n_alloc - n_full);
	  n_alloc = n_full;
	}

      for (i = 0; i < n_alloc; i++)
	{
	  idx = i * extras_per;
	  base = (slot + i) * extras_per;
	  for (j = 0; j < extras_per; j++)
	    iq->second_bufs[base + j] = extra_bufs[idx + j];
	  iq->n_used_per_chain[slot + i] = extras_per;
	}
      iq->n_total_additional_segs += n_alloc * extras_per;
    }

  if (n_alloc == 0)
    return;

  n = n_alloc;
  while (n >= 8)
    {
      u64 va[8];

      if (PREDICT_TRUE (n >= 16))
	{
	  clib_prefetch_store (re + 16);
	}

      vlib_get_buffers_with_offset (vm, bufs, (void **) va, 8,
				    sizeof (vlib_buffer_t));

      re[0].sge[0].addr = va[0];
      re[1].sge[0].addr = va[1];
      re[2].sge[0].addr = va[2];
      re[3].sge[0].addr = va[3];
      re[4].sge[0].addr = va[4];
      re[5].sge[0].addr = va[5];
      re[6].sge[0].addr = va[6];
      re[7].sge[0].addr = va[7];

      if (extras_per)
	{
	  for (j = 0; j < 8; j++)
	    {
	      u32 *extra = iq->second_bufs + ((slot + j) * extras_per);
	      u32 k;

	      for (k = 1; k < iq->n_ds_per_wqe; k++)
		{
		  u64 addr;
		  u32 bi = extra[k - 1];

		  vlib_get_buffers_with_offset (vm, &bi, (void **) &addr, 1,
						sizeof (vlib_buffer_t));
		  re[j].sge[k].addr = addr;
		}
	    }
	}

      re += 8;
      bufs += 8;
      slot += 8;
      n -= 8;
    }

  next_wr = re[-1].recv_wr.next;
  re[-1].recv_wr.next = 0;
  n = n_alloc;
  rv_ibv = ibv_post_recv (iq->ibv_qp, &iq->refill_entries[0].recv_wr, &bad_wr);
  if (rv_ibv)
    {
      vlib_error_count (vm, node->node_index, RDMA_RX_NODE_CTR_IBV_POST_RECV,
			1);
      n = 0;
      if (bad_wr)
	{
	  for (i = 0; i < n_alloc; i++)
	    {
	      if (&iq->refill_entries[i].recv_wr == bad_wr)
		break;
	    }
	  n = i;
	}
      vlib_buffer_free_from_ring (vm, iq->buffers, slot_orig + n, rxq->size,
				  n_alloc - n);
      if (extras_per && n_alloc != n)
	{
	  n_free = n_alloc - n;
	  for (i = 0; i < n_free; i++)
	    {
	      base = (slot_orig + n + i) * extras_per;
	      vlib_buffer_free (vm, iq->second_bufs + base, extras_per);
	      iq->n_used_per_chain[slot_orig + n + i] = 0;
	    }
	  if (iq->n_total_additional_segs >= n_free * extras_per)
	    iq->n_total_additional_segs -= n_free * extras_per;
	}
    }
  re[-1].recv_wr.next = next_wr;

  iq->tail += n;
}

static_always_inline u32
ibv_input_bufs (vnet_dev_rx_queue_t *rxq, vlib_buffer_t **b, struct ibv_wc *wc,
		u32 n_left_from)
{
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 n_rx_bytes = 0;

  while (n_left_from >= 4)
    {
      if (PREDICT_TRUE (n_left_from >= 8))
	{
	  clib_prefetch_load (wc + 4);
	  clib_prefetch_load (wc + 5);
	  clib_prefetch_load (wc + 6);
	  clib_prefetch_load (wc + 7);
	  vlib_prefetch_buffer_header (b[4 + 0], STORE);
	  vlib_prefetch_buffer_header (b[4 + 1], STORE);
	  vlib_prefetch_buffer_header (b[4 + 2], STORE);
	  vlib_prefetch_buffer_header (b[4 + 3], STORE);
	}

      b[0]->template = bt;
      b[1]->template = bt;
      b[2]->template = bt;
      b[3]->template = bt;

      n_rx_bytes += b[0]->current_length = wc[0].byte_len;
      n_rx_bytes += b[1]->current_length = wc[1].byte_len;
      n_rx_bytes += b[2]->current_length = wc[2].byte_len;
      n_rx_bytes += b[3]->current_length = wc[3].byte_len;

      b += 4;
      wc += 4;
      n_left_from -= 4;
    }

  while (n_left_from >= 1)
    {
      b[0]->template = bt;
      n_rx_bytes += b[0]->current_length = wc[0].byte_len;

      b += 1;
      wc += 1;
      n_left_from -= 1;
    }

  return n_rx_bytes;
}

static_always_inline void
ibv_legacy_rq_fix_chains (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq,
			  vlib_buffer_t **bufs, u32 qs_mask, u32 n)
{
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 buf_sz = iq->buf_sz;
  u32 extras_per = iq->n_ds_per_wqe - 1;
  uword slot = (iq->head - n) & qs_mask;
  u32 *extra = iq->second_bufs + (slot * extras_per);
  u32 n_wrap_around = (slot + n) & (qs_mask + 1) ? (slot + n) & qs_mask : 0;
  u8 *n_used_per_chain = &iq->n_used_per_chain[slot];
  u32 total_length;
  u32 n_extra_used;
  u32 seg;
  u8 extras_alloc;
  vlib_buffer_t *current_buf;

  n -= n_wrap_around;

wrap_around:
  while (n > 0)
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
	      if (n_extra_used > extras_per)
		n_extra_used = extras_per;

	      current_buf->current_length = buf_sz;
	      total_length -= buf_sz;
	      current_buf->total_length_not_including_first_buffer =
		total_length;
	      current_buf->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      current_buf->next_buffer = extra[0];

	      for (seg = 0; seg < n_extra_used; seg++)
		{
		  current_buf = vlib_get_buffer (vm, current_buf->next_buffer);
		  current_buf->template = bt;
		  current_buf->current_length =
		    clib_min (buf_sz, total_length);
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

	      if (n_extra_used < extras_per)
		vlib_buffer_free (vm, extra + n_extra_used,
				  extras_per - n_extra_used);
	    }
	  else
	    {
	      vlib_buffer_free (vm, extra, extras_per);
	    }

	  if (iq->n_total_additional_segs >= extras_alloc)
	    iq->n_total_additional_segs -= extras_alloc;
	  n_used_per_chain[0] = 0;
	}
      bufs++;
      extra += extras_per;
      n_used_per_chain++;
      n--;
    }
  if (PREDICT_FALSE (n_wrap_around))
    {
      n = n_wrap_around;
      n_wrap_around = 0;
      extra = iq->second_bufs;
      n_used_per_chain = iq->n_used_per_chain;
      goto wrap_around;
    }
}

static_always_inline u32
ibv_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vnet_dev_rx_queue_t *rxq)
{
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  vnet_main_t *vnm = vnet_get_main ();
  u32 next_index;
  u32 *to_next;
  u32 n_left_to_next;
  u32 n_rx_bytes = 0;
  int n_rx_packets = 0;
  u32 mask = rxq->size - 1;
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u32 n_trace;
  u32 n_left;
  u32 i;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE];

  n_rx_packets = ibv_poll_cq (iq->ibv_cq, VLIB_FRAME_SIZE, wc);
  if (n_rx_packets < 0)
    vlib_error_count (vm, node->node_index, RDMA_RX_NODE_CTR_IBV_POLL_CQ, 1);

  if (PREDICT_FALSE (n_rx_packets <= 0))
    return 0;

  next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  vlib_buffer_copy_indices_from_ring (to_next, iq->buffers, iq->head & mask,
				      rxq->size, n_rx_packets);
  vlib_get_buffers (vm, to_next, bufs, n_rx_packets);
  iq->head += n_rx_packets;
  n_rx_bytes = ibv_input_bufs (rxq, bufs, wc, n_rx_packets);
  if (iq->n_ds_per_wqe > 1)
    ibv_legacy_rq_fix_chains (vm, rxq, bufs, mask, n_rx_packets);

  if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf;
      vlib_frame_t *f;
      ethernet_input_frame_t *ef;
      nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      f = vlib_get_frame (vm, nf->frame);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = hw_if_index;
      vlib_frame_no_append (f);
    }

  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      n_left = n_rx_packets;
      i = 0;
      while (n_trace && n_left)
	{
	  if (vlib_trace_buffer (vm, node, next_index, bufs[i], 0))
	    {
	      ibv_rx_trace_t *tr =
		vlib_add_trace (vm, node, bufs[i], sizeof (*tr));
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

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, sw_if_index, n_rx_packets, n_rx_bytes);

  return n_rx_packets;
}

VNET_DEV_NODE_FN (ibv_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 rv = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      rv += ibv_rx_one_queue (vm, node, rxq);
      ibv_rxq_refill (vm, node, rxq);
    }

  return rv;
}
