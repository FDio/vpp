/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/devices/devices.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/vector/compress.h>
#include <ibverbs.h>

static_always_inline u16
sum_u8_x32 (u8 *x)
{
#if defined(CLIB_HAVE_VEC128) && (IBV_RX_REFILL_BATCH_SZ == 32)
#ifdef CLIB_HAVE_VEC256
  u8x32 v = *(u8x32 *) x;
  u8x16 sum8 = u8x32_extract_lo (v) + u8x32_extract_hi (v);
#else
  u8x16 *vx = (u8x16 *) x;
  u8x16 sum8 = vx[0] + vx[1];
#endif
  u16x8 sum16 = u16x8_from_u8x16 (sum8) + u16x8_from_u8x16_high (sum8);
  return u16x8_sum_elts (sum16);
#else
#warning "ibv_rxq_refill SIMD sum is disabled"
  u16 sum = 0;
  for (u32 i = 0; i < 32; i++)
    sum += x[i];
  return sum;
#endif
}

static_always_inline void
ibv_rxq_refill (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  u32 size = rxq->size;
  u32 head = iq->head;
  u32 tail = iq->tail;
  u16 mask = size - 1;
  u8 max_tails = iq->max_tails;
  u32 n_alloc = IBV_RX_REFILL_BATCH_SZ;
  u32 n;
  u32 all_bufs[IBV_RX_REFILL_BATCH_SZ * IBV_RXQ_MAX_CHAIN_SZ];
  u32 slot;
  u32 *bufs;
  ibv_rx_refill_entry_t *re;
  struct ibv_recv_wr *next_wr;

  if (PREDICT_FALSE (iq->n_left_to_post > 0))
    {
      struct ibv_recv_wr *bad_wr = 0;
      u32 n_posted = 0;
      u32 n_left = iq->n_left_to_post;
      u32 start = IBV_RX_REFILL_BATCH_SZ - n_left;
      int irv;

      if (iq->ibv_wq)
	irv = ibv_post_wq_recv (iq->ibv_wq, &iq->refill_entries[start].recv_wr, &bad_wr);
      else
	irv = ibv_post_recv (iq->ibv_qp, &iq->refill_entries[start].recv_wr, &bad_wr);
      if (irv)
	{
	  vlib_error_count (vm, node->node_index, RDMA_RX_NODE_CTR_IBV_POST_RECV, 1);
	  if (bad_wr)
	    n_posted = (ibv_rx_refill_entry_t *) bad_wr - &iq->refill_entries[start];
	}
      else
	n_posted = n_left;

      tail += n_posted;
      n_left -= n_posted;
      iq->n_left_to_post = n_left;

      if (n_left)
	goto done;
    }

  while ((size - (tail - head)) >= n_alloc)
    {
      u64 va[IBV_RX_REFILL_BATCH_SZ];
      struct ibv_recv_wr *bad_wr = 0;
      slot = tail & mask;
      bufs = iq->buffers + slot;
      re = iq->refill_entries;
      u16 n_tail_refill_sum = 0;
      u32 n_bufs;
      int irv;

      n_tail_refill_sum = max_tails ? sum_u8_x32 (iq->n_tail_refills + slot) : 0;
      n_bufs = n_alloc + n_tail_refill_sum;

      if (PREDICT_FALSE (vlib_buffer_strict_alloc_from_pool (vm, all_bufs, n_bufs, bpi) == 0))
	goto done;
      vlib_buffer_copy_indices_to_ring (iq->buffers, all_bufs, slot, size, n_alloc);

      u32 *next_bi = all_bufs + n_alloc;
      u32 base = slot * max_tails;
      for (u32 i = 0; i < n_alloc; i++)
	{
	  u8 n_refill = iq->n_tail_refills[slot + i];
	  for (u32 j = 0; j < n_refill; j++)
	    {
	      u32 bi = next_bi++[0];
	      vlib_buffer_t *b = vlib_get_buffer (vm, bi);

	      iq->second_bufs[base + j] = bi;
	      iq->refill_entries[i].sge[j + 1].addr = pointer_to_uword ((b->data));
	    }
	  base += max_tails;
	}

      vlib_get_buffers_with_offset (vm, bufs, (void **) va, IBV_RX_REFILL_BATCH_SZ,
				    sizeof (vlib_buffer_t));
      for (u32 i = 0; i < IBV_RX_REFILL_BATCH_SZ; i++)
	re[i].sge[0].addr = va[i];
      re += IBV_RX_REFILL_BATCH_SZ;

      next_wr = re[-1].recv_wr.next;
      re[-1].recv_wr.next = 0;
      n = n_alloc;
      if (iq->ibv_wq)
	irv = ibv_post_wq_recv (iq->ibv_wq, &iq->refill_entries[0].recv_wr, &bad_wr);
      else
	irv = ibv_post_recv (iq->ibv_qp, &iq->refill_entries[0].recv_wr, &bad_wr);
      re[-1].recv_wr.next = next_wr;
      if (irv)
	{
	  vlib_error_count (vm, node->node_index, RDMA_RX_NODE_CTR_IBV_POST_RECV, 1);
	  n = bad_wr ? (ibv_rx_refill_entry_t *) bad_wr - iq->refill_entries : 0;
	  iq->n_left_to_post = n_alloc - n;
	  tail += n;
	  goto done;
	}

      tail += n;
    }

done:
  iq->tail = tail;
}

static_always_inline void
ibv_rx_fix_chains (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, vlib_buffer_t **bufs, u32 first_slot,
		   u32 n_left)
{
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  u32 buf_sz = iq->buf_sz;
  u32 max_tails = iq->max_tails;
  u32 *extra = iq->second_bufs + (first_slot * max_tails);
  u8 *n_tail_refills = iq->n_tail_refills + first_slot;

  while (n_left > 0)
    {
      vlib_buffer_t *b = bufs++[0];
      u32 total_length = b->current_length;
      u32 n = 0;

      if (PREDICT_FALSE (total_length > buf_sz))
	{
	  u32 bi, bytes_left = total_length - buf_sz;

	  b->total_length_not_including_first_buffer = bytes_left;
	  b->flags |= VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  b->current_length = buf_sz;

	  while (bytes_left > buf_sz)
	    {
	      bi = extra[n++];
	      b->next_buffer = bi;
	      b->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      b = vlib_get_buffer (vm, bi);
	      b->current_length = buf_sz;
	      bytes_left -= buf_sz;
	    }

	  bi = extra[n++];
	  b->next_buffer = bi;
	  b = vlib_get_buffer (vm, bi);
	  b->current_length = bytes_left;
	}

      extra += max_tails;
      n_tail_refills++[0] = n;
      n_left--;
    }
}

static_always_inline u32
ibv_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  ibv_rxq_t *iq = vnet_dev_get_rx_queue_data (rxq);
  struct ibv_wc wc[VLIB_FRAME_SIZE];
  u16 pkt_lengths[VLIB_FRAME_SIZE], *pl = pkt_lengths;
  vnet_main_t *vnm = vnet_get_main ();
  u32 next_index;
  u32 *to_next;
  u32 n_left_to_next;
  u32 n_rx_bytes = 0;
  u32 n_ip4_csum_ok = 0;
  int n_rx = 0;
  u32 mask = rxq->size - 1;
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u32 n_trace;
  u32 n_left;
  u32 slot;
  u32 n_drop = 0;
  u32 to_drop[VLIB_FRAME_SIZE];
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;

  n_rx = ibv_poll_cq (iq->ibv_cq, VLIB_FRAME_SIZE, wc);
  if (n_rx < 0)
    vlib_error_count (vm, node->node_index, RDMA_RX_NODE_CTR_IBV_POLL_CQ, 1);

  if (PREDICT_FALSE (n_rx <= 0))
    return 0;

  next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  slot = iq->head & mask;

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  vlib_buffer_copy_indices_from_ring (to_next, iq->buffers, slot, rxq->size, n_rx);
  iq->head += n_rx;

  vlib_frame_bitmap_t bad_bmp = {};
  vlib_frame_bitmap_init (bad_bmp, n_rx);

  for (u32 i = 0; i < n_rx; i++)
    if (wc[i].status != IBV_WC_SUCCESS)
      {
	vlib_frame_bitmap_clear_bit_at_index (bad_bmp, i);
	to_drop[n_drop++] = to_next[i];
      }
    else
      {
	n_rx_bytes += pl++[0] = wc[i].byte_len;
	if (wc[i].wc_flags & IBV_WC_IP_CSUM_OK)
	  n_ip4_csum_ok++;
      }

  if (n_drop)
    {
      clib_compress_u32 (to_next, to_next, bad_bmp, n_rx);
      n_rx -= n_drop;
    }

  vlib_get_buffers (vm, to_next, bufs, n_rx);

  for (pl = pkt_lengths, b = bufs, n_left = n_rx; n_left >= 4; b += 4, n_left -= 4, pl += 4)
    {
      if (PREDICT_TRUE (n_left >= 8))
	{
	  vlib_prefetch_buffer_header (b[4], STORE);
	  vlib_prefetch_buffer_header (b[5], STORE);
	  vlib_prefetch_buffer_header (b[6], STORE);
	  vlib_prefetch_buffer_header (b[7], STORE);
	}

      b[0]->template = bt;
      b[1]->template = bt;
      b[2]->template = bt;
      b[3]->template = bt;

      b[0]->current_length = pl[0];
      b[1]->current_length = pl[1];
      b[2]->current_length = pl[2];
      b[3]->current_length = pl[3];
    }

  for (; n_left > 0; b += 1, n_left -= 1, pl += 1)
    {
      b[0]->template = bt;
      b[0]->current_length = pl[0];
    }

  if (iq->max_tails)
    {
      u32 n_wrap = slot + n_rx > rxq->size ? slot + n_rx - rxq->size : 0;
      u32 off = n_rx - n_wrap;
      ibv_rx_fix_chains (vm, rxq, bufs, slot, off);
      if (PREDICT_FALSE (n_wrap))
	ibv_rx_fix_chains (vm, rxq, bufs + off, 0, n_wrap);
    }

  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      u32 i = 0;
      u32 j = 0;
      while (n_trace && i < n_rx + n_drop && j < n_rx)
	{
	  if (wc[i].status == IBV_WC_SUCCESS)
	    {
	      vlib_buffer_t *tb = bufs[j];
	      if (vlib_trace_buffer (vm, node, next_index, tb, 0))
		{
		  ibv_rx_trace_t *tr = vlib_add_trace (vm, node, tb, sizeof (*tr));
		  tr->next_index = next_index;
		  tr->qid = rxq->queue_id;
		  tr->hw_if_index = hw_if_index;
		  tr->wc = wc[i];
		  n_trace--;
		}
	      j++;
	    }
	  i++;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  if (PREDICT_FALSE (n_drop))
    {
      vlib_buffer_free (vm, to_drop, n_drop);
      vlib_error_count (vm, node->node_index, RDMA_RX_NODE_CTR_WC_STATUS, n_drop);
    }

  if (PREDICT_FALSE (n_rx == 0))
    {
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
      return 0;
    }

  if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf;
      vlib_frame_t *f;
      ethernet_input_frame_t *ef;
      nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      f = vlib_get_frame (vm, nf->frame);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;
      if (n_ip4_csum_ok == n_rx)
	f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = hw_if_index;
      vlib_frame_no_append (f);
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next - n_rx);

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_RX,
				   vm->thread_index, sw_if_index, n_rx, n_rx_bytes);

  return n_rx;
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
