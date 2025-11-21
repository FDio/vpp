/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <atlantic.h>

static_always_inline int
atl_rxq_refill_one_batch (vlib_main_t *vm, atl_rx_desc_t *desc_ring, u32 *bi_ring, u32 ring_size,
			  u16 off, u8 bpi, int va_dma, u32 n_descs)
{
  uword data[4 * ATL_RX_REFILL_BATCH_SZ] __clib_aligned (64);

  if (!vlib_buffer_strict_alloc_to_ring_from_pool (vm, bi_ring, off, ring_size, n_descs, bpi))
    return 0;

  vlib_get_buffers_with_offset (vm, bi_ring + off, (void **) data, n_descs,
				STRUCT_OFFSET_OF (vlib_buffer_t, data));

  if (!va_dma)
    for (u32 j = 0; j < n_descs; j++)
      data[j] = vlib_physmem_get_pa (vm, uword_to_pointer (data[j], void *));

#if defined(CLIB_HAVE_VEC512)
  u64x8 *av = (u64x8 *) data;
  u64x8 *dv = (u64x8 *) (desc_ring + off);
  for (u32 j = 0; j < n_descs / 8; j += 1, av += 1, dv += 2)
    {
      dv[0] = u64x8_shuffle2 (av[0], (u64x8){}, 0, 8, 1, 8, 2, 8, 3, 8);
      dv[1] = u64x8_shuffle2 (av[0], (u64x8){}, 4, 8, 5, 8, 6, 8, 7, 8);
    }
#elif defined(CLIB_HAVE_VEC256)
  u64x4 *av = (u64x4 *) data;
  u64x4 *dv = (u64x4 *) (desc_ring + off);
  for (u32 j = 0; j < n_descs / 4; j += 1, av += 1, dv += 2)
    {
      dv[0] = u64x4_shuffle2 (av[0], (u64x4){}, 0, 4, 1, 4);
      dv[1] = u64x4_shuffle2 (av[0], (u64x4){}, 2, 4, 3, 4);
    }
#else
  for (u32 j = 0; j < n_descs; j++)
    desc_ring[off + j] = (atl_rx_desc_t){
      .buf_addr = data[j],
    };
#endif

  return 1;
}

static_always_inline void
atl_rxq_refill (vlib_main_t *vm, vnet_dev_rx_queue_t *rxq, int va_dma)
{
  atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
  u32 *bi_ring = aq->buffer_indices;
  u16 n_refill;
  u16 size = rxq->size;
  u16 mask = size - 1;
  u16 tail = aq->tail;
  u16 off;
  u8 bpi = vnet_dev_get_rx_queue_buffer_pool_index (rxq);
  atl_rx_desc_t *desc_ring = aq->descs;
  const u32 x4_sz = 4 * ATL_RX_REFILL_BATCH_SZ;
  const u32 x1_sz = ATL_RX_REFILL_BATCH_SZ;

  n_refill = aq->head + size - tail;
  if (n_refill <= x1_sz)
    return;

  n_refill -= x1_sz;
  for (; n_refill >= x1_sz;)
    {
      off = tail & mask;
      if (n_refill >= x4_sz && off + x4_sz <= size)
	{
	  if (!atl_rxq_refill_one_batch (vm, desc_ring, bi_ring, size, off, bpi, va_dma, x4_sz))
	    break;
	  tail += x4_sz;
	  n_refill -= x4_sz;
	}
      else
	{
	  if (!atl_rxq_refill_one_batch (vm, desc_ring, bi_ring, size, off, bpi, va_dma, x1_sz))
	    break;
	  tail += x1_sz;
	  n_refill -= x1_sz;
	}
    }
  if (aq->tail != tail)
    {
      aq->tail = tail;
      __atomic_store_n (aq->tail_reg, tail & mask, __ATOMIC_RELEASE);
    }
}

static_always_inline uword
atl_rx_one_queue (vlib_main_t *vm, vlib_node_runtime_t *node, vnet_dev_rx_queue_t *rxq)
{
  vnet_main_t *vnm = vnet_get_main ();
  atl_rxq_t *aq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 buffer_indices[VLIB_FRAME_SIZE];
  u32 drop_indices[VLIB_FRAME_SIZE];
  u16 desc_ring_indices[VLIB_FRAME_SIZE];
  atl_rx_desc_t pkt_desc_or = {};
  vlib_buffer_t *buffers[VLIB_FRAME_SIZE];
  u32 n_descs = 0, n_drop = 0, n_pkts = 0, n_rx_bytes = 0, n_trace;
  u32 n_pkt_descs = 0;
  u32 n_left = VLIB_FRAME_SIZE;
  u32 next_index, sw_if_index;
  u16 head = aq->head;
  u16 pkt_head_slot = 0;
  u16 mask = rxq->size - 1;
  u16 slot = head & mask;
  u32 *to_next;
  u32 n_left_to_next;
  atl_rx_desc_t *descs = aq->descs;
  atl_rx_desc_t *next = descs + slot;
  atl_rx_desc_qw1_t qw1;
  u16 frame_max = vnet_dev_get_rx_queue_buffer_data_size (vm, rxq);
  atl_rx_desc_t all_desc_or = {};
  u32 *pkt_buffer_indices = buffer_indices;
  n_trace = vlib_get_trace_count (vm, node);

  qw1.as_u64 = __atomic_load_n (&next->qw1.as_u64, __ATOMIC_ACQUIRE);
  while ((qw1.dd) && n_left)
    {
      atl_rx_desc_t d = *next;
      u32 bi = aq->buffer_indices[slot];
      vlib_buffer_t *b = vlib_get_buffer (vm, bi);

      if (n_pkt_descs == 0)
	pkt_head_slot = slot;
      pkt_desc_or.as_u64x2 |= d.as_u64x2;
      pkt_buffer_indices[n_pkt_descs] = bi;
      b->template = bt;
      b->current_length = d.qw1.pkt_len;
      n_pkt_descs++;
      n_left--;

      if (PREDICT_TRUE (qw1.eop))
	{
	  atl_rx_desc_t bad_desc = { .qw1.mac_err = 1, .qw0.dma_err = 1 };
	  if (PREDICT_FALSE (!u64x2_is_all_zero (pkt_desc_or.as_u64x2 & bad_desc.as_u64x2)))
	    {
	      vlib_buffer_copy_indices (drop_indices + n_drop, pkt_buffer_indices, n_pkt_descs);
	      n_drop += n_pkt_descs;
	    }
	  else
	    {
	      desc_ring_indices[n_pkts] = pkt_head_slot;
	      all_desc_or.as_u64x2 |= pkt_desc_or.as_u64x2;
	      n_rx_bytes += d.qw1.pkt_len;
	      n_descs += n_pkt_descs;
	      pkt_buffer_indices += n_pkt_descs;
	      n_pkts++;
	    }

	  n_pkt_descs = 0;
	  pkt_desc_or.as_u64x2 = (u64x2){};
	}

      slot = (slot + 1) & mask;
      next = descs + slot;
      qw1.as_u64 = __atomic_load_n (&next->qw1.as_u64, __ATOMIC_ACQUIRE);
    }

  if (PREDICT_FALSE (n_drop))
    {
      vlib_buffer_free (vm, drop_indices, n_drop);
      vlib_error_count (vm, node->node_index, ATL_RX_NODE_CTR_RX_DESC_ERROR_DROP, n_drop);
    }

  aq->head = head + n_descs + n_drop;
  if (n_pkts == 0)
    return 0;

  next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);

  if (PREDICT_FALSE (n_trace))
    {
      for (u32 i = 0; i < n_pkts && n_trace > 0; i++)
	{
	  u16 head_slot = desc_ring_indices[i];
	  u32 bi = aq->buffer_indices[head_slot];
	  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
	  if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next_index, b, 0)))
	    {
	      atl_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->sw_if_index = sw_if_index;
	      tr->queue_id = rxq->queue_id;
	      tr->head_slot = head_slot;
	      tr->buffer_index = bi;
	      for (u32 j = 0, slot = head_slot; j < ATL_RX_TRACE_N_DESC;
		   j++, slot = (slot + 1) & mask)
		{
		  tr->desc[j] = descs[slot];
		  if (tr->desc[j].qw1.eop)
		    break;
		}
	      n_trace--;
	    }
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);
  ASSERT (n_left_to_next >= n_pkts);

  vlib_get_buffers (vm, buffer_indices, buffers, n_descs);

  if (PREDICT_TRUE (n_pkts < n_descs))
    {
      u32 n_enq = 0;
      u32 *bi = buffer_indices;
      for (vlib_buffer_t **pb = buffers, **b = buffers; pb < buffers + n_pkts; pb++, b++, bi++)
	{
	  u16 head_slot = desc_ring_indices[pb - buffers];
	  atl_rx_desc_t *d = descs + (head_slot & mask);

	  if (PREDICT_FALSE (d->qw1.eop == 0))
	    {
	      u32 pkt_len = descs[head_slot].qw1.pkt_len;
	      u32 bytes_left = pkt_len - frame_max;
	      u16 s = 1;
	      vlib_buffer_t *head = b[0], *prev = head, *curr = b[1];

	      /* update head buffer metadata */
	      head->current_length = frame_max;
	      head->total_length_not_including_first_buffer = pkt_len - frame_max;
	      head->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;

	      d = descs + ((head_slot + s) & mask);

	      while (d->qw1.eop == 0)
		{
		  curr->current_length = frame_max;
		  bytes_left -= frame_max;
		  prev->next_buffer = bi[s];
		  prev->flags |= VLIB_BUFFER_NEXT_PRESENT;
		  prev = curr;
		  s++;
		  curr = b[s];
		  d = descs + ((head_slot + s) & mask);
		}

	      prev->next_buffer = bi[s];
	      prev->flags |= VLIB_BUFFER_NEXT_PRESENT;

	      /* update tail buffer metadata */
	      curr->current_length = bytes_left;

	      to_next[n_enq++] = aq->buffer_indices[head_slot];
	      b += s;
	      bi += s;
	    }
	  else
	    to_next[n_enq++] = aq->buffer_indices[head_slot];
	}
      ASSERT (n_enq == n_pkts);
    }
  else
    vlib_buffer_copy_indices (to_next, buffer_indices, n_pkts);

  ASSERT (n_left_to_next >= n_pkts);
  to_next += n_pkts;
  n_left_to_next -= n_pkts;

  if (PREDICT_TRUE (next_index == VNET_DEV_ETH_RX_PORT_NEXT_ETH_INPUT))
    {
      vlib_next_frame_t *nf;
      vlib_frame_t *f;
      ethernet_input_frame_t *ef;
      u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
      nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
      f = vlib_get_frame (vm, nf->frame);
      f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

      ef = vlib_frame_scalar_args (f);
      ef->sw_if_index = sw_if_index;
      ef->hw_if_index = hw_if_index;

      f->flags |= all_desc_or.qw1.v4_sum_ng ? 0 : ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
      vlib_frame_no_append (f);
    }

  vlib_put_next_frame (vm, node, next_index, n_left_to_next);

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters +
				     VNET_INTERFACE_COUNTER_RX,
				   vm->thread_index, sw_if_index, n_pkts, n_rx_bytes);

  aq->stats_rx_packets += n_pkts;
  aq->stats_rx_bytes += n_rx_bytes;

  return n_pkts;
}

VNET_DEV_NODE_FN (atl_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;

  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      n_rx += atl_rx_one_queue (vm, node, rxq);
      if (rxq->port->dev->va_dma)
	atl_rxq_refill (vm, rxq, 1);
      else
	atl_rxq_refill (vm, rxq, 0);
    }

  return n_rx;
}
