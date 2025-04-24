/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vnet/dev/dev.h>
#include <vnet/ethernet/ethernet.h>
#include <dev_iavf/iavf.h>

#define IAVF_RX_REFILL_TRESHOLD 32

static const iavf_rx_desc_qw1_t mask_eop = { .eop = 1 };
static const iavf_rx_desc_qw1_t mask_flm = { .flm = 1 };
static const iavf_rx_desc_qw1_t mask_dd = { .dd = 1 };
static const iavf_rx_desc_qw1_t mask_ipe = { .ipe = 1 };
static const iavf_rx_desc_qw1_t mask_dd_eop = { .dd = 1, .eop = 1 };

static_always_inline int
iavf_rxd_is_not_eop (iavf_rx_desc_t *d)
{
  return (d->qw1.as_u64 & mask_eop.as_u64) == 0;
}

static_always_inline int
iavf_rxd_is_not_dd (iavf_rx_desc_t *d)
{
  return (d->qw1.as_u64 & mask_dd.as_u64) == 0;
}

static_always_inline void
iavf_rx_desc_write (iavf_rx_desc_t *d, u64 addr)
{
#ifdef CLIB_HAVE_VEC256
  *(u64x4 *) d = (u64x4){ addr, 0, 0, 0 };
#else
  d->qword[0] = addr;
  d->qword[1] = 0;
#endif
}

static_always_inline void
iavf_rxq_refill (vlib_main_t *vm, vlib_node_runtime_t *node,
		 vnet_dev_rx_queue_t *rxq, int use_va_dma)
{
  u16 n_refill, mask, n_alloc, slot, size;
  iavf_rxq_t *arq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_t *b[8];
  iavf_rx_desc_t *d, *first_d;
  void *p[8];

  size = rxq->size;
  mask = size - 1;
  n_refill = mask - arq->n_enqueued;
  if (PREDICT_TRUE (n_refill <= IAVF_RX_REFILL_TRESHOLD))
    return;

  slot = (arq->next - n_refill - 1) & mask;

  n_refill &= ~7; /* round to 8 */
  n_alloc = vlib_buffer_alloc_to_ring_from_pool (
    vm, arq->buffer_indices, slot, size, n_refill,
    vnet_dev_get_rx_queue_buffer_pool_index (rxq));

  if (PREDICT_FALSE (n_alloc != n_refill))
    {
      vlib_error_count (vm, node->node_index, IAVF_RX_NODE_CTR_BUFFER_ALLOC,
			1);
      if (n_alloc)
	vlib_buffer_free_from_ring (vm, arq->buffer_indices, slot, size,
				    n_alloc);
      return;
    }

  arq->n_enqueued += n_alloc;
  first_d = arq->descs;

  ASSERT (slot % 8 == 0);

  while (n_alloc >= 8)
    {
      d = first_d + slot;

      if (use_va_dma)
	{
	  vlib_get_buffers_with_offset (vm, arq->buffer_indices + slot, p, 8,
					sizeof (vlib_buffer_t));
	  iavf_rx_desc_write (d + 0, pointer_to_uword (p[0]));
	  iavf_rx_desc_write (d + 1, pointer_to_uword (p[1]));
	  iavf_rx_desc_write (d + 2, pointer_to_uword (p[2]));
	  iavf_rx_desc_write (d + 3, pointer_to_uword (p[3]));
	  iavf_rx_desc_write (d + 4, pointer_to_uword (p[4]));
	  iavf_rx_desc_write (d + 5, pointer_to_uword (p[5]));
	  iavf_rx_desc_write (d + 6, pointer_to_uword (p[6]));
	  iavf_rx_desc_write (d + 7, pointer_to_uword (p[7]));
	}
      else
	{
	  vlib_get_buffers (vm, arq->buffer_indices + slot, b, 8);
	  iavf_rx_desc_write (d + 0, vlib_buffer_get_pa (vm, b[0]));
	  iavf_rx_desc_write (d + 1, vlib_buffer_get_pa (vm, b[1]));
	  iavf_rx_desc_write (d + 2, vlib_buffer_get_pa (vm, b[2]));
	  iavf_rx_desc_write (d + 3, vlib_buffer_get_pa (vm, b[3]));
	  iavf_rx_desc_write (d + 4, vlib_buffer_get_pa (vm, b[4]));
	  iavf_rx_desc_write (d + 5, vlib_buffer_get_pa (vm, b[5]));
	  iavf_rx_desc_write (d + 6, vlib_buffer_get_pa (vm, b[6]));
	  iavf_rx_desc_write (d + 7, vlib_buffer_get_pa (vm, b[7]));
	}

      /* next */
      slot = (slot + 8) & mask;
      n_alloc -= 8;
    }

  /* RXQ can be smaller than 256 packets, especially if jumbo. */
  arq->descs[slot].qword[1] = 0;

  __atomic_store_n (arq->qrx_tail, slot, __ATOMIC_RELEASE);
}

static_always_inline uword
iavf_rx_attach_tail (vlib_main_t *vm, vlib_buffer_template_t *bt,
		     vlib_buffer_t *b, u64 qw1, iavf_rx_tail_t *t)
{
  vlib_buffer_t *hb = b;
  u32 tlnifb = 0, i = 0;

  if (qw1 & mask_eop.as_u64)
    return 0;

  while ((qw1 & mask_eop.as_u64) == 0)
    {
      ASSERT (i < IAVF_RX_MAX_DESC_IN_CHAIN - 1);
      ASSERT (qw1 & mask_dd.as_u64);
      qw1 = t->qw1s[i];
      b->next_buffer = t->buffers[i];
      b->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b = vlib_get_buffer (vm, b->next_buffer);
      b->template = *bt;
      tlnifb += b->current_length = ((iavf_rx_desc_qw1_t) qw1).length;
      i++;
    }

  hb->total_length_not_including_first_buffer = tlnifb;
  hb->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  return tlnifb;
}

static_always_inline void
iavf_process_flow_offload (vnet_dev_port_t *port, iavf_rt_data_t *rtd,
			   uword n_rx_packets)
{
  uword n;
  iavf_flow_lookup_entry_t fle;
  iavf_port_t *ap = vnet_dev_get_port_data (port);

  for (n = 0; n < n_rx_packets; n++)
    {
      if ((rtd->qw1s[n] & mask_flm.as_u64) == 0)
	continue;

      fle = *pool_elt_at_index (ap->flow_lookup_entries, rtd->flow_ids[n]);

      if (fle.next_index != (u16) ~0)
	{
	  ASSERT (fle.next_index == (u16) ~0);
	  rtd->next[n] = fle.next_index;
	}

      if (fle.flow_id != ~0)
	rtd->bufs[n]->flow_id = fle.flow_id;

      if (fle.buffer_advance != ~0)
	vlib_buffer_advance (rtd->bufs[n], fle.buffer_advance);
    }
}

static_always_inline uword
iavf_process_rx_burst (vlib_main_t *vm, vlib_node_runtime_t *node,
		       vnet_dev_rx_queue_t *rxq, iavf_rt_data_t *rtd,
		       vlib_buffer_template_t *bt, u32 n_left,
		       int maybe_multiseg)
{
  vlib_buffer_t **b = rtd->bufs;
  u64 *qw1 = rtd->qw1s;
  iavf_rx_tail_t *tail = rtd->tails;
  uword n_rx_bytes = 0;

  while (n_left >= 4)
    {
      if (n_left >= 12)
	{
	  vlib_prefetch_buffer_header (b[8], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[11], LOAD);
	}

      b[0]->template = *bt;
      b[1]->template = *bt;
      b[2]->template = *bt;
      b[3]->template = *bt;

      n_rx_bytes += b[0]->current_length =
	((iavf_rx_desc_qw1_t) qw1[0]).length;
      n_rx_bytes += b[1]->current_length =
	((iavf_rx_desc_qw1_t) qw1[1]).length;
      n_rx_bytes += b[2]->current_length =
	((iavf_rx_desc_qw1_t) qw1[2]).length;
      n_rx_bytes += b[3]->current_length =
	((iavf_rx_desc_qw1_t) qw1[3]).length;

      if (maybe_multiseg)
	{
	  n_rx_bytes += iavf_rx_attach_tail (vm, bt, b[0], qw1[0], tail + 0);
	  n_rx_bytes += iavf_rx_attach_tail (vm, bt, b[1], qw1[1], tail + 1);
	  n_rx_bytes += iavf_rx_attach_tail (vm, bt, b[2], qw1[2], tail + 2);
	  n_rx_bytes += iavf_rx_attach_tail (vm, bt, b[3], qw1[3], tail + 3);
	}

      /* next */
      qw1 += 4;
      tail += 4;
      b += 4;
      n_left -= 4;
    }

  while (n_left)
    {
      b[0]->template = *bt;

      n_rx_bytes += b[0]->current_length =
	((iavf_rx_desc_qw1_t) qw1[0]).length;

      if (maybe_multiseg)
	n_rx_bytes += iavf_rx_attach_tail (vm, bt, b[0], qw1[0], tail + 0);

      /* next */
      qw1 += 1;
      tail += 1;
      b += 1;
      n_left -= 1;
    }
  return n_rx_bytes;
}

static_always_inline uword
iavf_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame, vnet_dev_port_t *port,
			  vnet_dev_rx_queue_t *rxq, int with_flows)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 thr_idx = vlib_get_thread_index ();
  iavf_rt_data_t *rtd = vnet_dev_get_rt_temp_space (vm);
  iavf_rxq_t *arq = vnet_dev_get_rx_queue_data (rxq);
  vlib_buffer_template_t bt = vnet_dev_get_rx_queue_if_buffer_template (rxq);
  u32 n_trace, n_rx_packets = 0, n_rx_bytes = 0;
  u16 n_tail_desc = 0;
  u64 or_qw1 = 0;
  u32 *bi, *to_next, n_left_to_next;
  u32 next_index = vnet_dev_get_rx_queue_if_next_index (rxq);
  u32 sw_if_index = vnet_dev_get_rx_queue_if_sw_if_index (rxq);
  u32 hw_if_index = vnet_dev_get_rx_queue_if_hw_if_index (rxq);
  u16 next = arq->next;
  u16 size = rxq->size;
  u16 mask = size - 1;
  iavf_rx_desc_t *d, *descs = arq->descs;
#ifdef CLIB_HAVE_VEC256
  u64x4 q1x4, or_q1x4 = { 0 };
  u32x4 fdidx4;
  u64x4 dd_eop_mask4 = u64x4_splat (mask_dd_eop.as_u64);
#elif defined(CLIB_HAVE_VEC128)
  u32x4 q1x4_lo, q1x4_hi, or_q1x4 = { 0 };
  u32x4 fdidx4;
  u32x4 dd_eop_mask4 = u32x4_splat (mask_dd_eop.as_u64);
#endif
  int single_next = 1;

  /* is there anything on the ring */
  d = descs + next;
  if ((d->qword[1] & mask_dd.as_u64) == 0)
    goto done;

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  /* fetch up to IAVF_RX_VECTOR_SZ from the rx ring, unflatten them and
     copy needed data from descriptor to rx vector */
  bi = to_next;

  while (n_rx_packets < IAVF_RX_VECTOR_SZ)
    {
      if (next + 11 < size)
	{
	  int stride = 8;
	  clib_prefetch_load ((void *) (descs + (next + stride)));
	  clib_prefetch_load ((void *) (descs + (next + stride + 1)));
	  clib_prefetch_load ((void *) (descs + (next + stride + 2)));
	  clib_prefetch_load ((void *) (descs + (next + stride + 3)));
	}

#ifdef CLIB_HAVE_VEC256
      if (n_rx_packets >= IAVF_RX_VECTOR_SZ - 4 || next >= size - 4)
	goto one_by_one;

      q1x4 = u64x4_gather ((void *) &d[0].qword[1], (void *) &d[1].qword[1],
			   (void *) &d[2].qword[1], (void *) &d[3].qword[1]);

      /* not all packets are ready or at least one of them is chained */
      if (!u64x4_is_equal (q1x4 & dd_eop_mask4, dd_eop_mask4))
	goto one_by_one;

      or_q1x4 |= q1x4;

      u64x4_store_unaligned (q1x4, rtd->qw1s + n_rx_packets);
#elif defined(CLIB_HAVE_VEC128)
      if (n_rx_packets >= IAVF_RX_VECTOR_SZ - 4 || next >= size - 4)
	goto one_by_one;

      q1x4_lo =
	u32x4_gather ((void *) &d[0].qword[1], (void *) &d[1].qword[1],
		      (void *) &d[2].qword[1], (void *) &d[3].qword[1]);

      /* not all packets are ready or at least one of them is chained */
      if (!u32x4_is_equal (q1x4_lo & dd_eop_mask4, dd_eop_mask4))
	goto one_by_one;

      q1x4_hi = u32x4_gather (
	(void *) &d[0].qword[1] + 4, (void *) &d[1].qword[1] + 4,
	(void *) &d[2].qword[1] + 4, (void *) &d[3].qword[1] + 4);

      or_q1x4 |= q1x4_lo;
      rtd->qw1s[n_rx_packets + 0] = (u64) q1x4_hi[0] << 32 | (u64) q1x4_lo[0];
      rtd->qw1s[n_rx_packets + 1] = (u64) q1x4_hi[1] << 32 | (u64) q1x4_lo[1];
      rtd->qw1s[n_rx_packets + 2] = (u64) q1x4_hi[2] << 32 | (u64) q1x4_lo[2];
      rtd->qw1s[n_rx_packets + 3] = (u64) q1x4_hi[3] << 32 | (u64) q1x4_lo[3];
#endif
#if defined(CLIB_HAVE_VEC256) || defined(CLIB_HAVE_VEC128)

      if (with_flows)
	{
	  fdidx4 = u32x4_gather (
	    (void *) &d[0].fdid_flex_hi, (void *) &d[1].fdid_flex_hi,
	    (void *) &d[2].fdid_flex_hi, (void *) &d[3].fdid_flex_hi);
	  u32x4_store_unaligned (fdidx4, rtd->flow_ids + n_rx_packets);
	}

      vlib_buffer_copy_indices (bi, arq->buffer_indices + next, 4);

      /* next */
      next = (next + 4) & mask;
      d = descs + next;
      n_rx_packets += 4;
      bi += 4;
      continue;
    one_by_one:
#endif
      clib_prefetch_load ((void *) (descs + ((next + 8) & mask)));

      if (iavf_rxd_is_not_dd (d))
	break;

      bi[0] = arq->buffer_indices[next];

      /* deal with chained buffers */
      if (PREDICT_FALSE (iavf_rxd_is_not_eop (d)))
	{
	  u16 tail_desc = 0;
	  u16 tail_next = next;
	  iavf_rx_tail_t *tail = rtd->tails + n_rx_packets;
	  iavf_rx_desc_t *td;
	  do
	    {
	      tail_next = (tail_next + 1) & mask;
	      td = descs + tail_next;

	      /* bail out in case of incomplete transaction */
	      if (iavf_rxd_is_not_dd (td))
		goto no_more_desc;

	      or_qw1 |= tail->qw1s[tail_desc] = td[0].qword[1];
	      tail->buffers[tail_desc] = arq->buffer_indices[tail_next];
	      tail_desc++;
	    }
	  while (iavf_rxd_is_not_eop (td));
	  next = tail_next;
	  n_tail_desc += tail_desc;
	}

      or_qw1 |= rtd->qw1s[n_rx_packets] = d[0].qword[1];
      if (PREDICT_FALSE (with_flows))
	{
	  rtd->flow_ids[n_rx_packets] = d[0].fdid_flex_hi;
	}

      /* next */
      next = (next + 1) & mask;
      d = descs + next;
      n_rx_packets++;
      bi++;
    }
no_more_desc:

  if (n_rx_packets == 0)
    goto done;

  arq->next = next;
  arq->n_enqueued -= n_rx_packets + n_tail_desc;

#if defined(CLIB_HAVE_VEC256) || defined(CLIB_HAVE_VEC128)
  or_qw1 |= or_q1x4[0] | or_q1x4[1] | or_q1x4[2] | or_q1x4[3];
#endif

  vlib_get_buffers (vm, to_next, rtd->bufs, n_rx_packets);

  n_rx_bytes =
    n_tail_desc ?
	    iavf_process_rx_burst (vm, node, rxq, rtd, &bt, n_rx_packets, 1) :
	    iavf_process_rx_burst (vm, node, rxq, rtd, &bt, n_rx_packets, 0);

  /* the MARKed packets may have different next nodes */
  if (PREDICT_FALSE (with_flows && (or_qw1 & mask_flm.as_u64)))
    {
      u32 n;
      single_next = 0;
      for (n = 0; n < n_rx_packets; n++)
	rtd->next[n] = next_index;

      iavf_process_flow_offload (port, rtd, n_rx_packets);
    }

  /* packet trace if enabled */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      u32 n_left = n_rx_packets;
      u32 i, j;
      u16 *next_indices = rtd->next;

      i = 0;
      while (n_trace && n_left)
	{
	  vlib_buffer_t *b = rtd->bufs[i];
	  if (PREDICT_FALSE (single_next == 0))
	    next_index = next_indices[0];

	  if (PREDICT_TRUE (vlib_trace_buffer (vm, node, next_index, b,
					       /* follow_chain */ 0)))
	    {
	      iavf_rx_trace_t *tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->next_index = next_index;
	      tr->qid = rxq->queue_id;
	      tr->hw_if_index = hw_if_index;
	      tr->qw1s[0] = rtd->qw1s[i];
	      tr->flow_id =
		(tr->qw1s[0] & mask_flm.as_u64) ? rtd->flow_ids[i] : 0;
	      for (j = 1; j < IAVF_RX_MAX_DESC_IN_CHAIN; j++)
		tr->qw1s[j] = rtd->tails[i].qw1s[j - 1];

	      n_trace--;
	    }

	  /* next */
	  n_left--;
	  i++;
	  next_indices++;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  /* enqueu the packets to the next nodes */
  if (PREDICT_FALSE (with_flows && (or_qw1 & mask_flm.as_u64)))
    {
      /* release next node's frame vector, in this case we use
	 vlib_buffer_enqueue_to_next to place the packets
       */
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

      /* enqueue buffers to the next node */
      vlib_buffer_enqueue_to_next (vm, node, to_next, rtd->next, n_rx_packets);
    }
  else
    {
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

	  if ((or_qw1 & mask_ipe.as_u64) == 0)
	    f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
	  vlib_frame_no_append (f);
	}

      n_left_to_next -= n_rx_packets;
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    thr_idx, hw_if_index, n_rx_packets, n_rx_bytes);

done:
  return n_rx_packets;
}

VNET_DEV_NODE_FN (iavf_rx_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  foreach_vnet_dev_rx_queue_runtime (rxq, node)
    {
      vnet_dev_port_t *port = rxq->port;
      iavf_port_t *ap = vnet_dev_get_port_data (port);
      if (PREDICT_FALSE (ap->flow_offload))
	n_rx += iavf_device_input_inline (vm, node, frame, port, rxq, 1);
      else
	n_rx += iavf_device_input_inline (vm, node, frame, port, rxq, 0);

      /* refill rx ring */
      if (rxq->port->dev->va_dma)
	iavf_rxq_refill (vm, node, rxq, 1 /* use_va_dma */);
      else
	iavf_rxq_refill (vm, node, rxq, 0 /* use_va_dma */);
    }

  return n_rx;
}
