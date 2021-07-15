/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/pci/pci.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/rx_queue_funcs.h>

#include <avf/avf.h>

#define foreach_avf_input_error \
  _(BUFFER_ALLOC, "buffer alloc error")

typedef enum
{
#define _(f,s) AVF_INPUT_ERROR_##f,
  foreach_avf_input_error
#undef _
    AVF_INPUT_N_ERROR,
} avf_input_error_t;

static __clib_unused char *avf_input_error_strings[] = {
#define _(n,s) s,
  foreach_avf_input_error
#undef _
};

#define AVF_INPUT_REFILL_TRESHOLD 32

static_always_inline void
avf_rx_desc_write (avf_rx_desc_t * d, u64 addr)
{
#ifdef CLIB_HAVE_VEC256
  u64x4 v = { addr, 0, 0, 0 };
  u64x4_store_unaligned (v, (void *) d);
#else
  d->qword[0] = addr;
  d->qword[1] = 0;
#endif
}

static_always_inline void
avf_rxq_refill (vlib_main_t * vm, vlib_node_runtime_t * node, avf_rxq_t * rxq,
		int use_va_dma)
{
  u16 n_refill, mask, n_alloc, slot, size;
  vlib_buffer_t *b[8];
  avf_rx_desc_t *d, *first_d;
  void *p[8];

  size = rxq->size;
  mask = size - 1;
  n_refill = mask - rxq->n_enqueued;
  if (PREDICT_TRUE (n_refill <= AVF_INPUT_REFILL_TRESHOLD))
    return;

  slot = (rxq->next - n_refill - 1) & mask;

  n_refill &= ~7;		/* round to 8 */
  n_alloc =
    vlib_buffer_alloc_to_ring_from_pool (vm, rxq->bufs, slot, size, n_refill,
					 rxq->buffer_pool_index);

  if (PREDICT_FALSE (n_alloc != n_refill))
    {
      vlib_error_count (vm, node->node_index,
			AVF_INPUT_ERROR_BUFFER_ALLOC, 1);
      if (n_alloc)
	vlib_buffer_free_from_ring (vm, rxq->bufs, slot, size, n_alloc);
      return;
    }

  rxq->n_enqueued += n_alloc;
  first_d = rxq->descs;

  ASSERT (slot % 8 == 0);

  while (n_alloc >= 8)
    {
      d = first_d + slot;

      if (use_va_dma)
	{
	  vlib_get_buffers_with_offset (vm, rxq->bufs + slot, p, 8,
					sizeof (vlib_buffer_t));
	  avf_rx_desc_write (d + 0, pointer_to_uword (p[0]));
	  avf_rx_desc_write (d + 1, pointer_to_uword (p[1]));
	  avf_rx_desc_write (d + 2, pointer_to_uword (p[2]));
	  avf_rx_desc_write (d + 3, pointer_to_uword (p[3]));
	  avf_rx_desc_write (d + 4, pointer_to_uword (p[4]));
	  avf_rx_desc_write (d + 5, pointer_to_uword (p[5]));
	  avf_rx_desc_write (d + 6, pointer_to_uword (p[6]));
	  avf_rx_desc_write (d + 7, pointer_to_uword (p[7]));
	}
      else
	{
	  vlib_get_buffers (vm, rxq->bufs + slot, b, 8);
	  avf_rx_desc_write (d + 0, vlib_buffer_get_pa (vm, b[0]));
	  avf_rx_desc_write (d + 1, vlib_buffer_get_pa (vm, b[1]));
	  avf_rx_desc_write (d + 2, vlib_buffer_get_pa (vm, b[2]));
	  avf_rx_desc_write (d + 3, vlib_buffer_get_pa (vm, b[3]));
	  avf_rx_desc_write (d + 4, vlib_buffer_get_pa (vm, b[4]));
	  avf_rx_desc_write (d + 5, vlib_buffer_get_pa (vm, b[5]));
	  avf_rx_desc_write (d + 6, vlib_buffer_get_pa (vm, b[6]));
	  avf_rx_desc_write (d + 7, vlib_buffer_get_pa (vm, b[7]));
	}

      /* next */
      slot = (slot + 8) & mask;
      n_alloc -= 8;
    }

  avf_tail_write (rxq->qrx_tail, slot);
}


static_always_inline uword
avf_rx_attach_tail (vlib_main_t * vm, vlib_buffer_t * bt, vlib_buffer_t * b,
		    u64 qw1, avf_rx_tail_t * t)
{
  vlib_buffer_t *hb = b;
  u32 tlnifb = 0, i = 0;

  if (qw1 & AVF_RXD_STATUS_EOP)
    return 0;

  while ((qw1 & AVF_RXD_STATUS_EOP) == 0)
    {
      ASSERT (i < AVF_RX_MAX_DESC_IN_CHAIN - 1);
      ASSERT (qw1 & AVF_RXD_STATUS_DD);
      qw1 = t->qw1s[i];
      b->next_buffer = t->buffers[i];
      b->flags |= VLIB_BUFFER_NEXT_PRESENT;
      b = vlib_get_buffer (vm, b->next_buffer);
      vlib_buffer_copy_template (b, bt);
      tlnifb += b->current_length = qw1 >> AVF_RXD_LEN_SHIFT;
      i++;
    }

  hb->total_length_not_including_first_buffer = tlnifb;
  hb->flags |= VLIB_BUFFER_TOTAL_LENGTH_VALID;
  return tlnifb;
}

static_always_inline void
avf_process_flow_offload (avf_device_t *ad, avf_per_thread_data_t *ptd,
			  uword n_rx_packets)
{
  uword n;
  avf_flow_lookup_entry_t *fle;

  for (n = 0; n < n_rx_packets; n++)
    {
      if ((ptd->qw1s[n] & AVF_RXD_STATUS_FLM) == 0)
	continue;

      fle = pool_elt_at_index (ad->flow_lookup_entries, ptd->flow_ids[n]);

      if (fle->next_index != (u16) ~0)
	{
	  ptd->next[n] = fle->next_index;
	}

      if (fle->flow_id != ~0)
	{
	  ptd->bufs[n]->flow_id = fle->flow_id;
	}

      if (fle->buffer_advance != ~0)
	{
	  vlib_buffer_advance (ptd->bufs[n], fle->buffer_advance);
	}
    }
}

static_always_inline uword
avf_process_rx_burst (vlib_main_t * vm, vlib_node_runtime_t * node,
		      avf_per_thread_data_t * ptd, u32 n_left,
		      int maybe_multiseg)
{
  vlib_buffer_t bt;
  vlib_buffer_t **b = ptd->bufs;
  u64 *qw1 = ptd->qw1s;
  avf_rx_tail_t *tail = ptd->tails;
  uword n_rx_bytes = 0;

  /* copy template into local variable - will save per packet load */
  vlib_buffer_copy_template (&bt, &ptd->buffer_template);

  while (n_left >= 4)
    {
      if (n_left >= 12)
	{
	  vlib_prefetch_buffer_header (b[8], LOAD);
	  vlib_prefetch_buffer_header (b[9], LOAD);
	  vlib_prefetch_buffer_header (b[10], LOAD);
	  vlib_prefetch_buffer_header (b[11], LOAD);
	}

      vlib_buffer_copy_template (b[0], &bt);
      vlib_buffer_copy_template (b[1], &bt);
      vlib_buffer_copy_template (b[2], &bt);
      vlib_buffer_copy_template (b[3], &bt);

      n_rx_bytes += b[0]->current_length = qw1[0] >> AVF_RXD_LEN_SHIFT;
      n_rx_bytes += b[1]->current_length = qw1[1] >> AVF_RXD_LEN_SHIFT;
      n_rx_bytes += b[2]->current_length = qw1[2] >> AVF_RXD_LEN_SHIFT;
      n_rx_bytes += b[3]->current_length = qw1[3] >> AVF_RXD_LEN_SHIFT;

      if (maybe_multiseg)
	{
	  n_rx_bytes += avf_rx_attach_tail (vm, &bt, b[0], qw1[0], tail + 0);
	  n_rx_bytes += avf_rx_attach_tail (vm, &bt, b[1], qw1[1], tail + 1);
	  n_rx_bytes += avf_rx_attach_tail (vm, &bt, b[2], qw1[2], tail + 2);
	  n_rx_bytes += avf_rx_attach_tail (vm, &bt, b[3], qw1[3], tail + 3);
	}

      /* next */
      qw1 += 4;
      tail += 4;
      b += 4;
      n_left -= 4;
    }

  while (n_left)
    {
      vlib_buffer_copy_template (b[0], &bt);

      n_rx_bytes += b[0]->current_length = qw1[0] >> AVF_RXD_LEN_SHIFT;

      if (maybe_multiseg)
	n_rx_bytes += avf_rx_attach_tail (vm, &bt, b[0], qw1[0], tail + 0);

      /* next */
      qw1 += 1;
      tail += 1;
      b += 1;
      n_left -= 1;
    }
  return n_rx_bytes;
}

static_always_inline uword
avf_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, avf_device_t *ad, u16 qid,
			 int with_flows)
{
  avf_main_t *am = &avf_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 thr_idx = vlib_get_thread_index ();
  avf_per_thread_data_t *ptd =
    vec_elt_at_index (am->per_thread_data, thr_idx);
  avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);
  u32 n_trace, n_rx_packets = 0, n_rx_bytes = 0;
  u16 n_tail_desc = 0;
  u64 or_qw1 = 0;
  u32 *bi, *to_next, n_left_to_next;
  vlib_buffer_t *bt = &ptd->buffer_template;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u16 next = rxq->next;
  u16 size = rxq->size;
  u16 mask = size - 1;
  avf_rx_desc_t *d, *fd = rxq->descs;
#ifdef CLIB_HAVE_VEC256
  u64x4 q1x4, or_q1x4 = { 0 };
  u32x4 fdidx4;
  u64x4 dd_eop_mask4 = u64x4_splat (AVF_RXD_STATUS_DD | AVF_RXD_STATUS_EOP);
#elif defined(CLIB_HAVE_VEC128)
  u32x4 q1x4_lo, q1x4_hi, or_q1x4 = { 0 };
  u32x4 fdidx4;
  u32x4 dd_eop_mask4 = u32x4_splat (AVF_RXD_STATUS_DD | AVF_RXD_STATUS_EOP);
#endif
  int single_next = 1;

  /* is there anything on the ring */
  d = fd + next;
  if ((d->qword[1] & AVF_RXD_STATUS_DD) == 0)
    goto done;

  if (PREDICT_FALSE (ad->per_interface_next_index != ~0))
    next_index = ad->per_interface_next_index;

  if (PREDICT_FALSE (vnet_device_input_have_features (ad->sw_if_index)))
    vnet_feature_start_device_input_x1 (ad->sw_if_index, &next_index, bt);

  vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

  /* fetch up to AVF_RX_VECTOR_SZ from the rx ring, unflatten them and
     copy needed data from descriptor to rx vector */
  bi = to_next;

  while (n_rx_packets < AVF_RX_VECTOR_SZ)
    {
      if (next + 11 < size)
	{
	  int stride = 8;
	  clib_prefetch_load ((void *) (fd + (next + stride)));
	  clib_prefetch_load ((void *) (fd + (next + stride + 1)));
	  clib_prefetch_load ((void *) (fd + (next + stride + 2)));
	  clib_prefetch_load ((void *) (fd + (next + stride + 3)));
	}

#ifdef CLIB_HAVE_VEC256
      if (n_rx_packets >= AVF_RX_VECTOR_SZ - 4 || next >= size - 4)
	goto one_by_one;

      q1x4 = u64x4_gather ((void *) &d[0].qword[1], (void *) &d[1].qword[1],
			   (void *) &d[2].qword[1], (void *) &d[3].qword[1]);

      /* not all packets are ready or at least one of them is chained */
      if (!u64x4_is_equal (q1x4 & dd_eop_mask4, dd_eop_mask4))
	goto one_by_one;

      or_q1x4 |= q1x4;

      u64x4_store_unaligned (q1x4, ptd->qw1s + n_rx_packets);
#elif defined(CLIB_HAVE_VEC128)
      if (n_rx_packets >= AVF_RX_VECTOR_SZ - 4 || next >= size - 4)
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
      ptd->qw1s[n_rx_packets + 0] = (u64) q1x4_hi[0] << 32 | (u64) q1x4_lo[0];
      ptd->qw1s[n_rx_packets + 1] = (u64) q1x4_hi[1] << 32 | (u64) q1x4_lo[1];
      ptd->qw1s[n_rx_packets + 2] = (u64) q1x4_hi[2] << 32 | (u64) q1x4_lo[2];
      ptd->qw1s[n_rx_packets + 3] = (u64) q1x4_hi[3] << 32 | (u64) q1x4_lo[3];
#endif
#if defined(CLIB_HAVE_VEC256) || defined(CLIB_HAVE_VEC128)

      if (with_flows)
	{
	  fdidx4 = u32x4_gather (
	    (void *) &d[0].fdid_flex_hi, (void *) &d[1].fdid_flex_hi,
	    (void *) &d[2].fdid_flex_hi, (void *) &d[3].fdid_flex_hi);
	  u32x4_store_unaligned (fdidx4, ptd->flow_ids + n_rx_packets);
	}

      vlib_buffer_copy_indices (bi, rxq->bufs + next, 4);

      /* next */
      next = (next + 4) & mask;
      d = fd + next;
      n_rx_packets += 4;
      bi += 4;
      continue;
    one_by_one:
#endif
      clib_prefetch_load ((void *) (fd + ((next + 8) & mask)));

      if (avf_rxd_is_not_dd (d))
	break;

      bi[0] = rxq->bufs[next];

      /* deal with chained buffers */
      if (PREDICT_FALSE (avf_rxd_is_not_eop (d)))
	{
	  u16 tail_desc = 0;
	  u16 tail_next = next;
	  avf_rx_tail_t *tail = ptd->tails + n_rx_packets;
	  avf_rx_desc_t *td;
	  do
	    {
	      tail_next = (tail_next + 1) & mask;
	      td = fd + tail_next;

	      /* bail out in case of incomplete transaction */
	      if (avf_rxd_is_not_dd (td))
		goto no_more_desc;

	      or_qw1 |= tail->qw1s[tail_desc] = td[0].qword[1];
	      tail->buffers[tail_desc] = rxq->bufs[tail_next];
	      tail_desc++;
	    }
	  while (avf_rxd_is_not_eop (td));
	  next = tail_next;
	  n_tail_desc += tail_desc;
	}

      or_qw1 |= ptd->qw1s[n_rx_packets] = d[0].qword[1];
      if (PREDICT_FALSE (with_flows))
	{
	  ptd->flow_ids[n_rx_packets] = d[0].fdid_flex_hi;
	}

      /* next */
      next = (next + 1) & mask;
      d = fd + next;
      n_rx_packets++;
      bi++;
    }
no_more_desc:

  if (n_rx_packets == 0)
    goto done;

  rxq->next = next;
  rxq->n_enqueued -= n_rx_packets + n_tail_desc;

  /* avoid eating our own tail */
  rxq->descs[(next + rxq->n_enqueued) & mask].qword[1] = 0;

#if defined(CLIB_HAVE_VEC256) || defined(CLIB_HAVE_VEC128)
  or_qw1 |= or_q1x4[0] | or_q1x4[1] | or_q1x4[2] | or_q1x4[3];
#endif

  vlib_get_buffers (vm, to_next, ptd->bufs, n_rx_packets);

  vnet_buffer (bt)->sw_if_index[VLIB_RX] = ad->sw_if_index;
  vnet_buffer (bt)->sw_if_index[VLIB_TX] = ~0;
  bt->buffer_pool_index = rxq->buffer_pool_index;
  bt->ref_count = 1;

  if (n_tail_desc)
    n_rx_bytes = avf_process_rx_burst (vm, node, ptd, n_rx_packets, 1);
  else
    n_rx_bytes = avf_process_rx_burst (vm, node, ptd, n_rx_packets, 0);

  /* the MARKed packets may have different next nodes */
  if (PREDICT_FALSE (with_flows && (or_qw1 & AVF_RXD_STATUS_FLM)))
    {
      u32 n;
      single_next = 0;
      for (n = 0; n < n_rx_packets; n++)
	ptd->next[n] = next_index;

      avf_process_flow_offload (ad, ptd, n_rx_packets);
    }

  /* packet trace if enabled */
  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      u32 n_left = n_rx_packets;
      u32 i, j;
      u16 *next_indices = ptd->next;

      i = 0;
      while (n_trace && n_left)
	{
	  vlib_buffer_t *b = ptd->bufs[i];
	  if (PREDICT_FALSE (single_next == 0))
	    next_index = next_indices[0];

	  if (PREDICT_TRUE
	      (vlib_trace_buffer
	       (vm, node, next_index, b, /* follow_chain */ 0)))
	    {
	      avf_input_trace_t *tr =
		vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->next_index = next_index;
	      tr->qid = qid;
	      tr->hw_if_index = ad->hw_if_index;
	      tr->qw1s[0] = ptd->qw1s[i];
	      tr->flow_id =
		(tr->qw1s[0] & AVF_RXD_STATUS_FLM) ? ptd->flow_ids[i] : 0;
	      for (j = 1; j < AVF_RX_MAX_DESC_IN_CHAIN; j++)
		tr->qw1s[j] = ptd->tails[i].qw1s[j - 1];

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
  if (PREDICT_FALSE (with_flows && (or_qw1 & AVF_RXD_STATUS_FLM)))
    {
      /* release next node's frame vector, in this case we use
	 vlib_buffer_enqueue_to_next to place the packets
       */
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

      /* enqueue buffers to the next node */
      vlib_buffer_enqueue_to_next (vm, node, to_next, ptd->next, n_rx_packets);
    }
  else
    {
      if (PREDICT_TRUE (next_index == VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT))
	{
	  vlib_next_frame_t *nf;
	  vlib_frame_t *f;
	  ethernet_input_frame_t *ef;
	  nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
	  f = vlib_get_frame (vm, nf->frame);
	  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

	  ef = vlib_frame_scalar_args (f);
	  ef->sw_if_index = ad->sw_if_index;
	  ef->hw_if_index = ad->hw_if_index;

	  if ((or_qw1 & AVF_RXD_ERROR_IPE) == 0)
	    f->flags |= ETH_INPUT_FRAME_F_IP4_CKSUM_OK;
	  vlib_frame_no_append (f);
	}

      n_left_to_next -= n_rx_packets;
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX, thr_idx,
				   ad->hw_if_index, n_rx_packets, n_rx_bytes);

done:
  /* refill rx ring */
  if (ad->flags & AVF_DEVICE_F_VA_DMA)
    avf_rxq_refill (vm, node, rxq, 1 /* use_va_dma */ );
  else
    avf_rxq_refill (vm, node, rxq, 0 /* use_va_dma */ );

  return n_rx_packets;
}

VLIB_NODE_FN (avf_input_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  u32 n_rx = 0;
  vnet_hw_if_rxq_poll_vector_t *pv;

  pv = vnet_hw_if_get_rxq_poll_vector (vm, node);

  for (int i = 0; i < vec_len (pv); i++)
    {
      avf_device_t *ad = avf_get_device (pv[i].dev_instance);
      if ((ad->flags & AVF_DEVICE_F_ADMIN_UP) == 0)
	continue;
      if (PREDICT_FALSE (ad->flags & AVF_DEVICE_F_RX_FLOW_OFFLOAD))
	n_rx +=
	  avf_device_input_inline (vm, node, frame, ad, pv[i].queue_id, 1);
      else
	n_rx +=
	  avf_device_input_inline (vm, node, frame, ad, pv[i].queue_id, 0);
    }

  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (avf_input_node) = {
  .name = "avf-input",
  .sibling_of = "device-input",
  .format_trace = format_avf_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = AVF_INPUT_N_ERROR,
  .error_strings = avf_input_error_strings,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
