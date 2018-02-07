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
#include <vnet/devices/devices.h>

#include <avf/avf.h>

#define foreach_avf_input_error \
  _(BUFFER_ALLOC, "buffer alloc error") \
  _(RX_PACKET_ERROR, "Rx packet errors")

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

#define AVF_RX_DESC_STATUS(x)		(1 << x)
#define AVF_RX_DESC_STATUS_DD		AVF_RX_DESC_STATUS(0)
#define AVF_RX_DESC_STATUS_EOP		AVF_RX_DESC_STATUS(1)

static_always_inline void
avf_input_trace (vlib_main_t * vm, vlib_node_runtime_t * node, u32 next0,
		 vlib_buffer_t * b0, uword * n_trace, avf_device_t * ad,
		 avf_rx_vector_entry_t * rxve)
{
  avf_input_trace_t *tr;
  vlib_trace_buffer (vm, node, next0, b0, /* follow_chain */ 0);
  vlib_set_trace_count (vm, node, --(*n_trace));
  tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
  tr->next_index = next0;
  tr->hw_if_index = ad->hw_if_index;
  clib_memcpy (&tr->rxve, rxve, sizeof (avf_rx_vector_entry_t));
}

#define AVF_INPUT_REFILL_TRESHOLD 32
static_always_inline void
avf_rxq_refill (vlib_main_t * vm, vlib_node_runtime_t * node, avf_rxq_t * rxq,
		int use_iova)
{
  u16 n_refill, mask, n_alloc, slot;
  avf_rx_desc_t *d;

  n_refill = rxq->size - 1 - rxq->n_bufs;
  if (PREDICT_TRUE (n_refill <= AVF_INPUT_REFILL_TRESHOLD))
    return;

  mask = rxq->size - 1;
  slot = (rxq->next - n_refill - 1) & mask;

  n_refill &= ~7;		/* round to 8 */
  n_alloc = vlib_buffer_alloc_to_ring (vm, rxq->bufs, slot, rxq->size,
				       n_refill);

  if (PREDICT_FALSE (n_alloc != n_refill))
    {
      vlib_error_count (vm, node->node_index,
			AVF_INPUT_ERROR_BUFFER_ALLOC, 1);
      if (n_alloc)
	vlib_buffer_free (vm, rxq->bufs + slot, n_alloc);
      return;
    }

  rxq->n_bufs += n_alloc;

  while (n_alloc--)
    {
      u64 addr;
      d = ((avf_rx_desc_t *) rxq->descs) + slot;
      if (use_iova)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, rxq->bufs[slot]);
	  addr = pointer_to_uword (b->data);
	}
      else
	addr = vlib_get_buffer_data_physical_address (vm, rxq->bufs[slot]);
      d->qword[0] = addr;
      d->qword[1] = 0;
      slot = (slot + 1) & mask;
    }

  CLIB_MEMORY_BARRIER ();
  *(rxq->qrx_tail) = slot;
}

static_always_inline u32
avf_find_next (vlib_node_runtime_t * node, avf_rx_vector_entry_t * rxve,
	       vlib_buffer_t * b)
{
  avf_main_t *am = &avf_main;
  avf_ptype_t *ptype;
  if (PREDICT_FALSE (rxve->error))
    {
      b->error = node->errors[AVF_INPUT_ERROR_RX_PACKET_ERROR];
      return VNET_DEVICE_INPUT_NEXT_DROP;
    }
  ptype = am->ptypes + rxve->ptype;
  vlib_buffer_advance (b, ptype->buffer_advance);
  b->flags |= ptype->flags;
  return ptype->next_node;
}


static_always_inline uword
avf_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame, avf_device_t * ad, u16 qid)
{
  avf_main_t *am = &avf_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 thr_idx = vlib_get_thread_index ();
  avf_per_thread_data_t *ptd =
    vec_elt_at_index (am->per_thread_data, thr_idx);
  avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);
  avf_rx_vector_entry_t *rxve;
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  avf_rx_desc_t *d;
  u32 *to_next = 0;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 sw_if_idx[VLIB_N_RX_TX] = {[VLIB_RX] = ad->sw_if_index,[VLIB_TX] = ~0 };
  u16 mask = rxq->size - 1;
  u16 n_rxv = 0;

  /* fetch up to AVF_RX_VECTOR_SZ from the rx ring, unflatten them and
     copy needed data from descriptor to rx vector */
  d = rxq->descs + rxq->next;
  while ((d->qword[1] & AVF_RX_DESC_STATUS_DD) && n_rxv < AVF_RX_VECTOR_SZ)
    {
      u16 next_pf = (rxq->next + 8) & mask;
      CLIB_PREFETCH (rxq->descs + next_pf, CLIB_CACHE_LINE_BYTES, LOAD);
      rxve = ptd->rx_vector + n_rxv;
      rxve->bi = rxq->bufs[rxq->next];
      rxve->status = avf_get_u64_bits (d, 8, 18, 0);
      rxve->error = avf_get_u64_bits (d, 8, 26, 19);
      rxve->ptype = avf_get_u64_bits (d, 8, 37, 30);
      rxve->length = avf_get_u64_bits (d, 8, 63, 38);

      /* deal with chained buffers */
      while (PREDICT_FALSE ((d->qword[1] & AVF_RX_DESC_STATUS_EOP) == 0))
	{
	  clib_error ("fixme");
	}

      /* next */
      rxq->next = (rxq->next + 1) & mask;
      d = rxq->descs + rxq->next;
      n_rxv++;
      rxq->n_bufs--;
    }

  if (n_rxv == 0)
    return 0;

  /* refill rx ring */
  if (ad->flags & AVF_DEVICE_F_IOVA)
    avf_rxq_refill (vm, node, rxq, 1 /* use_iova */ );
  else
    avf_rxq_refill (vm, node, rxq, 0 /* use_iova */ );

  n_rx_packets = n_rxv;
  rxve = ptd->rx_vector;
  while (n_rxv)
    {
      u32 n_left_to_next;
      u32 bi0, bi1, bi2, bi3;
      vlib_buffer_t *b0, *b1, *b2, *b3;
      u32 next0, next1, next2, next3;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_rxv >= 12 && n_left_to_next >= 4)
	{
	  vlib_buffer_t *p;
	  p = vlib_get_buffer (vm, rxve[8].bi);
	  vlib_prefetch_buffer_header (p, LOAD);
	  //__builtin_prefetch (p->data, 0, 2);

	  p = vlib_get_buffer (vm, rxve[9].bi);
	  vlib_prefetch_buffer_header (p, LOAD);
	  //__builtin_prefetch (p->data, 0, 2);

	  p = vlib_get_buffer (vm, rxve[10].bi);
	  vlib_prefetch_buffer_header (p, LOAD);
	  //__builtin_prefetch (p->data, 0, 2);

	  p = vlib_get_buffer (vm, rxve[11].bi);
	  vlib_prefetch_buffer_header (p, LOAD);
	  //__builtin_prefetch (p->data, 0, 2);

	  to_next[0] = bi0 = rxve[0].bi;
	  to_next[1] = bi1 = rxve[1].bi;
	  to_next[2] = bi2 = rxve[2].bi;
	  to_next[3] = bi3 = rxve[3].bi;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);

	  b0->current_data = 0;
	  b1->current_data = 0;
	  b2->current_data = 0;
	  b3->current_data = 0;

	  b0->current_length = rxve[0].length;
	  b1->current_length = rxve[1].length;
	  b2->current_length = rxve[2].length;
	  b3->current_length = rxve[3].length;

	  n_rx_bytes += b0->current_length;
	  n_rx_bytes += b1->current_length;
	  n_rx_bytes += b2->current_length;
	  n_rx_bytes += b3->current_length;


	  if (PREDICT_TRUE (ad->per_interface_next_index == ~0))
	    {
	      next0 = avf_find_next (node, rxve, b0);
	      next1 = avf_find_next (node, rxve + 1, b1);
	      next2 = avf_find_next (node, rxve + 2, b2);
	      next3 = avf_find_next (node, rxve + 3, b3);
	      vnet_feature_start_device_input_x4 (ad->sw_if_index, &next0,
						  &next1, &next2, &next3, b0,
						  b1, b2, b3);
	    }
	  else
	    next0 = next1 = next2 = next3 = ad->per_interface_next_index;

	  clib_memcpy (vnet_buffer (b0)->sw_if_index, sw_if_idx,
		       sizeof (sw_if_idx));
	  clib_memcpy (vnet_buffer (b1)->sw_if_index, sw_if_idx,
		       sizeof (sw_if_idx));
	  clib_memcpy (vnet_buffer (b2)->sw_if_index, sw_if_idx,
		       sizeof (sw_if_idx));
	  clib_memcpy (vnet_buffer (b3)->sw_if_index, sw_if_idx,
		       sizeof (sw_if_idx));

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b1);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b2);
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b3);

	  if (PREDICT_FALSE (n_trace))
	    {
	      avf_input_trace (vm, node, next0, b0, &n_trace, ad, rxve);
	      if (n_trace)
		avf_input_trace (vm, node, next1, b1, &n_trace, ad, rxve + 1);
	      if (n_trace)
		avf_input_trace (vm, node, next2, b2, &n_trace, ad, rxve + 2);
	      if (n_trace)
		avf_input_trace (vm, node, next3, b3, &n_trace, ad, rxve + 3);
	    }

	  /* next */
	  to_next += 4;
	  n_left_to_next -= 4;
	  rxve += 4;
	  n_rxv -= 4;

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);
	}
      while (n_rxv && n_left_to_next)
	{
	  bi0 = rxve[0].bi;
	  to_next[0] = bi0;
	  b0 = vlib_get_buffer (vm, bi0);

	  b0->current_data = 0;
	  b0->current_length = rxve->length;
	  n_rx_bytes += b0->current_length;
	  __builtin_prefetch (b0->data, 0, 1);

	  if (PREDICT_TRUE (ad->per_interface_next_index == ~0))
	    {
	      next0 = avf_find_next (node, rxve, b0);
	      vnet_feature_start_device_input_x1 (ad->sw_if_index, &next0,
						  b0);
	    }
	  else
	    next0 = ad->per_interface_next_index;

	  clib_memcpy (vnet_buffer (b0)->sw_if_index, sw_if_idx,
		       sizeof (sw_if_idx));

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
	  if (PREDICT_FALSE (n_trace > 0))
	    avf_input_trace (vm, node, next0, b0, &n_trace, ad, rxve);

	  /* next */
	  to_next += 1;
	  n_left_to_next -= 1;
	  rxve += 1;
	  n_rxv -= 1;

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX, thr_idx,
				   ad->hw_if_index, n_rx_packets, n_rx_bytes);

  return n_rx_packets;
}

uword
CLIB_MULTIARCH_FN (avf_input) (vlib_main_t * vm, vlib_node_runtime_t * node,
			       vlib_frame_t * frame)
{
  u32 n_rx = 0;
  avf_main_t *am = &avf_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    avf_device_t *ad;
    ad = vec_elt_at_index (am->devices, dq->dev_instance);
    if ((ad->flags & AVF_DEVICE_F_INITIALIZED) == 0)
      continue;
    if ((ad->flags & AVF_DEVICE_F_ADMIN_UP) == 0)
      continue;
    n_rx += avf_device_input_inline (vm, node, frame, ad, dq->queue_id);
  }
  return n_rx;
}

#ifndef CLIB_MULTIARCH_VARIANT
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (avf_input_node) = {
  .function = avf_input,
  .name = "avf-input",
  .sibling_of = "device-input",
  .format_trace = format_avf_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
  .n_errors = AVF_INPUT_N_ERROR,
  .error_strings = avf_input_error_strings,
};

#if __x86_64__
vlib_node_function_t __clib_weak avf_input_avx512;
vlib_node_function_t __clib_weak avf_input_avx2;
static void __clib_constructor
avf_input_multiarch_select (void)
{
  if (avf_input_avx512 && clib_cpu_supports_avx512f ())
    avf_input_node.function = avf_input_avx512;
  else if (avf_input_avx2 && clib_cpu_supports_avx2 ())
    avf_input_node.function = avf_input_avx2;
}

#endif
#endif

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
