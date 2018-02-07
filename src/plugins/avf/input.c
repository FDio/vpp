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

#define AVF_RX_DESC_STATUS_DD (1<<0)

static_always_inline uword
avf_rx_desc_done (avf_rx_desc_t * d)
{
  return avf_get_u64_bits (d, 8, 18, 0) & AVF_RX_DESC_STATUS_DD;
}

static_always_inline void
avf_input_trace (vlib_main_t * vm, vlib_node_runtime_t * node, u32 next0,
		 vlib_buffer_t * b0, uword * n_trace, avf_device_t * ad,
		 avf_rx_desc_t * d)
{
  avf_input_trace_t *tr;
  vlib_trace_buffer (vm, node, next0, b0, /* follow_chain */ 0);
  vlib_set_trace_count (vm, node, --(*n_trace));
  tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
  tr->next_index = next0;
  tr->hw_if_index = ad->hw_if_index;
  clib_memcpy (&tr->desc, d, sizeof (avf_rx_desc_t));
}

static_always_inline uword
avf_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			 vlib_frame_t * frame, avf_device_t * ad, u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 thread_index = vlib_get_thread_index ();
  avf_rxq_t *rxq = vec_elt_at_index (ad->rxqs, qid);
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  avf_rx_desc_t *d;
  u32 *to_next = 0;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u32 sw_if_idx[VLIB_N_RX_TX] = {[VLIB_RX] = ad->sw_if_index,[VLIB_TX] = ~0 };
  u16 mask = rxq->size - 1;

  d = ((avf_rx_desc_t *) rxq->descs) + rxq->next;
  while (avf_rx_desc_done (d))
    {
      u32 n_left_to_next;
      u32 bi0;
      vlib_buffer_t *b0;
      u32 next0;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (avf_rx_desc_done (d) && n_left_to_next)
	{
	  bi0 = rxq->bufs[rxq->next];
	  to_next[0] = bi0;
	  b0 = vlib_get_buffer (vm, bi0);

	  b0->current_data = 0;
	  b0->current_length = avf_get_u64_bits (d, 8, 63, 38);
	  n_rx_packets++;
	  n_rx_bytes += b0->current_length;

	  next0 = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;

	  clib_memcpy (vnet_buffer (b0)->sw_if_index, sw_if_idx,
		       sizeof (sw_if_idx));

	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
	  if (PREDICT_FALSE (n_trace > 0))
	    avf_input_trace (vm, node, next0, b0, &n_trace, ad, d);

	  to_next += 1;
	  n_left_to_next -= 1;

	  rxq->next = (rxq->next + 1) & mask;
	  d = ((avf_rx_desc_t *) rxq->descs) + rxq->next;
	  rxq->n_bufs--;
	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX,
				   thread_index, ad->hw_if_index,
				   n_rx_packets, n_rx_bytes);

#define AVF_INPUT_REFILL_TRESHOLD 32
  u16 n_refill = rxq->size - 1 - rxq->n_bufs;
  if (n_refill > AVF_INPUT_REFILL_TRESHOLD)
    {
      u16 n_alloc;
      u16 slot = (rxq->next - n_refill - 1) & mask;

      n_refill &= ~7;		/* round to 8 */
      n_alloc = vlib_buffer_alloc_to_ring (vm, rxq->bufs, slot, rxq->size,
					   n_refill);

      if (PREDICT_FALSE (n_alloc != n_refill))
	{
	  vlib_error_count (vm, node->node_index,
			    AVF_INPUT_ERROR_BUFFER_ALLOC, 1);
	  if (n_alloc)
	    vlib_buffer_free (vm, rxq->bufs + slot, n_alloc);
	  goto done;
	}

      rxq->n_bufs += n_alloc;

      while (n_alloc--)
	{
	  d = ((avf_rx_desc_t *) rxq->descs) + slot;
	  d->qword[0] =
	    vlib_get_buffer_data_physical_address (vm, rxq->bufs[slot]);
	  d->qword[1] = 0;
	  clib_warning ("refill slot %u", slot);
	  slot = (slot + 1) & mask;
	}

      CLIB_MEMORY_BARRIER ();
      *(rxq->qrx_tail) = slot;
    }

done:
  return n_rx_packets;
}

uword
avf_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
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

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (avf_input_node) = {
  .function = avf_input_fn,
  .name = "avf-input",
  .sibling_of = "device-input",
  .format_trace = format_avf_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_POLLING,
  .n_errors = AVF_INPUT_N_ERROR,
  .error_strings = avf_input_error_strings,
};

/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
