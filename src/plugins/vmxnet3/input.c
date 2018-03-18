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

#include <vmxnet3/vmxnet3.h>

#define foreach_vmxnet3_input_error \
  _(BUFFER_ALLOC, "buffer alloc error") \
  _(RX_PACKET_ERROR, "Rx packet errors")

typedef enum
{
#define _(f,s) VMXNET3_INPUT_ERROR_##f,
  foreach_vmxnet3_input_error
#undef _
    VMXNET3_INPUT_N_ERROR,
} vmxnet3_input_error_t;

static __clib_unused char *vmxnet3_input_error_strings[] = {
#define _(n,s) s,
  foreach_vmxnet3_input_error
#undef _
};

static_always_inline u16
vmxnet3_find_rid (vmxnet3_device_t * vd, vmxnet3_rx_comp *rx_comp)
{
  u32 rid;

  // rid is bits 16-25 (10 bits number)
  rid = rx_comp->index & (0xffffffff >> 6);
  rid >>= 16;
  if ((rid >= vd->num_rx_queues) && (rid < (vd->num_rx_queues << 1)))
    return 1;
  else
    return 0;
}

static_always_inline uword
vmxnet3_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * frame, vmxnet3_device_t * vd,
			     u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 n_rx_packets = 0, n_rx_bytes = 0, generation;
  vmxnet3_rx_comp *rx_comp;
  u32 comp_idx;
  u32 desc_idx;
  vmxnet3_rxq_t *rxq;
  u16 mask;
  u32 thread_index = vm->thread_index;
  u32 buffer_indices[VLIB_FRAME_SIZE], *bi;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vmxnet3_rx_ring *ring;
  vmxnet3_rx_comp_ring *comp_ring;
  u16 rid;
  vlib_buffer_t *prev_b0 = 0;

  rxq = vec_elt_at_index (vd->rxqs, qid);
  comp_ring = &rxq->rx_comp_ring;
  mask = rxq->size - 1;
  bi = buffer_indices;
  next = nexts;
  while (1)
    {
      vlib_buffer_t *b0, *hb;

      comp_idx = comp_ring->next & mask;
      if (comp_ring->next & rxq->size)
	generation = 0;
      else
	generation = VMXNET3_RXCF_GEN;
      rx_comp = &rxq->rx_comp[comp_idx];
      if (generation != (rx_comp->flags & VMXNET3_RXCF_GEN))
	break;

      rid = vmxnet3_find_rid (vd, rx_comp);
      ring = &rxq->rx_ring[rid];

      ASSERT (ring->consume < ring->produce);
      ASSERT ((ring->consume + ring->fill) == ring->produce);
      ring->consume++;
      comp_ring->next++;
      desc_idx = rx_comp->index & VMXNET3_RXC_INDEX;
      ring->fill--;

      bi[0] = ring->bufs[desc_idx];

      ASSERT ((ring->bufs[desc_idx] = ~0) == ~0);

      b0 = vlib_get_buffer (vm, bi[0]);
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = vd->sw_if_index;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~0;
      b0->current_length = rx_comp->len & VMXNET3_RXCL_LEN_MASK;
      b0->current_data = 0;
      b0->total_length_not_including_first_buffer = 0;
      b0->next_buffer = 0;
      b0->flags = 0;
      b0->error = 0;
      ASSERT (b0->current_length != 0);

      if (rx_comp->index & VMXNET3_RXCI_SOP)
	{
	  /* start segment */
	  b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  hb = b0;
	  if (!(rx_comp->index & VMXNET3_RXCI_EOP))
	    {
	      b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
	      hb->total_length_not_including_first_buffer += b0->current_length;
	      prev_b0 = b0;
	    }
	  else
	    {
	      /*
	       * Both start and end of packet is set. It is a complete packet
	       */
	      prev_b0 = 0;
	    }

	}
      else if (rx_comp->index & VMXNET3_RXCI_EOP)
	{
	  b0->flags = 0;
	  /* end of segment */
	  if (prev_b0)
	    {
	      prev_b0->next_buffer = bi[0];
	      hb->total_length_not_including_first_buffer += b0->current_length;
	      prev_b0 = 0;
	    }
	}
      else if (prev_b0) // !sop && !eop
	{
	  /* mid chain */
	  b0->flags = VLIB_BUFFER_NEXT_PRESENT;
	  prev_b0->next_buffer = bi[0];
	  prev_b0 = b0;
	  hb->total_length_not_including_first_buffer += b0->current_length;
	}

      bi++;
      n_rx_bytes += rx_comp->len & VMXNET3_RXCL_LEN_MASK;

      if (!prev_b0)
	{
	  next[0] = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
	  n_rx_packets++;
	  next++;
	}
    }

  if (PREDICT_FALSE ((n_trace = vlib_get_trace_count (vm, node))))
    {
      u32 n_left = n_rx_packets;

      bi = buffer_indices;
      next = nexts;
      while (n_trace && n_left)
	{
	  vlib_buffer_t *b;
	  vmxnet3_input_trace_t *tr;

	  b = vlib_get_buffer (vm, bi[0]);
	  vlib_trace_buffer (vm, node, next[0], b, /* follow_chain */ 0);
	  tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	  tr->next_index = next[0];
	  tr->hw_if_index = vd->hw_if_index;
	  tr->buffer = *b;

	  n_trace--;
	  n_left--;
	  bi++;
	  next++;
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  if (PREDICT_TRUE (n_rx_packets))
    {
      vlib_buffer_enqueue_to_next (vm, node, buffer_indices, nexts,
				   n_rx_packets);
      vlib_increment_combined_counter
	(vnm->interface_main.combined_sw_if_counters +
	 VNET_INTERFACE_COUNTER_RX, thread_index,
	 vd->hw_if_index, n_rx_packets, n_rx_bytes);

      vmxnet3_rxq_refill_ring0 (vm, vd, rxq);
      vmxnet3_rxq_refill_ring1 (vm, vd, rxq);
    }

  return n_rx_packets;
}

VLIB_NODE_FN (vmxnet3_input_node) (vlib_main_t * vm,
                                   vlib_node_runtime_t * node,
				   vlib_frame_t * frame)
{
  u32 n_rx = 0;
  vmxnet3_main_t *vmxm = &vmxnet3_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    vmxnet3_device_t *vd;
    vd = vec_elt_at_index (vmxm->devices, dq->dev_instance);
    if ((vd->flags & VMXNET3_DEVICE_F_ADMIN_UP) == 0)
      continue;
    n_rx += vmxnet3_device_input_inline (vm, node, frame, vd, dq->queue_id);
  }
  return n_rx;
}

#ifndef CLIB_MARCH_VARIANT
/* *INDENT-OFF* */
VLIB_REGISTER_NODE (vmxnet3_input_node) = {
  .name = "vmxnet3-input",
  .sibling_of = "device-input",
  .format_trace = format_vmxnet3_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
  .n_errors = VMXNET3_INPUT_N_ERROR,
  .error_strings = vmxnet3_input_error_strings,
};
#endif

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
