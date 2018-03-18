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

static_always_inline uword
vmxnet3_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * frame, vmxnet3_device_t * vd,
			     u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 n_rx_packets = 0, n_rx_bytes = 0;
  vmxnet3_rx_comp *rx_comp;
  u32 comp_idx;
  u32 desc_idx;
  u32 generation;
  vmxnet3_rxq_t *rxq;
  u16 mask;
  u32 thr_idx = vlib_get_thread_index ();

  rxq = vec_elt_at_index (vd->rxqs, qid);
  mask = rxq->size - 1;
  while (1)
    {
      u16 next = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      u32 buffer_indices;
      vlib_buffer_t *b0;

      comp_idx = vd->count.rx_cons & mask;
      if (vd->count.rx_cons & VMXNET3_NUM_RX_COMP)
	generation = 0;
      else
	generation = VMXNET3_RXCF_GEN;
      rx_comp = &vd->dma->rx_comp[comp_idx];
      if (generation != (rx_comp->flags & VMXNET3_RXCF_GEN))
	break;

      vd->count.rx_cons++;

      desc_idx = rx_comp->index & mask;

      vd->count.rx_fill--;

      b0 = vlib_get_buffer (vm, rxq->bufs[desc_idx]);
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = vd->sw_if_index;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~0;
      b0->current_length = n_rx_bytes = rx_comp->len;
      b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
      n_rx_packets++;

      buffer_indices = rxq->bufs[desc_idx];

      if (PREDICT_FALSE (n_trace))
	{
	  vmxnet3_input_trace_t *tr;

	  vlib_trace_buffer (vm, node, next, b0, /* follow_chain */ 0);
	  tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	  tr->next_index = next;
	  tr->hw_if_index = vd->hw_if_index;
	  n_trace--;
	  vlib_set_trace_count (vm, node, n_trace);
	}

      vlib_buffer_enqueue_to_next (vm, node, &buffer_indices, &next,
				   n_rx_packets);
      vlib_increment_combined_counter
	(vnm->interface_main.combined_sw_if_counters +
	 VNET_INTERFACE_COUNTER_RX, thr_idx,
	 vd->hw_if_index, n_rx_packets, n_rx_bytes);
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
