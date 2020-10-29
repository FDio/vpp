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
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/udp/udp_packet.h>

#include <vmxnet3/vmxnet3.h>

#define foreach_vmxnet3_input_error \
  _(BUFFER_ALLOC, "buffer alloc error") \
  _(RX_PACKET_NO_SOP, "Rx packet error - no SOP") \
  _(RX_PACKET, "Rx packet error") \
  _(RX_PACKET_EOP, "Rx packet error found on EOP") \
  _(NO_BUFFER, "Rx no buffer error")

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
vmxnet3_find_rid (vmxnet3_device_t * vd, vmxnet3_rx_comp * rx_comp)
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

static_always_inline void
vmxnet3_rx_comp_ring_advance_next (vmxnet3_rxq_t * rxq)
{
  vmxnet3_rx_comp_ring *comp_ring = &rxq->rx_comp_ring;

  comp_ring->next++;
  if (PREDICT_FALSE (comp_ring->next == rxq->size))
    {
      comp_ring->next = 0;
      comp_ring->gen ^= VMXNET3_RXCF_GEN;
    }
}

static_always_inline void
vmxnet3_handle_offload (vmxnet3_rx_comp * rx_comp, vlib_buffer_t * hb,
			u16 gso_size)
{
  u8 l4_hdr_sz = 0;

  if (rx_comp->flags & VMXNET3_RXCF_IP4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) (hb->data +
					    sizeof (ethernet_header_t));

      vnet_buffer (hb)->l2_hdr_offset = 0;
      vnet_buffer (hb)->l3_hdr_offset = sizeof (ethernet_header_t);
      vnet_buffer (hb)->l4_hdr_offset = sizeof (ethernet_header_t) +
	ip4_header_bytes (ip4);
      hb->flags |= VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	VNET_BUFFER_F_L4_HDR_OFFSET_VALID | VNET_BUFFER_F_IS_IP4 |
	VNET_BUFFER_F_OFFLOAD;
      u32 oflags = vnet_buffer2 (hb)->oflags;

      /* checksum offload */
      if (!(rx_comp->index & VMXNET3_RXCI_CNC))
	{
	  if (!(rx_comp->flags & VMXNET3_RXCF_IPC))
	    {
	      oflags |= VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
	      ip4->checksum = 0;
	    }
	  if (!(rx_comp->flags & VMXNET3_RXCF_TUC))
	    {
	      if (rx_comp->flags & VMXNET3_RXCF_TCP)
		{
		  tcp_header_t *tcp =
		    (tcp_header_t *) (hb->data +
				      vnet_buffer (hb)->l4_hdr_offset);
		  oflags |= VNET_BUFFER_OFFLOAD_F_TCP_CKSUM;
		  tcp->checksum = 0;
		}
	      else if (rx_comp->flags & VMXNET3_RXCF_UDP)
		{
		  udp_header_t *udp =
		    (udp_header_t *) (hb->data +
				      vnet_buffer (hb)->l4_hdr_offset);
		  oflags |= VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;
		  udp->checksum = 0;
		}
	    }
	}

      vnet_buffer2 (hb)->oflags = oflags;
      if (gso_size)
	{
	  if (rx_comp->flags & VMXNET3_RXCF_TCP)
	    {
	      tcp_header_t *tcp =
		(tcp_header_t *) (hb->data + vnet_buffer (hb)->l4_hdr_offset);
	      l4_hdr_sz = tcp_header_bytes (tcp);
	    }
	  else if (rx_comp->flags & VMXNET3_RXCF_UDP)
	    {
	      udp_header_t *udp =
		(udp_header_t *) (hb->data + vnet_buffer (hb)->l4_hdr_offset);
	      l4_hdr_sz = sizeof (*udp);
	    }
	  vnet_buffer2 (hb)->gso_size = gso_size;
	  vnet_buffer2 (hb)->gso_l4_hdr_sz = l4_hdr_sz;
	  hb->flags |= VNET_BUFFER_F_GSO;
	}
    }
  else if (rx_comp->flags & VMXNET3_RXCF_IP6)
    {
      vnet_buffer (hb)->l2_hdr_offset = 0;
      vnet_buffer (hb)->l3_hdr_offset = sizeof (ethernet_header_t);
      vnet_buffer (hb)->l4_hdr_offset = sizeof (ethernet_header_t) +
	sizeof (ip6_header_t);
      hb->flags |= VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	VNET_BUFFER_F_L4_HDR_OFFSET_VALID | VNET_BUFFER_F_IS_IP6 |
	VNET_BUFFER_F_OFFLOAD;
      u32 oflags = vnet_buffer2 (hb)->oflags;

      /* checksum offload */
      if (!(rx_comp->index & VMXNET3_RXCI_CNC))
	{
	  if (!(rx_comp->flags & VMXNET3_RXCF_TUC))
	    {
	      if (rx_comp->flags & VMXNET3_RXCF_TCP)
		{
		  tcp_header_t *tcp =
		    (tcp_header_t *) (hb->data +
				      vnet_buffer (hb)->l4_hdr_offset);
		  oflags |= VNET_BUFFER_OFFLOAD_F_TCP_CKSUM;
		  tcp->checksum = 0;
		}
	      else if (rx_comp->flags & VMXNET3_RXCF_UDP)
		{
		  udp_header_t *udp =
		    (udp_header_t *) (hb->data +
				      vnet_buffer (hb)->l4_hdr_offset);
		  oflags |= VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;
		  udp->checksum = 0;
		}
	    }
	}

      vnet_buffer2 (hb)->oflags = oflags;
      if (gso_size)
	{
	  if (rx_comp->flags & VMXNET3_RXCF_TCP)
	    {
	      tcp_header_t *tcp =
		(tcp_header_t *) (hb->data + vnet_buffer (hb)->l4_hdr_offset);
	      l4_hdr_sz = tcp_header_bytes (tcp);
	    }
	  else if (rx_comp->flags & VMXNET3_RXCF_UDP)
	    {
	      udp_header_t *udp =
		(udp_header_t *) (hb->data + vnet_buffer (hb)->l4_hdr_offset);
	      l4_hdr_sz = sizeof (*udp);
	    }
	  vnet_buffer2 (hb)->gso_size = gso_size;
	  vnet_buffer2 (hb)->gso_l4_hdr_sz = l4_hdr_sz;
	  hb->flags |= VNET_BUFFER_F_GSO;
	}
    }
}

static_always_inline uword
vmxnet3_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			     vlib_frame_t * frame, vmxnet3_device_t * vd,
			     u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 n_rx_packets = 0, n_rx_bytes = 0;
  vmxnet3_rx_comp *rx_comp;
  u32 desc_idx;
  vmxnet3_rxq_t *rxq;
  u32 thread_index = vm->thread_index;
  u32 buffer_indices[VLIB_FRAME_SIZE], *bi;
  u16 nexts[VLIB_FRAME_SIZE], *next;
  vmxnet3_rx_ring *ring;
  vmxnet3_rx_comp_ring *comp_ring;
  u16 rid;
  vlib_buffer_t *prev_b0 = 0, *hb = 0;
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  u8 known_next = 0, got_packet = 0;
  vmxnet3_rx_desc *rxd;
  clib_error_t *error;
  u16 gso_size = 0;

  rxq = vec_elt_at_index (vd->rxqs, qid);
  comp_ring = &rxq->rx_comp_ring;
  bi = buffer_indices;
  next = nexts;
  rx_comp = &rxq->rx_comp[comp_ring->next];

  while (PREDICT_TRUE ((n_rx_packets < VLIB_FRAME_SIZE) &&
		       (comp_ring->gen ==
			(rx_comp->flags & VMXNET3_RXCF_GEN))))
    {
      vlib_buffer_t *b0;
      u32 bi0;

      rid = vmxnet3_find_rid (vd, rx_comp);
      ring = &rxq->rx_ring[rid];

      if (PREDICT_TRUE (ring->fill >= 1))
	ring->fill--;
      else
	{
	  vlib_error_count (vm, node->node_index,
			    VMXNET3_INPUT_ERROR_NO_BUFFER, 1);
	  if (hb)
	    {
	      vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, hb));
	      hb = 0;
	    }
	  prev_b0 = 0;
	  break;
	}

      desc_idx = rx_comp->index & VMXNET3_RXC_INDEX;
      ring->consume = desc_idx;
      rxd = &rxq->rx_desc[rid][desc_idx];

      bi0 = ring->bufs[desc_idx];
      ring->bufs[desc_idx] = ~0;

      b0 = vlib_get_buffer (vm, bi0);
      vnet_buffer (b0)->sw_if_index[VLIB_RX] = vd->sw_if_index;
      vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;
      vnet_buffer (b0)->feature_arc_index = 0;
      b0->current_length = rx_comp->len & VMXNET3_RXCL_LEN_MASK;
      b0->current_data = 0;
      b0->total_length_not_including_first_buffer = 0;
      b0->next_buffer = 0;
      b0->flags = 0;
      b0->error = 0;
      b0->current_config_index = 0;

      if (PREDICT_FALSE ((rx_comp->index & VMXNET3_RXCI_EOP) &&
			 (rx_comp->len & VMXNET3_RXCL_ERROR)))
	{
	  vlib_buffer_free_one (vm, bi0);
	  vlib_error_count (vm, node->node_index,
			    VMXNET3_INPUT_ERROR_RX_PACKET_EOP, 1);
	  if (hb && vlib_get_buffer_index (vm, hb) != bi0)
	    {
	      vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, hb));
	      hb = 0;
	    }
	  prev_b0 = 0;
	  goto next;
	}

      if (rx_comp->index & VMXNET3_RXCI_SOP)
	{
	  ASSERT (!(rxd->flags & VMXNET3_RXF_BTYPE));
	  /* start segment */
	  if (vd->gso_enable &&
	      (rx_comp->flags & VMXNET3_RXCF_CT) == VMXNET3_RXCOMP_TYPE_LRO)
	    {
	      vmxnet3_rx_comp_ext *lro = (vmxnet3_rx_comp_ext *) rx_comp;

	      gso_size = lro->flags & VMXNET3_RXECF_MSS_MASK;
	    }

	  hb = b0;
	  bi[0] = bi0;
	  if (!(rx_comp->index & VMXNET3_RXCI_EOP))
	    {
	      hb->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	      prev_b0 = b0;
	    }
	  else
	    {
	      /*
	       * Both start and end of packet is set. It is a complete packet
	       */
	      prev_b0 = 0;
	      got_packet = 1;
	    }
	}
      else if (rx_comp->index & VMXNET3_RXCI_EOP)
	{
	  /* end of segment */
	  if (PREDICT_TRUE (prev_b0 != 0))
	    {
	      if (PREDICT_TRUE (b0->current_length != 0))
		{
		  prev_b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
		  prev_b0->next_buffer = bi0;
		  hb->total_length_not_including_first_buffer +=
		    b0->current_length;
		}
	      else
		{
		  vlib_buffer_free_one (vm, bi0);
		}
	      prev_b0 = 0;
	      got_packet = 1;
	    }
	  else
	    {
	      /* EOP without SOP, error */
	      vlib_error_count (vm, node->node_index,
				VMXNET3_INPUT_ERROR_RX_PACKET_NO_SOP, 1);
	      vlib_buffer_free_one (vm, bi0);
	      if (hb && vlib_get_buffer_index (vm, hb) != bi0)
		{
		  vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, hb));
		  hb = 0;
		}
	      goto next;
	    }
	}
      else if (prev_b0)		// !sop && !eop
	{
	  /* mid chain */
	  ASSERT (rxd->flags & VMXNET3_RXF_BTYPE);
	  prev_b0->flags |= VLIB_BUFFER_NEXT_PRESENT;
	  prev_b0->next_buffer = bi0;
	  prev_b0 = b0;
	  hb->total_length_not_including_first_buffer += b0->current_length;
	}
      else
	{
	  vlib_error_count (vm, node->node_index,
			    VMXNET3_INPUT_ERROR_RX_PACKET, 1);
	  vlib_buffer_free_one (vm, bi0);
	  if (hb && vlib_get_buffer_index (vm, hb) != bi0)
	    {
	      vlib_buffer_free_one (vm, vlib_get_buffer_index (vm, hb));
	      hb = 0;
	    }
	  goto next;
	}

      n_rx_bytes += b0->current_length;

      if (got_packet)
	{
	  if (PREDICT_FALSE (vd->per_interface_next_index != ~0))
	    {
	      next_index = vd->per_interface_next_index;
	      known_next = 1;
	    }

	  if (PREDICT_FALSE
	      (vnet_device_input_have_features (vd->sw_if_index)))
	    {
	      vnet_feature_start_device_input_x1 (vd->sw_if_index,
						  &next_index, hb);
	      known_next = 1;
	    }

	  if (PREDICT_FALSE (known_next))
	    next[0] = next_index;
	  else
	    {
	      ethernet_header_t *e = (ethernet_header_t *) hb->data;

	      next[0] = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
	      if (!ethernet_frame_is_tagged (ntohs (e->type)))
		vmxnet3_handle_offload (rx_comp, hb, gso_size);
	    }

	  n_rx_packets++;
	  next++;
	  bi++;
	  hb = 0;
	  got_packet = 0;
	  gso_size = 0;
	}

    next:
      vmxnet3_rx_comp_ring_advance_next (rxq);
      rx_comp = &rxq->rx_comp[comp_ring->next];
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
	 vd->sw_if_index, n_rx_packets, n_rx_bytes);
    }

  error = vmxnet3_rxq_refill_ring0 (vm, vd, rxq);
  if (PREDICT_FALSE (error != 0))
    {
      vlib_error_count (vm, node->node_index,
			VMXNET3_INPUT_ERROR_BUFFER_ALLOC, 1);
    }
  error = vmxnet3_rxq_refill_ring1 (vm, vd, rxq);
  if (PREDICT_FALSE (error != 0))
    {
      vlib_error_count (vm, node->node_index,
			VMXNET3_INPUT_ERROR_BUFFER_ALLOC, 1);
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
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
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
