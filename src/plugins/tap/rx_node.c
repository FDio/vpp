/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016-2025 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <tap/internal.h>
#include <tap/inline.h>

static char *tap_virtio_input_error_strings[] = {
#define _(n, s) s,
  foreach_virtio_input_error
#undef _
};

static_always_inline void
tap_needs_csum (vlib_buffer_t *b0, vnet_virtio_net_hdr_v1_t *hdr, u8 *l4_proto,
		u8 *l4_hdr_sz, int is_tun)
{
  if (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
    {
      u16 ethertype = 0, l2hdr_sz = 0;
      vnet_buffer_oflags_t oflags = 0;

      if (is_tun)
	{
	  switch (b0->data[0] & 0xf0)
	    {
	    case 0x40:
	      ethertype = ETHERNET_TYPE_IP4;
	      break;
	    case 0x60:
	      ethertype = ETHERNET_TYPE_IP6;
	      break;
	    }
	}
      else
	{
	  ethernet_header_t *eh = (ethernet_header_t *) b0->data;
	  ethertype = clib_net_to_host_u16 (eh->type);
	  l2hdr_sz = sizeof (ethernet_header_t);

	  if (ethernet_frame_is_tagged (ethertype))
	    {
	      ethernet_vlan_header_t *vlan =
		(ethernet_vlan_header_t *) (eh + 1);

	      ethertype = clib_net_to_host_u16 (vlan->type);
	      l2hdr_sz += sizeof (*vlan);
	      if (ethertype == ETHERNET_TYPE_VLAN)
		{
		  vlan++;
		  ethertype = clib_net_to_host_u16 (vlan->type);
		  l2hdr_sz += sizeof (*vlan);
		}
	    }
	}

      vnet_buffer (b0)->l2_hdr_offset = 0;
      vnet_buffer (b0)->l3_hdr_offset = l2hdr_sz;

      if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP4))
	{
	  ip4_header_t *ip4 = (ip4_header_t *) (b0->data + l2hdr_sz);
	  vnet_buffer (b0)->l4_hdr_offset = l2hdr_sz + ip4_header_bytes (ip4);
	  *l4_proto = ip4->protocol;
	  oflags |= VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
	  b0->flags |=
	    (VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	     VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	     VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
	}
      else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
	{
	  ip6_header_t *ip6 = (ip6_header_t *) (b0->data + l2hdr_sz);
	  vnet_buffer (b0)->l4_hdr_offset = l2hdr_sz + sizeof (ip6_header_t);
	  /* FIXME IPv6 EH traversal */
	  *l4_proto = ip6->protocol;
	  b0->flags |=
	    (VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
	     VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	     VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
	}
      if (*l4_proto == IP_PROTOCOL_TCP)
	{
	  oflags |= VNET_BUFFER_OFFLOAD_F_TCP_CKSUM;
	  tcp_header_t *tcp =
	    (tcp_header_t *) (b0->data + vnet_buffer (b0)->l4_hdr_offset);
	  *l4_hdr_sz = tcp_header_bytes (tcp);
	}
      else if (*l4_proto == IP_PROTOCOL_UDP)
	{
	  oflags |= VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;
	  *l4_hdr_sz = sizeof (udp_header_t);
	}
      if (oflags)
	vnet_buffer_offload_flags_set (b0, oflags);
    }
}

static_always_inline void
fill_gso_buffer_flags (vlib_buffer_t *b0, vnet_virtio_net_hdr_v1_t *hdr,
		       u8 l4_proto, u8 l4_hdr_sz)
{
  if (hdr->gso_type == VIRTIO_NET_HDR_GSO_TCPV4)
    {
      ASSERT (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM);
      vnet_buffer2 (b0)->gso_size = hdr->gso_size;
      vnet_buffer2 (b0)->gso_l4_hdr_sz = l4_hdr_sz;
      b0->flags |= VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP4;
    }
  if (hdr->gso_type == VIRTIO_NET_HDR_GSO_TCPV6)
    {
      ASSERT (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM);
      vnet_buffer2 (b0)->gso_size = hdr->gso_size;
      vnet_buffer2 (b0)->gso_l4_hdr_sz = l4_hdr_sz;
      b0->flags |= VNET_BUFFER_F_GSO | VNET_BUFFER_F_IS_IP6;
    }
}

static_always_inline u16
tap_n_left_to_process (vnet_virtio_vring_t *vring)
{
  return vring->used->idx - vring->last_used_idx;
}

static_always_inline u16
tap_get_slot_id (vnet_virtio_vring_t *vring, u16 last, u16 mask)
{
  return vring->used->ring[last & mask].id;
}

static_always_inline u16
tap_get_len (vnet_virtio_vring_t *vring, const int hdr_sz, u16 last, u16 mask)
{
  return vring->used->ring[last & mask].len - hdr_sz;
}

static_always_inline void
tap_device_input_ethernet (vlib_main_t *vm, vlib_node_runtime_t *node,
			   const u32 next_index, const u32 sw_if_index,
			   const u32 hw_if_index)
{
  vlib_next_frame_t *nf;
  vlib_frame_t *f;
  ethernet_input_frame_t *ef;

  if (PREDICT_FALSE (VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT != next_index))
    return;

  nf = vlib_node_runtime_get_next_frame (
    vm, node, VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT);
  f = vlib_get_frame (vm, nf->frame);
  f->flags = ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

  ef = vlib_frame_scalar_args (f);
  ef->sw_if_index = sw_if_index;
  ef->hw_if_index = hw_if_index;
  vlib_frame_no_append (f);
}

static_always_inline uword
tap_device_input_gso_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			     vlib_frame_t *frame, tap_if_t *tif,
			     vnet_virtio_vring_t *vring, int is_tun,
			     int gso_enabled, int checksum_offload_enabled)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_thread_index_t thread_index = vm->thread_index;
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 next_index;
  const int hdr_sz = tif->tap_virtio_net_hdr_sz;
  u32 *to_next = 0;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u16 mask = vring->queue_size - 1;
  u16 last = vring->last_used_idx;
  u16 n_left = tap_n_left_to_process (vring);
  vlib_buffer_t bt = {};

  if (n_left == 0)
    return 0;

  if (PREDICT_FALSE (n_left == vring->queue_size))
    {
      /*
       * Informational error logging when VPP is not pulling packets fast
       * enough.
       */
      vlib_error_count (vm, node->node_index, VIRTIO_INPUT_ERROR_FULL_RX_QUEUE,
			1);
    }

  if (is_tun)
    {
      next_index = VNET_DEVICE_INPUT_NEXT_IP4_INPUT;
    }
  else
    {
      next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      if (PREDICT_FALSE (tif->per_interface_next_index != ~0))
	next_index = tif->per_interface_next_index;

      /* only for l2, redirect if feature path enabled */
      vnet_feature_start_device_input (tif->sw_if_index, &next_index, &bt);
    }

  while (n_left)
    {
      u32 n_left_to_next;
      u32 next0 = next_index;

      vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left && n_left_to_next)
	{
	  u8 l4_proto = 0, l4_hdr_sz = 0;
	  u16 num_buffers = 1;
	  vnet_virtio_net_hdr_v1_t *hdr;
	  u16 slot = tap_get_slot_id (vring, last, mask);
	  u16 len = tap_get_len (vring, hdr_sz, last, mask);
	  u32 bi0 = vring->buffers[slot];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  hdr = vlib_buffer_get_current (b0);
	  if (hdr_sz == sizeof (vnet_virtio_net_hdr_v1_t))
	    num_buffers = hdr->num_buffers;

	  b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  b0->current_data = 0;
	  b0->current_length = len;

	  if (checksum_offload_enabled)
	    tap_needs_csum (b0, hdr, &l4_proto, &l4_hdr_sz, is_tun);

	  if (gso_enabled)
	    fill_gso_buffer_flags (b0, hdr, l4_proto, l4_hdr_sz);

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = tif->sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~0;

	  /* if multisegment packet */
	  if (PREDICT_FALSE (num_buffers > 1))
	    {
	      vlib_buffer_t *pb, *cb;
	      pb = b0;
	      b0->total_length_not_including_first_buffer = 0;
	      while (num_buffers > 1)
		{
		  last++;
		  u16 cslot = tap_get_slot_id (vring, last, mask);
		  /* hdr size is 0 after 1st packet in chain buffers */
		  u16 clen = tap_get_len (vring, 0, last, mask);
		  u32 cbi = vring->buffers[cslot];
		  cb = vlib_get_buffer (vm, cbi);

		  /* current buffer */
		  cb->current_length = clen;

		  /* previous buffer */
		  pb->next_buffer = cbi;
		  pb->flags |= VLIB_BUFFER_NEXT_PRESENT;

		  /* first buffer */
		  b0->total_length_not_including_first_buffer += clen;

		  pb = cb;
		  vring->desc_in_use--;
		  num_buffers--;
		  n_left--;
		}
	      len += b0->total_length_not_including_first_buffer;
	    }

	  if (is_tun)
	    {
	      switch (b0->data[0] & 0xf0)
		{
		case 0x40:
		  next0 = VNET_DEVICE_INPUT_NEXT_IP4_INPUT;
		  break;
		case 0x60:
		  next0 = VNET_DEVICE_INPUT_NEXT_IP6_INPUT;
		  break;
		default:
		  next0 = VNET_DEVICE_INPUT_NEXT_DROP;
		  break;
		}

	      if (PREDICT_FALSE (tif->per_interface_next_index != ~0))
		next0 = tif->per_interface_next_index;
	    }
	  else
	    {
	      /* copy feature arc data from template */
	      b0->current_config_index = bt.current_config_index;
	      vnet_buffer (b0)->feature_arc_index =
		vnet_buffer (&bt)->feature_arc_index;
	    }

	  /* trace */
	  if (PREDICT_FALSE (n_trace > 0 &&
			     vlib_trace_buffer (vm, node, next0,
						b0, /* follow_chain */
						1)))
	    {
	      tap_rx_trace_t *tr;
	      vlib_set_trace_count (vm, node, --n_trace);
	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->hw_if_index = tif->hw_if_index;
	      tr->len = len;
	      clib_memcpy_fast (&tr->hdr, hdr, (hdr_sz == 12) ? 12 : 10);
	    }

	  /* enqueue buffer */
	  to_next[0] = bi0;
	  vring->desc_in_use--;
	  to_next += 1;
	  n_left_to_next--;
	  n_left--;
	  last++;

	  /* only tun interfaces may have different next index */
	  if (is_tun)
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					     n_left_to_next, bi0, next0);

	  /* next packet */
	  n_rx_packets++;
	  n_rx_bytes += len;
	}
      tap_device_input_ethernet (vm, node, next_index, tif->sw_if_index,
				 tif->hw_if_index);
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vring->last_used_idx = last;

  vring->total_packets += n_rx_packets;
  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    thread_index, tif->sw_if_index, n_rx_packets, n_rx_bytes);

  return n_rx_packets;
}

static_always_inline uword
tap_device_input_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			 vlib_frame_t *frame, tap_if_t *tif, u16 qid,
			 int is_tun)
{
  vnet_virtio_vring_t *vring = vec_elt_at_index (tif->rxq_vrings, qid);
  const int hdr_sz = tif->tap_virtio_net_hdr_sz;
  uword rv;

  if (tif->gso_enabled)
    rv =
      tap_device_input_gso_inline (vm, node, frame, tif, vring, is_tun, 1, 1);
  else if (tif->csum_offload_enabled)
    rv =
      tap_device_input_gso_inline (vm, node, frame, tif, vring, is_tun, 0, 1);
  else
    rv =
      tap_device_input_gso_inline (vm, node, frame, tif, vring, is_tun, 0, 0);

  tap_refill_vring_split (vm, tif, vring, hdr_sz, node->node_index);
  return rv;
}

VLIB_NODE_FN (tap_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_rx = 0;
  tap_main_t *tm = &tap_main;
  vnet_hw_if_rxq_poll_vector_t *p,
    *pv = vnet_hw_if_get_rxq_poll_vector (vm, node);

  vec_foreach (p, pv)
    {
      tap_if_t *tif;
      tif = vec_elt_at_index (tm->interfaces, p->dev_instance);
      if (tif->flags & VIRTIO_IF_FLAG_ADMIN_UP)
	{
	  if (tif->is_tun)
	    n_rx += tap_device_input_inline (vm, node, frame, tif, p->queue_id,
					     1 /* is_tun */);
	  else
	    n_rx += tap_device_input_inline (vm, node, frame, tif, p->queue_id,
					     0 /* is_tun */);
	}
    }

  return n_rx;
}

VLIB_REGISTER_NODE (tap_input_node) = {
  .name = "tap-virtio-input",
  .sibling_of = "device-input",
  .format_trace = format_tap_input_trace,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .n_errors = VIRTIO_INPUT_N_ERROR,
  .error_strings = tap_virtio_input_error_strings,
};
