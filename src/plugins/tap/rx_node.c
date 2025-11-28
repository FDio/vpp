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

#define foreach_tap_rx_error                                                  \
  _ (BUFFER_ALLOC, "buffer alloc error")                                      \
  _ (FULL_RX_QUEUE, "full rx queue (driver tx drop)")

typedef enum
{
#define _(f, s) TAP_RX_ERROR_##f,
  foreach_tap_rx_error
#undef _
    TAP_RX_N_ERROR,
} tap_rx_error_t;

static_always_inline void
tap_refill_vring (vlib_main_t *vm, tap_rxq_t *rxq, u32 node_index, int is_tun)
{
  u16 used, next, avail, n_slots, n_refill;
  u16 sz = rxq->queue_size;
  u16 mask = sz - 1;
  u8 off = is_tun ? TUN_DATA_OFFSET : 0;
  vnet_virtio_vring_desc_t dt = {
    .len = vlib_buffer_get_default_data_size (vm) + VIRTIO_NET_HDR_SZ - off,
    .flags = VRING_DESC_F_WRITE,
  };

more:
  used = rxq->desc_in_use;

  if (sz - used < sz / 8)
    return;

  /* deliver free buffers in chunks of 64 */
  n_refill = clib_min (sz - used, 64);

  next = rxq->desc_next;
  avail = rxq->avail->idx;
  n_slots = vlib_buffer_alloc_to_ring_from_pool (
    vm, rxq->buffers, next, rxq->queue_size, n_refill, rxq->buffer_pool_index);

  if (PREDICT_FALSE (n_slots != n_refill))
    {
      vlib_error_count (vm, node_index, TAP_RX_ERROR_BUFFER_ALLOC,
			n_refill - n_slots);
      if (n_slots == 0)
	return;
    }

  while (n_slots)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, rxq->buffers[next]);
      dt.addr = pointer_to_uword (b->data - VIRTIO_NET_HDR_SZ + off);
      rxq->desc[next] = dt;
      rxq->avail->ring[avail & mask] = next;
      avail++;
      next = (next + 1) & mask;
      n_slots--;
      used++;
    }
  rxq->desc_next = next;
  rxq->desc_in_use = used;
  __atomic_store_n (&rxq->avail->idx, avail, __ATOMIC_RELEASE);
  if ((__atomic_load_n (&rxq->used->flags, __ATOMIC_ACQUIRE) &
       VRING_USED_F_NO_NOTIFY) == 0)
    {
      ssize_t __clib_unused rv;
      rv = write (rxq->kick_fd, &(u64){ 1 }, sizeof (u64));
    }
  goto more;
}

static char *tap_input_error_strings[] = {
#define _(n, s) s,
  foreach_tap_rx_error
#undef _
};

static_always_inline void
tap_rx_offloads (vlib_buffer_t *b0, vnet_virtio_net_hdr_v1_t *hdr, int is_tun)
{
  u8 l4_proto = 0, l4_hdr_sz, type;
  u16 ethertype = 0, l2hdr_sz = 0;
  vnet_buffer_oflags_t oflags = 0;
  u8 off = is_tun ? TUN_DATA_OFFSET : 0;
  u8 *data = b0->data;

  if (PREDICT_TRUE (!(hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)))
    return;

  if (is_tun)
    {
      l2hdr_sz = off;

      switch (data[off] & 0xf0)
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
      ethernet_header_t *eh = (ethernet_header_t *) (data + off);
      ethertype = clib_net_to_host_u16 (eh->type);
      l2hdr_sz = sizeof (ethernet_header_t);

      if (ethernet_frame_is_tagged (ethertype))
	{
	  ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) (eh + 1);

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

  vnet_buffer (b0)->l2_hdr_offset = off;
  vnet_buffer (b0)->l3_hdr_offset = l2hdr_sz;

  if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP4))
    {
      ip4_header_t *ip4 = (ip4_header_t *) (data + l2hdr_sz);
      vnet_buffer (b0)->l4_hdr_offset = l2hdr_sz + ip4_header_bytes (ip4);
      l4_proto = ip4->protocol;
      oflags |= VNET_BUFFER_OFFLOAD_F_IP_CKSUM;
      b0->flags |= (VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
		    VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		    VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
    }
  else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
    {
      ip6_header_t *ip6 = (ip6_header_t *) (data + l2hdr_sz);
      vnet_buffer (b0)->l4_hdr_offset = l2hdr_sz + sizeof (ip6_header_t);
      /* FIXME IPv6 EH traversal */
      l4_proto = ip6->protocol;
      b0->flags |= (VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
		    VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		    VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
    }
  if (l4_proto == IP_PROTOCOL_TCP)
    {
      oflags |= VNET_BUFFER_OFFLOAD_F_TCP_CKSUM;
      tcp_header_t *tcp =
	(tcp_header_t *) (b0->data + vnet_buffer (b0)->l4_hdr_offset);
      l4_hdr_sz = tcp_header_bytes (tcp);
    }
  else if (l4_proto == IP_PROTOCOL_UDP)
    {
      oflags |= VNET_BUFFER_OFFLOAD_F_UDP_CKSUM;
      l4_hdr_sz = sizeof (udp_header_t);
    }
  if (oflags)
    vnet_buffer_offload_flags_set (b0, oflags);

  type = hdr->gso_type;

  if (type & (VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_TCPV6))
    {
      ASSERT (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM);
      vnet_buffer2 (b0)->gso_size = hdr->gso_size;
      vnet_buffer2 (b0)->gso_l4_hdr_sz = l4_hdr_sz;
      b0->flags |= VNET_BUFFER_F_GSO |
		   (type & VIRTIO_NET_HDR_GSO_TCPV4 ? VNET_BUFFER_F_IS_IP4 :
						      VNET_BUFFER_F_IS_IP6);
    }
}

static_always_inline uword
tap_rx_dequeue (vlib_main_t *vm, vlib_node_runtime_t *node, tap_if_t *tif,
		tap_rxq_t *rxq, u32 *buffers, u16 *nexts, u32 *n_rx_bytes,
		int is_tun)
{
  const int hdr_sz = VIRTIO_NET_HDR_SZ;
  u32 n_rx_packets = 0;
  u16 n_left, mask, last = rxq->last_used_idx;
  vlib_buffer_template_t bt;
  u8 off = is_tun ? TUN_DATA_OFFSET : 0;
  vnet_virtio_vring_used_elem_t *ring = rxq->used->ring;
  u32 *ring_buffers = rxq->buffers;

  n_left = __atomic_load_n (&rxq->used->idx, __ATOMIC_ACQUIRE) - last;

  if (n_left == 0)
    return 0;

  mask = rxq->queue_size - 1;
  bt = tif->buffer_template;

  /* Informational error logging when VPP is not pulling packets fast enough */
  if (PREDICT_FALSE (n_left == rxq->queue_size))
    vlib_error_count (vm, node->node_index, TAP_RX_ERROR_FULL_RX_QUEUE, 1);

  while (n_left && n_rx_packets < VLIB_FRAME_SIZE)
    {
      vnet_virtio_vring_used_elem_t *e = ring + (last & mask);
      u32 bi0 = ring_buffers[e->id];
      u16 len = e->len - hdr_sz;
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      vnet_virtio_net_hdr_v1_t *hdr;
      u16 num_buffers;

      hdr = (vnet_virtio_net_hdr_v1_t *) (b0->data + off - hdr_sz);
      num_buffers = hdr->num_buffers;
      b0->template = bt;
      b0->current_length = len;

      tap_rx_offloads (b0, hdr, is_tun);

      /* if multisegment packet */
      if (PREDICT_FALSE (num_buffers > 1))
	{
	  vlib_buffer_t *pb, *cb;
	  pb = b0;
	  u32 tlnifb = 0;
	  while (num_buffers > 1)
	    {
	      last++;
	      e = &ring[last & mask];
	      u32 cbi = ring_buffers[e->id];
	      u16 clen = e->len;
	      cb = vlib_get_buffer (vm, cbi);

	      /* current buffer */
	      cb->current_length = clen;

	      /* previous buffer */
	      pb->next_buffer = cbi;
	      pb->flags |= VLIB_BUFFER_NEXT_PRESENT;

	      /* first buffer */
	      tlnifb += clen;

	      pb = cb;
	      rxq->desc_in_use--;
	      num_buffers--;
	      n_left--;
	    }
	  b0->total_length_not_including_first_buffer = tlnifb;
	  len += tlnifb;
	}

      if (is_tun)
	nexts[n_rx_packets] = b0->data[off];

      buffers[n_rx_packets] = bi0;
      rxq->desc_in_use--;
      n_left--;
      last++;

      n_rx_packets++;
      *n_rx_bytes += len;
    }

  rxq->last_used_idx = last;

  rxq->total_packets += n_rx_packets;

  return n_rx_packets;
}

static_always_inline uword
tap_device_input_one_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			     tap_if_t *tif, u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  tap_rxq_t *rxq = tap_get_rx_queue (tif, qid);
  u32 buffer_indices[VLIB_FRAME_SIZE];
  u16 next_indices[VLIB_FRAME_SIZE];
  u32 n_rx_bytes = 0;
  uword n_trace;
  uword n_rx;
  u32 next_index = tif->next_index;
  u8 is_tun = tif->is_tun;

  if (is_tun)
    {
      n_rx = tap_rx_dequeue (vm, node, tif, rxq, buffer_indices, next_indices,
			     &n_rx_bytes, 1);
      /* next_indices contains 1st byte of packet, convert it to next_index */
      for (u32 i = 0; i < n_rx; i += 8)
	{
	  u16x8 r, m4, m6;
	  r = *(u16x8u *) (next_indices + i) >> 4;
	  m4 = r == u16x8_splat (4);
	  m6 = r == u16x8_splat (6);
	  r = ~(m4 & m6) & u16x8_splat (VNET_DEVICE_INPUT_NEXT_DROP);
	  r |= m4 & u16x8_splat (VNET_DEVICE_INPUT_NEXT_IP4_INPUT);
	  r |= m6 & u16x8_splat (VNET_DEVICE_INPUT_NEXT_IP6_INPUT);
	  *(u16x8u *) (next_indices + i) = r;
	}
    }
  else
    {
      n_rx = tap_rx_dequeue (vm, node, tif, rxq, buffer_indices, next_indices,
			     &n_rx_bytes, 0);
    }

  vlib_increment_combined_counter (
    vnm->interface_main.combined_sw_if_counters + VNET_INTERFACE_COUNTER_RX,
    vm->thread_index, tif->sw_if_index, n_rx, n_rx_bytes);

  n_trace = vlib_get_trace_count (vm, node);
  if (n_trace > 0)
    {
      u8 off = tif->is_tun ? TUN_DATA_OFFSET : 0;
      for (u32 i = 0; n_trace > 0 && i < n_rx; i++)
	{
	  vlib_buffer_t *b = vlib_get_buffer (vm, buffer_indices[i]);
	  if (vlib_trace_buffer (vm, node, next_indices[i], b,
				 /* follow_chain */ 0))
	    {
	      tap_rx_trace_t *tr;
	      tr = vlib_add_trace (vm, node, b, sizeof (*tr));
	      tr->next_index = is_tun ? next_indices[i] : next_index;
	      tr->hw_if_index = tif->hw_if_index;
	      tr->len = b->current_length;
	      tr->hdr = ((vnet_virtio_net_hdr_v1_t *) (b->data + off))[-1];
	      n_trace--;
	    }
	}
      vlib_set_trace_count (vm, node, n_trace);
    }

  if (is_tun)
    {
      vlib_buffer_enqueue_to_next (vm, node, buffer_indices, next_indices,
				   n_rx);
      tap_refill_vring (vm, rxq, node->node_index, 1);
    }
  else
    {
      if (n_rx)
	{
	  u32 *to_next, n_left_to_next;
	  vlib_get_new_next_frame (vm, node, tif->next_index, to_next,
				   n_left_to_next);

	  ASSERT (n_rx <= n_left_to_next);

	  vlib_buffer_copy_indices (to_next, buffer_indices, n_rx);

	  if (PREDICT_TRUE (next_index ==
			    VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT))
	    {
	      vlib_next_frame_t *nf;
	      vlib_frame_t *f;
	      ethernet_input_frame_t *ef;
	      nf = vlib_node_runtime_get_next_frame (vm, node, next_index);
	      f = vlib_get_frame (vm, nf->frame);
	      f->flags |= ETH_INPUT_FRAME_F_SINGLE_SW_IF_IDX;

	      ef = vlib_frame_scalar_args (f);
	      ef->sw_if_index = tif->sw_if_index;
	      ef->hw_if_index = tif->hw_if_index;
	      vlib_frame_no_append (f);
	    }

	  n_left_to_next -= n_rx;
	  vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	}
      tap_refill_vring (vm, rxq, node->node_index, 0);
    }

  return n_rx;
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
      tap_if_t *tif = pool_elt_at_index (tm->interfaces, p->dev_instance);
      if (tif->admin_up)
	n_rx += tap_device_input_one_inline (vm, node, tif, p->queue_id);
    }

  return n_rx;
}

VLIB_REGISTER_NODE (tap_input_node) = {
  .name = "tap-input",
  .sibling_of = "device-input",
  .format_trace = format_tap_input_trace,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .n_errors = TAP_RX_N_ERROR,
  .error_strings = tap_input_error_strings,
};
