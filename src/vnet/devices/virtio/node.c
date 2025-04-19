/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#ifdef __linux__
#include <linux/if_tun.h>
#elif __FreeBSD__
#include <net/if_tun.h>
#endif /* __linux */
#include <sys/ioctl.h>
#include <sys/eventfd.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/interface/rx_queue_funcs.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/devices/virtio/virtio.h>
#include <vnet/devices/virtio/virtio_inline.h>

static char *virtio_input_error_strings[] = {
#define _(n, s) s,
  foreach_virtio_input_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  u16 ring;
  u16 len;
  vnet_virtio_net_hdr_v1_t hdr;
} virtio_input_trace_t;

static u8 *
format_virtio_input_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  virtio_input_trace_t *t = va_arg (*args, virtio_input_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "virtio: hw_if_index %d next-index %d vring %u len %u",
	      t->hw_if_index, t->next_index, t->ring, t->len);
  s = format (s, "\n%Uhdr: flags 0x%02x gso_type 0x%02x hdr_len %u "
	      "gso_size %u csum_start %u csum_offset %u num_buffers %u",
	      format_white_space, indent + 2,
	      t->hdr.flags, t->hdr.gso_type, t->hdr.hdr_len, t->hdr.gso_size,
	      t->hdr.csum_start, t->hdr.csum_offset, t->hdr.num_buffers);
  return s;
}

static_always_inline void
virtio_needs_csum (vlib_buffer_t *b0, vnet_virtio_net_hdr_v1_t *hdr,
		   u8 *l4_proto, u8 *l4_hdr_sz, virtio_if_type_t type)
{
  if (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)
    {
      u16 ethertype = 0, l2hdr_sz = 0;
      vnet_buffer_oflags_t oflags = 0;

      if (type == VIRTIO_IF_TYPE_TUN)
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
	  b0->flags |= (VNET_BUFFER_F_IS_IP6 |
			VNET_BUFFER_F_L2_HDR_OFFSET_VALID
			| VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
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
virtio_n_left_to_process (vnet_virtio_vring_t *vring, const int packed)
{
  if (packed)
    return vring->desc_in_use;
  else
    return vring->used->idx - vring->last_used_idx;
}

static_always_inline u16
virtio_get_slot_id (vnet_virtio_vring_t *vring, const int packed, u16 last,
		    u16 mask)
{
  if (packed)
    return vring->packed_desc[last].id;
  else
    return vring->used->ring[last & mask].id;
}

static_always_inline u16
virtio_get_len (vnet_virtio_vring_t *vring, const int packed, const int hdr_sz,
		u16 last, u16 mask)
{
  if (packed)
    return vring->packed_desc[last].len - hdr_sz;
  else
    return vring->used->ring[last & mask].len - hdr_sz;
}

#define virtio_packed_check_n_left(vring, last)                               \
  do                                                                          \
    {                                                                         \
      vnet_virtio_vring_packed_desc_t *d = &vring->packed_desc[last];         \
      u16 flags = d->flags;                                                   \
      if ((flags & VRING_DESC_F_AVAIL) != (vring->used_wrap_counter << 7) ||  \
	  (flags & VRING_DESC_F_USED) != (vring->used_wrap_counter << 15))    \
	{                                                                     \
	  n_left = 0;                                                         \
	}                                                                     \
    }                                                                         \
  while (0)

#define increment_last(last, packed, vring)                                   \
  do                                                                          \
    {                                                                         \
      last++;                                                                 \
      if (packed && last >= vring->queue_size)                                \
	{                                                                     \
	  last = 0;                                                           \
	  vring->used_wrap_counter ^= 1;                                      \
	}                                                                     \
    }                                                                         \
  while (0)

static_always_inline void
virtio_device_input_ethernet (vlib_main_t *vm, vlib_node_runtime_t *node,
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
virtio_device_input_gso_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
				vlib_frame_t *frame, virtio_if_t *vif,
				vnet_virtio_vring_t *vring,
				virtio_if_type_t type, int gso_enabled,
				int checksum_offload_enabled, int packed)
{
  vnet_main_t *vnm = vnet_get_main ();
  clib_thread_index_t thread_index = vm->thread_index;
  uword n_trace = vlib_get_trace_count (vm, node);
  u32 next_index;
  const int hdr_sz = vif->virtio_net_hdr_sz;
  u32 *to_next = 0;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u16 mask = vring->queue_size - 1;
  u16 last = vring->last_used_idx;
  u16 n_left = virtio_n_left_to_process (vring, packed);
  vlib_buffer_t bt = {};

  if (packed)
    {
      virtio_packed_check_n_left (vring, last);
    }

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

  if (type == VIRTIO_IF_TYPE_TUN)
    {
      next_index = VNET_DEVICE_INPUT_NEXT_IP4_INPUT;
    }
  else
    {
      next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
      if (PREDICT_FALSE (vif->per_interface_next_index != ~0))
	next_index = vif->per_interface_next_index;

      /* only for l2, redirect if feature path enabled */
      vnet_feature_start_device_input (vif->sw_if_index, &next_index, &bt);
    }

  while (n_left)
    {
      u32 n_left_to_next;
      u32 next0 = next_index;

      vlib_get_new_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left && n_left_to_next)
	{
	  if (packed)
	    {
	      vnet_virtio_vring_packed_desc_t *d = &vring->packed_desc[last];
	      u16 flags = d->flags;
	      if ((flags & VRING_DESC_F_AVAIL) !=
		  (vring->used_wrap_counter << 7)
		  || (flags & VRING_DESC_F_USED) !=
		  (vring->used_wrap_counter << 15))
		{
		  n_left = 0;
		  break;
		}
	    }
	  u8 l4_proto = 0, l4_hdr_sz = 0;
	  u16 num_buffers = 1;
	  vnet_virtio_net_hdr_v1_t *hdr;
	  u16 slot = virtio_get_slot_id (vring, packed, last, mask);
	  u16 len = virtio_get_len (vring, packed, hdr_sz, last, mask);
	  u32 bi0 = vring->buffers[slot];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  hdr = vlib_buffer_get_current (b0);
	  if (hdr_sz == sizeof (vnet_virtio_net_hdr_v1_t))
	    num_buffers = hdr->num_buffers;

	  b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;
	  b0->current_data = 0;
	  b0->current_length = len;

	  if (checksum_offload_enabled)
	    virtio_needs_csum (b0, hdr, &l4_proto, &l4_hdr_sz, type);

	  if (gso_enabled)
	    fill_gso_buffer_flags (b0, hdr, l4_proto, l4_hdr_sz);

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = vif->sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  /* if multisegment packet */
	  if (PREDICT_FALSE (num_buffers > 1))
	    {
	      vlib_buffer_t *pb, *cb;
	      pb = b0;
	      b0->total_length_not_including_first_buffer = 0;
	      while (num_buffers > 1)
		{
		  increment_last (last, packed, vring);
		  u16 cslot = virtio_get_slot_id (vring, packed, last, mask);
		  /* hdr size is 0 after 1st packet in chain buffers */
		  u16 clen = virtio_get_len (vring, packed, 0, last, mask);
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

	  if (type == VIRTIO_IF_TYPE_TUN)
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

	      if (PREDICT_FALSE (vif->per_interface_next_index != ~0))
		next0 = vif->per_interface_next_index;
	    }
	  else
	    {
	      /* copy feature arc data from template */
	      b0->current_config_index = bt.current_config_index;
	      vnet_buffer (b0)->feature_arc_index =
		vnet_buffer (&bt)->feature_arc_index;
	    }

	  /* trace */
	  if (PREDICT_FALSE (n_trace > 0 && vlib_trace_buffer (vm, node, next0, b0,	/* follow_chain */
							       1)))
	    {
	      virtio_input_trace_t *tr;
	      vlib_set_trace_count (vm, node, --n_trace);
	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->hw_if_index = vif->hw_if_index;
	      tr->len = len;
	      clib_memcpy_fast (&tr->hdr, hdr, (hdr_sz == 12) ? 12 : 10);
	    }

	  /* enqueue buffer */
	  to_next[0] = bi0;
	  vring->desc_in_use--;
	  to_next += 1;
	  n_left_to_next--;
	  n_left--;
	  increment_last (last, packed, vring);

	  /* only tun interfaces may have different next index */
	  if (type == VIRTIO_IF_TYPE_TUN)
	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					     n_left_to_next, bi0, next0);

	  /* next packet */
	  n_rx_packets++;
	  n_rx_bytes += len;
	}
      virtio_device_input_ethernet (vm, node, next_index, vif->sw_if_index,
				    vif->hw_if_index);
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vring->last_used_idx = last;

  vring->total_packets += n_rx_packets;
  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX, thread_index,
				   vif->sw_if_index, n_rx_packets,
				   n_rx_bytes);

  return n_rx_packets;
}

static_always_inline uword
virtio_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame, virtio_if_t * vif, u16 qid,
			    virtio_if_type_t type)
{
  vnet_virtio_vring_t *vring = vec_elt_at_index (vif->rxq_vrings, qid);
  const int hdr_sz = vif->virtio_net_hdr_sz;
  uword rv;

  if (vif->is_packed)
    {
      if (vif->gso_enabled)
	rv =
	  virtio_device_input_gso_inline (vm, node, frame, vif, vring, type,
					  1, 1, 1);
      else if (vif->csum_offload_enabled)
	rv =
	  virtio_device_input_gso_inline (vm, node, frame, vif, vring, type,
					  0, 1, 1);
      else
	rv =
	  virtio_device_input_gso_inline (vm, node, frame, vif, vring, type,
					  0, 0, 1);

      virtio_refill_vring_packed (vm, vif, type, vring, hdr_sz,
				  node->node_index);
    }
  else
    {
      if (vif->gso_enabled)
	rv =
	  virtio_device_input_gso_inline (vm, node, frame, vif, vring, type,
					  1, 1, 0);
      else if (vif->csum_offload_enabled)
	rv =
	  virtio_device_input_gso_inline (vm, node, frame, vif, vring, type,
					  0, 1, 0);
      else
	rv =
	  virtio_device_input_gso_inline (vm, node, frame, vif, vring, type,
					  0, 0, 0);

      virtio_refill_vring_split (vm, vif, type, vring, hdr_sz,
				 node->node_index);
    }
  return rv;
}

VLIB_NODE_FN (virtio_input_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_rx = 0;
  virtio_main_t *vim = &virtio_main;
  vnet_hw_if_rxq_poll_vector_t *p,
    *pv = vnet_hw_if_get_rxq_poll_vector (vm, node);

  vec_foreach (p, pv)
    {
      virtio_if_t *vif;
      vif = vec_elt_at_index (vim->interfaces, p->dev_instance);
      if (vif->flags & VIRTIO_IF_FLAG_ADMIN_UP)
	{
	  if (vif->type == VIRTIO_IF_TYPE_TAP)
	    n_rx += virtio_device_input_inline (
	      vm, node, frame, vif, p->queue_id, VIRTIO_IF_TYPE_TAP);
	  else if (vif->type == VIRTIO_IF_TYPE_PCI)
	    n_rx += virtio_device_input_inline (
	      vm, node, frame, vif, p->queue_id, VIRTIO_IF_TYPE_PCI);
	  else if (vif->type == VIRTIO_IF_TYPE_TUN)
	    n_rx += virtio_device_input_inline (
	      vm, node, frame, vif, p->queue_id, VIRTIO_IF_TYPE_TUN);
	}
    }

  return n_rx;
}

VLIB_REGISTER_NODE (virtio_input_node) = {
  .name = "virtio-input",
  .sibling_of = "device-input",
  .format_trace = format_virtio_input_trace,
  .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .n_errors = VIRTIO_INPUT_N_ERROR,
  .error_strings = virtio_input_error_strings,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
