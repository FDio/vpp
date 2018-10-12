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
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <linux/virtio_net.h>
#include <linux/vhost.h>
#include <sys/eventfd.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/devices/devices.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/devices/virtio/virtio.h>


#define foreach_virtio_input_error \
  _(UNKNOWN, "unknown") \
  _(UNKNOWN_GSO_TYPE, "unknown GSO type")

typedef enum
{
#define _(f,s) TAP_INPUT_ERROR_##f,
  foreach_virtio_input_error
#undef _
    TAP_INPUT_N_ERROR,
} virtio_input_error_t;

static char *virtio_input_error_strings[] = {
#define _(n,s) s,
  foreach_virtio_input_error
#undef _
};

typedef struct
{
  u32 next_index;
  u32 hw_if_index;
  u16 ring;
  u16 len;
  struct virtio_net_hdr_v1 hdr;
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
virtio_refill_vring (vlib_main_t * vm, virtio_vring_t * vring)
{
  const int hdr_sz = sizeof (struct virtio_net_hdr_v1);
  u16 used, next, avail, n_slots;
  u16 sz = vring->size;
  u16 mask = sz - 1;

more:
  used = vring->desc_in_use;

  if (sz - used < sz / 8)
    return;

  /* deliver free buffers in chunks of 64 */
  n_slots = clib_min (sz - used, 64);

  next = vring->desc_next;
  avail = vring->avail->idx;
  n_slots = vlib_buffer_alloc_to_ring (vm, vring->buffers, next, vring->size,
				       n_slots);

  if (n_slots == 0)
    return;

  while (n_slots)
    {
      struct vring_desc *d = &vring->desc[next];;
      vlib_buffer_t *b = vlib_get_buffer (vm, vring->buffers[next]);
      b->error = 0;
      d->addr = pointer_to_uword (vlib_buffer_get_current (b)) - hdr_sz;
      d->len = VLIB_BUFFER_DATA_SIZE + hdr_sz;
      d->flags = VRING_DESC_F_WRITE;
      vring->avail->ring[avail & mask] = next;
      avail++;
      next = (next + 1) & mask;
      n_slots--;
      used++;
    }
  CLIB_MEMORY_STORE_BARRIER ();
  vring->avail->idx = avail;
  vring->desc_next = next;
  vring->desc_in_use = used;

  if ((vring->used->flags & VIRTIO_RING_FLAG_MASK_INT) == 0)
    virtio_kick (vring);
  goto more;
}

static_always_inline void
fill_gso_buffer_flags (vlib_buffer_t * b0, struct virtio_net_hdr_v1 *hdr)
{
  u8 l4_proto = 0;
  u8 l4_hdr_sz = 0;
  if (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM)

    {
      ethernet_header_t *eh = (ethernet_header_t *) b0->data;
      u16 ethertype = clib_net_to_host_u16 (eh->type);
      u16 l2hdr_sz = sizeof (ethernet_header_t);

      vnet_buffer (b0)->l2_hdr_offset = 0;
      vnet_buffer (b0)->l3_hdr_offset = l2hdr_sz;
      if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP4))
	{
	  ip4_header_t *ip4 = (ip4_header_t *) (b0->data + l2hdr_sz);
	  vnet_buffer (b0)->l4_hdr_offset = l2hdr_sz + ip4_header_bytes (ip4);
	  l4_proto = ip4->protocol;
	  b0->flags |=
	    (VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID
	     | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	     VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
	  b0->flags |= VNET_BUFFER_F_OFFLOAD_IP_CKSUM;
	}
      else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
	{
	  ip6_header_t *ip6 = (ip6_header_t *) (b0->data + l2hdr_sz);
	  /* FIXME IPv6 EH traversal */
	  vnet_buffer (b0)->l4_hdr_offset = l2hdr_sz + sizeof (ip6_header_t);
	  l4_proto = ip6->protocol;
	  b0->flags |=
	    (VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L2_HDR_OFFSET_VALID
	     | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	     VNET_BUFFER_F_L4_HDR_OFFSET_VALID);
	  b0->flags |= VNET_BUFFER_F_OFFLOAD_IP_CKSUM;
	}
      if (l4_proto == IP_PROTOCOL_TCP)
	{
	  b0->flags |= VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
	  tcp_header_t *tcp = (tcp_header_t *) (b0->data +
						vnet_buffer
						(b0)->l4_hdr_offset);
	  l4_hdr_sz = tcp_header_bytes (tcp);
	  tcp->checksum = 0;
	}
      else if (l4_proto == IP_PROTOCOL_UDP)
	{
	  b0->flags |= VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
	  udp_header_t *udp = (udp_header_t *) (b0->data +
						vnet_buffer
						(b0)->l4_hdr_offset);
	  l4_hdr_sz = sizeof (*udp);
	  udp->checksum = 0;
	}
    }

  if (hdr->gso_type == VIRTIO_NET_HDR_GSO_TCPV4)
    {
      ASSERT (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM);
      vnet_buffer2 (b0)->gso_size = hdr->gso_size;
      vnet_buffer2 (b0)->gso_l4_hdr_sz = l4_hdr_sz;
      vnet_buffer2 (b0)->gso_l4_proto = l4_proto;
      b0->flags |= VNET_BUFFER_F_GSO;
      b0->flags |= VNET_BUFFER_F_IS_IP4;
    }
  if (hdr->gso_type == VIRTIO_NET_HDR_GSO_TCPV6)
    {
      ASSERT (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM);
      vnet_buffer2 (b0)->gso_size = hdr->gso_size;
      vnet_buffer2 (b0)->gso_l4_hdr_sz = l4_hdr_sz;
      vnet_buffer2 (b0)->gso_l4_proto = l4_proto;
      b0->flags |= VNET_BUFFER_F_GSO;
      b0->flags |= VNET_BUFFER_F_IS_IP6;
    }
}


static_always_inline uword
virtio_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame, virtio_if_t * vif, u16 qid,
			    int gso_enabled)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 thread_index = vm->thread_index;
  uword n_trace = vlib_get_trace_count (vm, node);
  virtio_vring_t *vring = vec_elt_at_index (vif->vrings, 0);
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  const int hdr_sz = sizeof (struct virtio_net_hdr_v1);
  u32 *to_next = 0;
  u32 n_rx_packets = 0;
  u32 n_rx_bytes = 0;
  u16 mask = vring->size - 1;
  u16 last = vring->last_used_idx;
  u16 n_left = vring->used->idx - last;

  if ((vring->used->flags & VIRTIO_RING_FLAG_MASK_INT) == 0 &&
      vring->last_kick_avail_idx != vring->avail->idx)
    virtio_kick (vring);

  if (n_left == 0)
    goto refill;

  while (n_left)
    {
      u32 n_left_to_next;
      u32 next0 = next_index;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left && n_left_to_next)
	{
	  u16 num_buffers;
	  struct vring_used_elem *e = &vring->used->ring[last & mask];
	  struct virtio_net_hdr_v1 *hdr;
	  u16 slot = e->id;
	  u16 len = e->len - hdr_sz;
	  u32 bi0 = vring->buffers[slot];
	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
	  hdr = vlib_buffer_get_current (b0) - hdr_sz;
	  num_buffers = hdr->num_buffers;

	  b0->current_data = 0;
	  b0->current_length = len;
	  b0->total_length_not_including_first_buffer = 0;
	  b0->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID;

	  if (gso_enabled)
	    fill_gso_buffer_flags (b0, hdr);

	  vnet_buffer (b0)->sw_if_index[VLIB_RX] = vif->sw_if_index;
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = (u32) ~ 0;

	  /* if multisegment packet */
	  if (PREDICT_FALSE (num_buffers > 1))
	    {
	      vlib_buffer_t *pb, *cb;
	      pb = b0;
	      while (num_buffers > 1)
		{
		  last++;
		  e = &vring->used->ring[last & mask];
		  u32 cbi = vring->buffers[e->id];
		  cb = vlib_get_buffer (vm, cbi);

		  /* current buffer */
		  cb->current_data = -hdr_sz;
		  cb->current_length = e->len;

		  /* previous buffer */
		  pb->next_buffer = cbi;
		  pb->flags |= VLIB_BUFFER_NEXT_PRESENT;

		  /* first buffer */
		  b0->total_length_not_including_first_buffer += e->len;

		  pb = cb;
		  vring->desc_in_use--;
		  num_buffers--;
		  n_left--;
		}
	    }

	  if (PREDICT_FALSE (vif->per_interface_next_index != ~0))
	    next0 = vif->per_interface_next_index;
	  else
	    /* redirect if feature path enabled */
	    vnet_feature_start_device_input_x1 (vif->sw_if_index, &next0, b0);
	  /* trace */
	  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

	  if (PREDICT_FALSE (n_trace > 0))
	    {
	      virtio_input_trace_t *tr;
	      vlib_trace_buffer (vm, node, next0, b0,
				 /* follow_chain */ 0);
	      vlib_set_trace_count (vm, node, --n_trace);
	      tr = vlib_add_trace (vm, node, b0, sizeof (*tr));
	      tr->next_index = next0;
	      tr->hw_if_index = vif->hw_if_index;
	      tr->len = len;
	      clib_memcpy_fast (&tr->hdr, hdr, hdr_sz);
	    }

	  /* enqueue buffer */
	  to_next[0] = bi0;
	  vring->desc_in_use--;
	  to_next += 1;
	  n_left_to_next--;
	  n_left--;
	  last++;

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	  /* next packet */
	  n_rx_packets++;
	  n_rx_bytes += len;
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vring->last_used_idx = last;

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX, thread_index,
				   vif->hw_if_index, n_rx_packets,
				   n_rx_bytes);
refill:
  virtio_refill_vring (vm, vring);

  return n_rx_packets;
}

static uword
virtio_input_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
		 vlib_frame_t * frame)
{
  u32 n_rx = 0;
  virtio_main_t *nm = &virtio_main;
  vnet_device_input_runtime_t *rt = (void *) node->runtime_data;
  vnet_device_and_queue_t *dq;

  foreach_device_and_queue (dq, rt->devices_and_queues)
  {
    virtio_if_t *mif;
    mif = vec_elt_at_index (nm->interfaces, dq->dev_instance);
    if (mif->flags & VIRTIO_IF_FLAG_ADMIN_UP)
      {
	if (mif->gso_enabled)
	  n_rx += virtio_device_input_inline (vm, node, frame, mif,
					      dq->queue_id, 1);
	else
	  n_rx += virtio_device_input_inline (vm, node, frame, mif,
					      dq->queue_id, 0);
      }
  }

  return n_rx;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (virtio_input_node) = {
  .function = virtio_input_fn,
  .name = "virtio-input",
  .sibling_of = "device-input",
  .format_trace = format_virtio_input_trace,
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
  .n_errors = TAP_INPUT_N_ERROR,
  .error_strings = virtio_input_error_strings,
};

VLIB_NODE_FUNCTION_MULTIARCH (virtio_input_node, virtio_input_fn)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
