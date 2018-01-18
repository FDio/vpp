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
  vlib_buffer_t b;
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
  s = format (s, "\n%Ubuffer: %U",
	      format_white_space, indent + 2, format_vnet_buffer, &t->b);
  return s;
}

static_always_inline void
virtio_refill_vring (vlib_main_t * vm, virtio_vring_t * vring)
{
  const int hdr_sz = sizeof (struct virtio_net_hdr_v1);
  u16 used, next, avail, n_slots;
  u16 sz = vring->size;
  u16 mask = sz - 1;

  used = vring->desc_in_use;

  if (sz - used < sz / 8)
    return;

  n_slots = sz - used;
  next = vring->desc_next;
  avail = vring->avail->idx;
  n_slots = vlib_buffer_alloc_to_ring (vm, vring->buffers, next, vring->size,
				       n_slots);

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
    {
      u64 b = 1;
      CLIB_UNUSED (int r) = write (vring->kick_fd, &b, sizeof (b));
    }
}

static_always_inline void
fill_metadata (vlib_buffer_t * b, u32 sw_if_index, u16 l2_hdr_sz,
	       u16 l3_hdr_sz, u32 flags)
{
  b->current_data = 0;
  b->total_length_not_including_first_buffer = 0;
  b->flags = VLIB_BUFFER_TOTAL_LENGTH_VALID |
    VNET_BUFFER_F_L2_HDR_OFFSET_VALID | flags;
  vnet_buffer (b)->sw_if_index[VLIB_RX] = sw_if_index;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = (u32) ~ 0;
  vnet_buffer (b)->l2_hdr_offset = 0;
  if (VNET_BUFFER_F_L3_HDR_OFFSET_VALID)
    vnet_buffer (b)->l3_hdr_offset = l2_hdr_sz;
  if (VNET_BUFFER_F_L4_HDR_OFFSET_VALID)
    vnet_buffer (b)->l4_hdr_offset = l2_hdr_sz + l3_hdr_sz;
}

#define _DBG(fmt, _args...) \
  fformat (stderr, "%u: " fmt "\n", vif->dev_instance, _args);

static_always_inline u16
gso_none (vlib_main_t * vm, virtio_if_t * vif, virtio_per_thread_data_t * ptd,
	  u32 bi, vlib_buffer_t * b, virtio_vring_t * vring, u16 last,
	  u16 mask)
{
  u16 slots_used = 1;
  u16 num_buffers;
  const int hdr_sz = sizeof (struct virtio_net_hdr_v1);
  struct vring_used_elem *e = &vring->used->ring[last & mask];
  struct virtio_net_hdr_v1 *hdr = vlib_buffer_get_current (b) - hdr_sz;
  u16 len = e->len - hdr_sz;
  int is_bad = 0;

  fill_metadata (b, vif->sw_if_index, 0, 0, 0);
  b->current_length = len;

  if (hdr->gso_type == VIRTIO_NET_HDR_GSO_TCPV4)
    {
      vnet_buffer (b)->gso_size = hdr->gso_size;
      b->flags |= VNET_BUFFER_F_GSO;
      //fformat (stderr, "\n%U\n", format_hexdump, hdr, 14);
    }

  num_buffers = hdr->num_buffers;
  /* if multisegment packet */
  if (PREDICT_FALSE (num_buffers > 1))
    {
      vlib_buffer_t *pb, *cb;
      pb = b;
      while (num_buffers-- > 1)
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
	  b->total_length_not_including_first_buffer += e->len;

	  pb = cb;
	  slots_used++;
	}
    }

if ((hdr->gso_type != VIRTIO_NET_HDR_GSO_TCPV4) &&
   (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM))
    {
      ethernet_header_t *eh = (ethernet_header_t *) b->data;
      u16 ethertype = clib_net_to_host_u16 (eh->type);
      u16 l2hdr_sz = sizeof (ethernet_header_t);

      if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP4))
	{
	  ip4_header_t *ip4 = (ip4_header_t *) (b->data + l2hdr_sz);
	  vnet_buffer (b)->l2_hdr_offset = 0;
	  vnet_buffer (b)->l3_hdr_offset = l2hdr_sz;
	  vnet_buffer (b)->l4_hdr_offset = l2hdr_sz + ip4_header_bytes (ip4);
	  b->flags |= (VNET_BUFFER_F_IS_IP4 |
		       VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
		       VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		       VNET_BUFFER_F_L4_HDR_OFFSET_VALID);

	  if (ip4->protocol == IP_PROTOCOL_TCP)
	    b->flags |= VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
	  else if (ip4->protocol == IP_PROTOCOL_UDP)
	    b->flags |= VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
	  else
	    is_bad = 1;
	}
      else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
	{
	  ip6_header_t *ip6 = (ip6_header_t *) (b->data + l2hdr_sz);
	  vnet_buffer (b)->l2_hdr_offset = 0;
	  vnet_buffer (b)->l3_hdr_offset = l2hdr_sz;
	  vnet_buffer (b)->l4_hdr_offset = l2hdr_sz + sizeof (ip6_header_t);
	  b->flags |= (VNET_BUFFER_F_IS_IP6 |
		       VNET_BUFFER_F_L2_HDR_OFFSET_VALID |
		       VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		       VNET_BUFFER_F_L4_HDR_OFFSET_VALID);

	  if (ip6->protocol == IP_PROTOCOL_TCP)
	    b->flags |= VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
	  else if (ip6->protocol == IP_PROTOCOL_UDP)
	    b->flags |= VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
	  else
	    is_bad = 1;
	}
      else
	is_bad = 1;
      if (b->flags & VNET_BUFFER_F_OFFLOAD_TCP_CKSUM)
	{
	  tcp_header_t *tcp = (tcp_header_t *) (b->data +
						vnet_buffer
						(b)->l4_hdr_offset);
	  tcp->checksum = 0;
	}
      else if (b->flags & VNET_BUFFER_F_OFFLOAD_UDP_CKSUM)
	{
	  udp_header_t *udp = (udp_header_t *) (b->data +
						vnet_buffer
						(b)->l4_hdr_offset);
	  udp->checksum = 0;
	}
    }
  if (is_bad)
    {
      vlib_buffer_free (vm, &bi, 1);
      /*FIXME counter */
    }
  else
    {
      vec_add1 (ptd->buffers, bi);
      ptd->n_rx_bytes += len;
    }
  return slots_used;
}

typedef enum
{
  GSO_TCP4,
  GSO_TCP6,
  GSO_UDP
} gso_type_t;

static_always_inline u16
gso (vlib_main_t * vm, virtio_if_t * vif, virtio_per_thread_data_t * ptd,
     u32 bi, vlib_buffer_t * b, virtio_vring_t * vring, u16 last, u16 mask,
     gso_type_t type)
{
  const int hdr_sz = sizeof (struct virtio_net_hdr_v1);
  struct virtio_net_hdr_v1 *hdr = vlib_buffer_get_current (b) - hdr_sz;
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  tcp_header_t *tcp;
  udp_header_t *udp;
  u32 seq;
  vlib_buffer_t *db = b, *sb;
  struct vring_used_elem *e = &vring->used->ring[last++ & mask];
  u32 *bufs;
  u8 *src_ptr, *dst_ptr;
  u16 src_left, dst_left, n_from, l2hdr_sz, l3hdr_sz, l4hdr_sz,
    ip_len, temp_sz, fid, tcp_flags, new_payload_sz, payload;
  int is_ip4;
  int is_tcp = (type == GSO_TCP4 || type == GSO_TCP6);
  int is_udp = (type == GSO_UDP);

  u32 flags = (VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
	       VNET_BUFFER_F_L4_HDR_OFFSET_VALID);

  ip4 = (ip4_header_t *) (b->data + sizeof (ethernet_header_t));
  ip6 = (ip6_header_t *) (b->data + sizeof (ethernet_header_t));

  is_ip4 = (type == GSO_TCP4 ||
	    (ip4->ip_version_and_header_length >> 4) == 4);
  l2hdr_sz = sizeof (ethernet_header_t);

  if (is_ip4)
    {
      flags |= VNET_BUFFER_F_IS_IP4;
      l3hdr_sz = ip4_header_bytes (ip4);
      fid = clib_net_to_host_u16 (ip4->fragment_id);
    }
  else
    {
      flags |= VNET_BUFFER_F_IS_IP6;
      l3hdr_sz = sizeof (ip6_header_t);	/* FIXME exthdrs */
      fid = 0;
    }
  if (is_tcp)
    {
      flags |= VNET_BUFFER_F_OFFLOAD_TCP_CKSUM;
      tcp = (tcp_header_t *) (b->data + l2hdr_sz + l3hdr_sz);
      l4hdr_sz = tcp_header_bytes (tcp);
      seq = clib_net_to_host_u32 (tcp->seq_number);
      /* store original flags for last packet and reset FIN and PSH */
      tcp_flags = tcp->flags;
      tcp->flags &= ~(TCP_FLAG_FIN | TCP_FLAG_PSH);
      tcp->checksum = 0;
      ip_len = hdr->gso_size + l3hdr_sz + l4hdr_sz;
      new_payload_sz = hdr->gso_size;
    }
  else if (is_udp)
    {
      flags |= VNET_BUFFER_F_OFFLOAD_UDP_CKSUM;
      ip_len = hdr->gso_size + l3hdr_sz;
      udp = (udp_header_t *) (b->data + l2hdr_sz + l3hdr_sz);
      udp->checksum = 0;
      udp->length = clib_host_to_net_u16 (ip_len - l3hdr_sz);
      l4hdr_sz = sizeof (udp_header_t);
      new_payload_sz = hdr->gso_size - l4hdr_sz;
    }

  temp_sz = l2hdr_sz + l3hdr_sz + l4hdr_sz;

  if (is_ip4)
    {
      payload = clib_net_to_host_u16 (ip4->length) - l3hdr_sz - l4hdr_sz;
      ip4->length = clib_host_to_net_u16 (ip_len);
    }
  else
    {
      payload = clib_net_to_host_u16 (ip6->payload_length) - l4hdr_sz;
      ip6->payload_length = clib_host_to_net_u16 (ip_len - l3hdr_sz);
    }

  /* number of additional buffers we need to alloc */
  u16 n_alloc, n_bufs = ((payload - 1) / new_payload_sz);

  /* first buffer we don't copy */
  vec_add1 (ptd->buffers, bi);
  /* create space fore new allocated buffers */
  vec_add2 (ptd->buffers, bufs, n_bufs);
  n_alloc = vlib_buffer_alloc (vm, bufs, n_bufs);

  /* damage control if alloc fails */
  if (PREDICT_FALSE (n_alloc < n_bufs))
    {
      if (n_alloc)
	vlib_buffer_free (vm, bufs, n_alloc);
      /* remove new buffer indices from vector including first one */
      _vec_len (ptd->buffers) -= n_bufs + 1;
      clib_error ("alloc fail");
      return 0;
    }

  /* set source to be remaining of first buffer */
  b->current_length = clib_min (ip_len + l2hdr_sz, e->len - hdr_sz);
  src_ptr = b->data + b->current_length;
  src_left = e->len - hdr_sz - b->current_length;
  dst_left = 0;

  n_from = hdr->num_buffers - 1;
  while (src_left || n_from)
    {
      if (src_left == 0)
	{
	  e = &vring->used->ring[last++ & mask];
	  bi = vring->buffers[e->id];
	  vec_add1 (ptd->to_free, bi);
	  sb = vlib_get_buffer (vm, bi);
	  src_left = e->len;
	  src_ptr = sb->data - hdr_sz;
	  n_from--;
	}
      if (dst_left == 0)
	{
	  /* last packet */
	  fill_metadata (db, vif->sw_if_index, l2hdr_sz, l3hdr_sz, flags);
	  if (is_ip4)
	    {
	      ip4->fragment_id = clib_host_to_net_u16 (fid);
	      ip4->checksum = ip4_header_checksum (ip4);
	    }
	  /* next packet */
	  db = vlib_get_buffer (vm, bufs[0]);
	  db->current_length = temp_sz;
	  /* copy headers including virtio header */
	  clib_memcpy (db->data - hdr_sz, b->data - hdr_sz, temp_sz + hdr_sz);
	  /* update fragment_id and seq */
	  if (is_ip4)
	    {
	      ip4 = (ip4_header_t *) (db->data + sizeof (ethernet_header_t));
	      fid += 1;
	    }
	  else
	    ip6 = (ip6_header_t *) (db->data + sizeof (ethernet_header_t));

	  if (is_tcp)
	    {
	      seq += hdr->gso_size;
	      tcp = (tcp_header_t *) (db->data + l2hdr_sz + l3hdr_sz);
	      tcp->seq_number = clib_host_to_net_u32 (seq);
	    }
	  if (is_udp)
	    {
	      udp = (udp_header_t *) (db->data + l2hdr_sz + l3hdr_sz);
	    }
	  dst_left = new_payload_sz;
	  dst_ptr = db->data + temp_sz;
	  bufs++;
	  n_bufs--;
	}

      u16 bytes_to_copy = clib_min (src_left, dst_left);
      clib_memcpy (dst_ptr, src_ptr, bytes_to_copy);
      db->current_length += bytes_to_copy;

      src_left -= bytes_to_copy;
      dst_left -= bytes_to_copy;
      src_ptr += bytes_to_copy;
      dst_ptr += bytes_to_copy;
    }

  /* last packet */
  fill_metadata (db, vif->sw_if_index, l2hdr_sz, l3hdr_sz, flags);
  if (is_ip4)
    {
      ip4->length = clib_host_to_net_u16 (db->current_length - l2hdr_sz);
      ip4->fragment_id = clib_host_to_net_u16 (fid);
      ip4->checksum = ip4_header_checksum (ip4);
    }
  else
    ip6->payload_length =
      clib_host_to_net_u16 (db->current_length - l2hdr_sz - l3hdr_sz);

  if (is_tcp)
    tcp->flags = tcp_flags;

  if (is_udp)
    udp->length = clib_host_to_net_u16 (db->current_length - l2hdr_sz -
					l3hdr_sz);

  return hdr->num_buffers;
}

static_always_inline uword
virtio_device_input_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame, virtio_if_t * vif, u16 qid)
{
  vnet_main_t *vnm = vnet_get_main ();
  virtio_main_t *vim = &virtio_main;
  u32 thread_index = vlib_get_thread_index ();
  uword n_trace = vlib_get_trace_count (vm, node);
  virtio_vring_t *vring = vec_elt_at_index (vif->vrings, 0);
  u32 next_index = VNET_DEVICE_INPUT_NEXT_ETHERNET_INPUT;
  virtio_per_thread_data_t *ptd =
    vec_elt_at_index (vim->per_thread_data, thread_index);
  const int hdr_sz = sizeof (struct virtio_net_hdr_v1);
  u32 *to_next = 0;
  u32 n_rx_packets = 0;
  u16 mask = vring->size - 1;
  u16 last = vring->last_used_idx;
  i16 n_left = vring->used->idx - last;

  if (n_left == 0)
    goto refill;

  ptd->n_rx_bytes = 0;

  n_left = clib_min (VLIB_FRAME_SIZE, n_left);
  while (n_left > 0)
    {
      struct vring_used_elem *e = &vring->used->ring[last & mask];
      struct virtio_net_hdr_v1 *hdr;
      u16 slots_used;
      u32 bi0 = vring->buffers[e->id];
      vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
      hdr = vlib_buffer_get_current (b0) - hdr_sz;

      if (hdr->gso_type == VIRTIO_NET_HDR_GSO_NONE)
	slots_used = gso_none (vm, vif, ptd, bi0, b0, vring, last, mask);
      else if (hdr->gso_type == VIRTIO_NET_HDR_GSO_TCPV4)
	slots_used = gso_none (vm, vif, ptd, bi0, b0, vring, last, mask);
	//slots_used = gso (vm, vif, ptd, bi0, b0, vring, last, mask, GSO_TCP4);
      else if (hdr->gso_type == VIRTIO_NET_HDR_GSO_TCPV6)
	slots_used = gso (vm, vif, ptd, bi0, b0, vring, last, mask, GSO_TCP6);
      else if (hdr->gso_type == VIRTIO_NET_HDR_GSO_UDP)
	slots_used = gso (vm, vif, ptd, bi0, b0, vring, last, mask, GSO_UDP);
      else
	{
	  slots_used = 0;
	  clib_error ("hdr->gso_type = %x", hdr->gso_type);
	}

      if (PREDICT_FALSE (slots_used == 0))
	goto done;

      vring->desc_in_use -= slots_used;
      n_left -= slots_used;
      last += slots_used;
    }
done:
  vring->last_used_idx = last;

  n_rx_packets = n_left = vec_len (ptd->buffers);
  u32 *buffers = ptd->buffers;
  while (n_left)
    {
      u32 n_left_to_next;
      u32 next0 = next_index;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left && n_left_to_next)
	{
	  u32 bi0 = buffers[0];
	  buffers++;

	  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);

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
	      tr->len = b0->current_length;
	      clib_memcpy (&tr->hdr, vlib_buffer_get_current (b0) - hdr_sz,
			   hdr_sz);
	      clib_memcpy (&tr->b, b0, sizeof (vlib_buffer_t));
	    }

	  /* enqueue buffer */
	  to_next[0] = bi0;
	  to_next += 1;
	  n_left_to_next--;
	  n_left--;

	  /* enqueue */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  if (vec_len (ptd->to_free))
    vlib_buffer_free (vm, ptd->to_free, vec_len (ptd->to_free));
  vec_reset_length (ptd->to_free);
  vec_reset_length (ptd->buffers);

  vlib_increment_combined_counter (vnm->interface_main.combined_sw_if_counters
				   + VNET_INTERFACE_COUNTER_RX, thread_index,
				   vif->hw_if_index, n_rx_packets,
				   ptd->n_rx_bytes);

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
	n_rx += virtio_device_input_inline (vm, node, frame, mif,
					    dq->queue_id);
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
