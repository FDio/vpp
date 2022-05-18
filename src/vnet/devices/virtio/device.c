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

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/gso/gro_func.h>
#include <vnet/gso/hdr_offset_parser.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_psh_cksum.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/devices/virtio/virtio.h>

#define VIRTIO_TX_MAX_CHAIN_LEN 127

#define foreach_virtio_tx_func_error	       \
_(NO_FREE_SLOTS, "no free tx slots")           \
_(TRUNC_PACKET, "packet > buffer size -- truncated in tx ring") \
_(PENDING_MSGS, "pending msgs in tx ring") \
_(INDIRECT_DESC_ALLOC_FAILED, "indirect descriptor allocation failed - packet drop") \
_(OUT_OF_ORDER, "out-of-order buffers in used ring") \
_(GSO_PACKET_DROP, "gso disabled on itf  -- gso packet drop") \
_(CSUM_OFFLOAD_PACKET_DROP, "checksum offload disabled on itf -- csum offload packet drop")

typedef enum
{
#define _(f,s) VIRTIO_TX_ERROR_##f,
  foreach_virtio_tx_func_error
#undef _
    VIRTIO_TX_N_ERROR,
} virtio_tx_func_error_t;

static char *virtio_tx_func_error_strings[] = {
#define _(n,s) s,
  foreach_virtio_tx_func_error
#undef _
};

static u8 *
format_virtio_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  u32 indent = format_get_indent (s);

  s = format (s, "VIRTIO interface");
  if (verbose)
    {
      s = format (s, "\n%U instance %u", format_white_space, indent + 2,
		  dev_instance);
    }
  return s;
}

typedef struct
{
  u32 buffer_index;
  u32 sw_if_index;
  generic_header_offset_t gho;
  vlib_buffer_t buffer;
} virtio_tx_trace_t;

static u8 *
format_virtio_tx_trace (u8 * s, va_list * va)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*va, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*va, vlib_node_t *);
  virtio_tx_trace_t *t = va_arg (*va, virtio_tx_trace_t *);
  u32 indent = format_get_indent (s);

  s = format (s, "%Ubuffer 0x%x: %U\n", format_white_space, indent,
	      t->buffer_index, format_vnet_buffer_no_chain, &t->buffer);
  s =
    format (s, "%U%U\n", format_white_space, indent,
	    format_generic_header_offset, &t->gho);
  s =
    format (s, "%U%U", format_white_space, indent,
	    format_ethernet_header_with_length, t->buffer.pre_data,
	    sizeof (t->buffer.pre_data));
  return s;
}

static void
virtio_tx_trace (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_buffer_t *b0,
		 u32 bi, int is_tun)
{
  virtio_tx_trace_t *t;
  t = vlib_add_trace (vm, node, b0, sizeof (t[0]));
  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
  t->buffer_index = bi;
  if (is_tun)
    {
      int is_ip4 = 0, is_ip6 = 0;

      switch (((u8 *) vlib_buffer_get_current (b0))[0] & 0xf0)
	{
	case 0x40:
	  is_ip4 = 1;
	  break;
	case 0x60:
	  is_ip6 = 1;
	  break;
	default:
	  break;
	}
      vnet_generic_header_offset_parser (b0, &t->gho, 0, is_ip4, is_ip6);
    }
  else
    vnet_generic_header_offset_parser (b0, &t->gho, 1,
				       b0->flags &
				       VNET_BUFFER_F_IS_IP4,
				       b0->flags & VNET_BUFFER_F_IS_IP6);

  clib_memcpy_fast (&t->buffer, b0, sizeof (*b0) - sizeof (b0->pre_data));
  clib_memcpy_fast (t->buffer.pre_data, vlib_buffer_get_current (b0),
		    sizeof (t->buffer.pre_data));
}

static void
virtio_interface_drop_inline (vlib_main_t *vm, virtio_if_t *vif,
			      uword node_index, u32 *buffers, u16 n,
			      virtio_tx_func_error_t error)
{
  vlib_error_count (vm, node_index, error, n);
  vlib_increment_simple_counter (vnet_main.interface_main.sw_if_counters +
				   VNET_INTERFACE_COUNTER_DROP,
				 vm->thread_index, vif->sw_if_index, n);
  vlib_buffer_free (vm, buffers, n);
}

static void
virtio_memset_ring_u32 (u32 *ring, u32 start, u32 ring_size, u32 n_buffers)
{
  ASSERT (n_buffers <= ring_size);

  if (PREDICT_TRUE (start + n_buffers <= ring_size))
    {
      clib_memset_u32 (ring + start, ~0, n_buffers);
    }
  else
    {
      clib_memset_u32 (ring + start, ~0, ring_size - start);
      clib_memset_u32 (ring, ~0, n_buffers - (ring_size - start));
    }
}

static void
virtio_free_used_device_desc_split (vlib_main_t *vm,
				    vnet_virtio_vring_t *vring,
				    uword node_index)
{
  u16 used = vring->desc_in_use;
  u16 sz = vring->queue_size;
  u16 mask = sz - 1;
  u16 last = vring->last_used_idx;
  u16 n_left = vring->used->idx - last;
  u16 out_of_order_count = 0;

  if (n_left == 0)
    return;

  while (n_left)
    {
      vnet_virtio_vring_used_elem_t *e = &vring->used->ring[last & mask];
      u16 slot, n_buffers;
      slot = n_buffers = e->id;

      while (e->id == (n_buffers & mask))
	{
	  n_left--;
	  last++;
	  n_buffers++;
	  vnet_virtio_vring_desc_t *d = &vring->desc[e->id];
	  u16 next;
	  while (d->flags & VRING_DESC_F_NEXT)
	    {
	      n_buffers++;
	      next = d->next;
	      d = &vring->desc[next];
	    }
	  if (n_left == 0)
	    break;
	  e = &vring->used->ring[last & mask];
	}
      vlib_buffer_free_from_ring (vm, vring->buffers, slot,
				  sz, (n_buffers - slot));
      virtio_memset_ring_u32 (vring->buffers, slot, sz, (n_buffers - slot));
      used -= (n_buffers - slot);

      if (n_left > 0)
	{
	  vlib_buffer_free (vm, &vring->buffers[e->id], 1);
	  vring->buffers[e->id] = ~0;
	  used--;
	  last++;
	  n_left--;
	  out_of_order_count++;
	  vring->flags |= VRING_TX_OUT_OF_ORDER;
	}
    }

  /*
   * Some vhost-backends give buffers back in out-of-order fashion in used ring.
   * It impacts the overall virtio-performance.
   */
  if (out_of_order_count)
    vlib_error_count (vm, node_index, VIRTIO_TX_ERROR_OUT_OF_ORDER,
		      out_of_order_count);

  vring->desc_in_use = used;
  vring->last_used_idx = last;
}

static void
virtio_free_used_device_desc_packed (vlib_main_t *vm,
				     vnet_virtio_vring_t *vring,
				     uword node_index)
{
  vnet_virtio_vring_packed_desc_t *d;
  u16 sz = vring->queue_size;
  u16 last = vring->last_used_idx;
  u16 n_buffers = 0, start;
  u16 flags;

  if (vring->desc_in_use == 0)
    return;

  d = &vring->packed_desc[last];
  flags = d->flags;
  start = d->id;

  while ((flags & VRING_DESC_F_AVAIL) == (vring->used_wrap_counter << 7) &&
	 (flags & VRING_DESC_F_USED) == (vring->used_wrap_counter << 15))
    {
      last++;
      n_buffers++;

      if (last >= sz)
	{
	  last = 0;
	  vring->used_wrap_counter ^= 1;
	}
      d = &vring->packed_desc[last];
      flags = d->flags;
    }

  if (n_buffers)
    {
      vlib_buffer_free_from_ring (vm, vring->buffers, start, sz, n_buffers);
      virtio_memset_ring_u32 (vring->buffers, start, sz, n_buffers);
      vring->desc_in_use -= n_buffers;
      vring->last_used_idx = last;
    }
}

static void
virtio_free_used_device_desc (vlib_main_t *vm, vnet_virtio_vring_t *vring,
			      uword node_index, int packed)
{
  if (packed)
    virtio_free_used_device_desc_packed (vm, vring, node_index);
  else
    virtio_free_used_device_desc_split (vm, vring, node_index);

}

static void
set_checksum_offsets (vlib_buffer_t *b, vnet_virtio_net_hdr_v1_t *hdr,
		      const int is_l2)
{
  vnet_buffer_oflags_t oflags = vnet_buffer (b)->oflags;

  if (b->flags & VNET_BUFFER_F_IS_IP4)
    {
      ip4_header_t *ip4;
      hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
      hdr->csum_start = vnet_buffer (b)->l4_hdr_offset; // 0x22;

      /*
       * virtio devices do not support IP4 checksum offload. So driver takes
       * care of it while doing tx.
       */
      ip4 = (ip4_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	ip4->checksum = ip4_header_checksum (ip4);

      /*
       * virtio devices assume the l4 header is set to the checksum of the
       * l3 pseudo-header, so we compute it before tx-ing
       */
      if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
	{
	  tcp_header_t *tcp =
	    (tcp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
	  tcp->checksum = ip4_pseudo_header_cksum (ip4);
	  hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
	}
      else if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
	{
	  udp_header_t *udp =
	    (udp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
	  udp->checksum = ip4_pseudo_header_cksum (ip4);
	  hdr->csum_offset = STRUCT_OFFSET_OF (udp_header_t, checksum);
	}
    }
  else if (b->flags & VNET_BUFFER_F_IS_IP6)
    {
      ip6_header_t *ip6;
      hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
      hdr->csum_start = vnet_buffer (b)->l4_hdr_offset; // 0x36;
      ip6 = (ip6_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);

      /*
       * virtio devices assume the l4 header is set to the checksum of the
       * l3 pseudo-header, so we compute it before tx-ing
       */
      if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
	{
	  tcp_header_t *tcp =
	    (tcp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
	  tcp->checksum = ip6_pseudo_header_cksum (ip6);
	  hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
	}
      else if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
	{
	  udp_header_t *udp =
	    (udp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
	  udp->checksum = ip6_pseudo_header_cksum (ip6);
	  hdr->csum_offset = STRUCT_OFFSET_OF (udp_header_t, checksum);
	}
    }
}

static void
set_gso_offsets (vlib_buffer_t *b, vnet_virtio_net_hdr_v1_t *hdr,
		 const int is_l2)
{
  vnet_buffer_oflags_t oflags = vnet_buffer (b)->oflags;

  if (b->flags & VNET_BUFFER_F_IS_IP4)
    {
      ip4_header_t *ip4;
      hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
      hdr->gso_size = vnet_buffer2 (b)->gso_size;
      hdr->hdr_len = vnet_buffer (b)->l4_hdr_offset -
		     vnet_buffer (b)->l2_hdr_offset +
		     vnet_buffer2 (b)->gso_l4_hdr_sz;
      hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
      hdr->csum_start = vnet_buffer (b)->l4_hdr_offset; // 0x22;
      hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
      ip4 = (ip4_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
      /*
       * virtio devices do not support IP4 checksum offload. So driver takes care
       * of it while doing tx.
       */
      if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
	ip4->checksum = ip4_header_checksum (ip4);
    }
  else if (b->flags & VNET_BUFFER_F_IS_IP6)
    {
      hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
      hdr->gso_size = vnet_buffer2 (b)->gso_size;
      hdr->hdr_len = vnet_buffer (b)->l4_hdr_offset -
		     vnet_buffer (b)->l2_hdr_offset +
		     vnet_buffer2 (b)->gso_l4_hdr_sz;
      hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
      hdr->csum_start = vnet_buffer (b)->l4_hdr_offset; // 0x36;
      hdr->csum_offset = STRUCT_OFFSET_OF (tcp_header_t, checksum);
    }
}

static u16
add_buffer_to_slot (vlib_main_t *vm, vlib_node_runtime_t *node,
		    virtio_if_t *vif, vnet_virtio_vring_t *vring, u32 bi,
		    u16 free_desc_count, u16 avail, u16 next, u16 mask,
		    int hdr_sz, int do_gso, int csum_offload, int is_pci,
		    int is_tun, int is_indirect, int is_any_layout)
{
  u16 n_added = 0;
  vnet_virtio_vring_desc_t *d;
  int is_l2 = !is_tun;
  d = &vring->desc[next];
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_virtio_net_hdr_v1_t *hdr = vlib_buffer_get_current (b) - hdr_sz;
  u32 drop_inline = ~0;

  clib_memset_u8 (hdr, 0, hdr_sz);

  if (b->flags & VNET_BUFFER_F_GSO)
    {
      if (do_gso)
	set_gso_offsets (b, hdr, is_l2);
      else
	{
	  drop_inline = VIRTIO_TX_ERROR_GSO_PACKET_DROP;
	  goto done;
	}
    }
  else if (b->flags & VNET_BUFFER_F_OFFLOAD)
    {
      if (csum_offload)
	set_checksum_offsets (b, hdr, is_l2);
      else
	{
	  drop_inline = VIRTIO_TX_ERROR_CSUM_OFFLOAD_PACKET_DROP;
	  goto done;
	}
    }

  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      virtio_tx_trace (vm, node, b, bi, is_tun);
    }

  if (PREDICT_TRUE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0))
    {
      d->addr = ((is_pci) ? vlib_buffer_get_current_pa (vm, b) :
		 pointer_to_uword (vlib_buffer_get_current (b))) - hdr_sz;
      d->len = b->current_length + hdr_sz;
      d->flags = 0;
    }
  else if (is_indirect)
    {
      /*
       * We are using single vlib_buffer_t for indirect descriptor(s)
       * chain. Single descriptor is 16 bytes and vlib_buffer_t
       * has 2048 bytes space. So maximum long chain can have 128
       * (=2048/16) indirect descriptors.
       * It can easily support 65535 bytes of Jumbo frames with
       * each data buffer size of 512 bytes minimum.
       */
      u32 indirect_buffer = 0;
      if (PREDICT_FALSE (vlib_buffer_alloc (vm, &indirect_buffer, 1) == 0))
	{
	  drop_inline = VIRTIO_TX_ERROR_INDIRECT_DESC_ALLOC_FAILED;
	  goto done;
	}

      vlib_buffer_t *indirect_desc = vlib_get_buffer (vm, indirect_buffer);
      indirect_desc->current_data = 0;
      indirect_desc->flags |= VLIB_BUFFER_NEXT_PRESENT;
      indirect_desc->next_buffer = bi;
      bi = indirect_buffer;

      vnet_virtio_vring_desc_t *id =
	(vnet_virtio_vring_desc_t *) vlib_buffer_get_current (indirect_desc);
      u32 count = 1;
      if (is_pci)
	{
	  d->addr = vlib_physmem_get_pa (vm, id);
	  id->addr = vlib_buffer_get_current_pa (vm, b) - hdr_sz;

	  /*
	   * If VIRTIO_F_ANY_LAYOUT is not negotiated, then virtio_net_hdr
	   * should be presented in separate descriptor and data will start
	   * from next descriptor.
	   */
	  if (is_any_layout)
	    id->len = b->current_length + hdr_sz;
	  else
	    {
	      id->len = hdr_sz;
	      id->flags = VRING_DESC_F_NEXT;
	      id->next = count;
	      count++;
	      id++;
	      id->addr = vlib_buffer_get_current_pa (vm, b);
	      id->len = b->current_length;
	    }
	  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      id->flags = VRING_DESC_F_NEXT;
	      id->next = count;
	      count++;
	      id++;
	      b = vlib_get_buffer (vm, b->next_buffer);
	      id->addr = vlib_buffer_get_current_pa (vm, b);
	      id->len = b->current_length;
	      if (PREDICT_FALSE (count == VIRTIO_TX_MAX_CHAIN_LEN))
		{
		  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
		    vlib_error_count (vm, node->node_index,
				      VIRTIO_TX_ERROR_TRUNC_PACKET, 1);
		  break;
		}
	    }
	}
      else			/* VIRTIO_IF_TYPE_[TAP | TUN] */
	{
	  d->addr = pointer_to_uword (id);
	  /* first buffer in chain */
	  id->addr = pointer_to_uword (vlib_buffer_get_current (b)) - hdr_sz;
	  id->len = b->current_length + hdr_sz;

	  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      id->flags = VRING_DESC_F_NEXT;
	      id->next = count;
	      count++;
	      id++;
	      b = vlib_get_buffer (vm, b->next_buffer);
	      id->addr = pointer_to_uword (vlib_buffer_get_current (b));
	      id->len = b->current_length;
	      if (PREDICT_FALSE (count == VIRTIO_TX_MAX_CHAIN_LEN))
		{
		  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
		    vlib_error_count (vm, node->node_index,
				      VIRTIO_TX_ERROR_TRUNC_PACKET, 1);
		  break;
		}
	    }
	}
      id->flags = 0;
      id->next = 0;
      d->len = count * sizeof (vnet_virtio_vring_desc_t);
      d->flags = VRING_DESC_F_INDIRECT;
    }
  else if (is_pci)
    {
      u16 count = next;
      vlib_buffer_t *b_temp = b;
      u16 n_buffers_in_chain = 1;

      /*
       * Check the length of the chain for the required number of
       * descriptors. Return from here, retry to get more descriptors,
       * if chain length is greater than available descriptors.
       */
      while (b_temp->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  n_buffers_in_chain++;
	  b_temp = vlib_get_buffer (vm, b_temp->next_buffer);
	}

      if (n_buffers_in_chain > free_desc_count)
	return n_buffers_in_chain;

      d->addr = vlib_buffer_get_current_pa (vm, b) - hdr_sz;
      d->len = b->current_length + hdr_sz;

      while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	{
	  d->flags = VRING_DESC_F_NEXT;
	  vring->buffers[count] = bi;
	  b->flags &=
	    ~(VLIB_BUFFER_NEXT_PRESENT | VLIB_BUFFER_TOTAL_LENGTH_VALID);
	  bi = b->next_buffer;
	  b->next_buffer = 0;
	  n_added++;
	  count = (count + 1) & mask;
	  d->next = count;
	  d = &vring->desc[count];
	  b = vlib_get_buffer (vm, bi);
	  d->addr = vlib_buffer_get_current_pa (vm, b);
	  d->len = b->current_length;
	}
      d->flags = 0;
      vring->buffers[count] = bi;
      vring->avail->ring[avail & mask] = next;
      n_added++;
      return n_added;
    }
  else
    {
      ASSERT (0);
    }
  vring->buffers[next] = bi;
  vring->avail->ring[avail & mask] = next;
  n_added++;

done:
  if (drop_inline != ~0)
    virtio_interface_drop_inline (vm, vif, node->node_index, &bi, 1,
				  drop_inline);

  return n_added;
}

static u16
add_buffer_to_slot_packed (vlib_main_t *vm, vlib_node_runtime_t *node,
			   virtio_if_t *vif, vnet_virtio_vring_t *vring,
			   u32 bi, u16 next, int hdr_sz, int do_gso,
			   int csum_offload, int is_pci, int is_tun,
			   int is_indirect, int is_any_layout)
{
  u16 n_added = 0, flags = 0;
  int is_l2 = !is_tun;
  vnet_virtio_vring_packed_desc_t *d = &vring->packed_desc[next];
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  vnet_virtio_net_hdr_v1_t *hdr = vlib_buffer_get_current (b) - hdr_sz;
  u32 drop_inline = ~0;

  clib_memset (hdr, 0, hdr_sz);

  if (b->flags & VNET_BUFFER_F_GSO)
    {
      if (do_gso)
	set_gso_offsets (b, hdr, is_l2);
      else
	{
	  drop_inline = VIRTIO_TX_ERROR_GSO_PACKET_DROP;
	  goto done;
	}
    }
  else if (b->flags & VNET_BUFFER_F_OFFLOAD)
    {
      if (csum_offload)
	set_checksum_offsets (b, hdr, is_l2);
      else
	{
	  drop_inline = VIRTIO_TX_ERROR_CSUM_OFFLOAD_PACKET_DROP;
	  goto done;
	}
    }
  if (PREDICT_FALSE (b->flags & VLIB_BUFFER_IS_TRACED))
    {
      virtio_tx_trace (vm, node, b, bi, is_tun);
    }

  if (PREDICT_TRUE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) == 0))
    {
      d->addr =
	((is_pci) ? vlib_buffer_get_current_pa (vm,
						b) :
	 pointer_to_uword (vlib_buffer_get_current (b))) - hdr_sz;
      d->len = b->current_length + hdr_sz;
    }
  else if (is_indirect)
    {
      /*
       * We are using single vlib_buffer_t for indirect descriptor(s)
       * chain. Single descriptor is 16 bytes and vlib_buffer_t
       * has 2048 bytes space. So maximum long chain can have 128
       * (=2048/16) indirect descriptors.
       * It can easily support 65535 bytes of Jumbo frames with
       * each data buffer size of 512 bytes minimum.
       */
      u32 indirect_buffer = 0;
      if (PREDICT_FALSE (vlib_buffer_alloc (vm, &indirect_buffer, 1) == 0))
	{
	  drop_inline = VIRTIO_TX_ERROR_INDIRECT_DESC_ALLOC_FAILED;
	  goto done;
	}

      vlib_buffer_t *indirect_desc = vlib_get_buffer (vm, indirect_buffer);
      indirect_desc->current_data = 0;
      indirect_desc->flags |= VLIB_BUFFER_NEXT_PRESENT;
      indirect_desc->next_buffer = bi;
      bi = indirect_buffer;

      vnet_virtio_vring_packed_desc_t *id =
	(vnet_virtio_vring_packed_desc_t *) vlib_buffer_get_current (
	  indirect_desc);
      u32 count = 1;
      if (is_pci)
	{
	  d->addr = vlib_physmem_get_pa (vm, id);
	  id->addr = vlib_buffer_get_current_pa (vm, b) - hdr_sz;

	  /*
	   * If VIRTIO_F_ANY_LAYOUT is not negotiated, then virtio_net_hdr
	   * should be presented in separate descriptor and data will start
	   * from next descriptor.
	   */
	  if (is_any_layout)
	    id->len = b->current_length + hdr_sz;
	  else
	    {
	      id->len = hdr_sz;
	      id->flags = 0;
	      id->id = 0;
	      count++;
	      id++;
	      id->addr = vlib_buffer_get_current_pa (vm, b);
	      id->len = b->current_length;
	    }
	  while (b->flags & VLIB_BUFFER_NEXT_PRESENT)
	    {
	      id->flags = 0;
	      id->id = 0;
	      count++;
	      id++;
	      b = vlib_get_buffer (vm, b->next_buffer);
	      id->addr = vlib_buffer_get_current_pa (vm, b);
	      id->len = b->current_length;
	      if (PREDICT_FALSE (count == VIRTIO_TX_MAX_CHAIN_LEN))
		{
		  if (b->flags & VLIB_BUFFER_NEXT_PRESENT)
		    vlib_error_count (vm, node->node_index,
				      VIRTIO_TX_ERROR_TRUNC_PACKET, 1);
		  break;
		}
	    }
	}
      id->flags = 0;
      id->id = 0;
      d->len = count * sizeof (vnet_virtio_vring_packed_desc_t);
      flags = VRING_DESC_F_INDIRECT;
    }
  else
    {
      ASSERT (0);
    }
  if (vring->avail_wrap_counter)
    {
      flags |= VRING_DESC_F_AVAIL;
      flags &= ~VRING_DESC_F_USED;
    }
  else
    {
      flags &= ~VRING_DESC_F_AVAIL;
      flags |= VRING_DESC_F_USED;
    }

  d->id = next;
  d->flags = flags;
  vring->buffers[next] = bi;
  n_added++;

done:
  if (drop_inline != ~0)
    virtio_interface_drop_inline (vm, vif, node->node_index, &bi, 1,
				  drop_inline);

  return n_added;
}

static uword
virtio_interface_tx_packed_gso_inline (
  vlib_main_t *vm, vlib_node_runtime_t *node, virtio_if_t *vif,
  virtio_if_type_t type, vnet_virtio_vring_t *vring, u32 *buffers, u16 n_left,
  const int do_gso, const int csum_offload)
{
  int is_pci = (type == VIRTIO_IF_TYPE_PCI);
  int is_tun = (type == VIRTIO_IF_TYPE_TUN);
  int is_indirect =
    ((vif->features & VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC)) != 0);
  int is_any_layout =
    ((vif->features & VIRTIO_FEATURE (VIRTIO_F_ANY_LAYOUT)) != 0);
  const int hdr_sz = vif->virtio_net_hdr_sz;
  u16 sz = vring->queue_size;
  u16 used, next, n_buffers = 0, n_buffers_left = 0;
  u16 n_vectors = n_left;


  used = vring->desc_in_use;
  next = vring->desc_next;

  if (vif->packet_buffering)
    {
      n_buffers = n_buffers_left = virtio_vring_n_buffers (vring->buffering);

      while (n_buffers_left && used < sz)
	{
	  u16 n_added = 0;

	  u32 bi = virtio_vring_buffering_read_from_front (vring->buffering);
	  if (bi == ~0)
	    break;
	  n_added = add_buffer_to_slot_packed (
	    vm, node, vif, vring, bi, next, hdr_sz, do_gso, csum_offload,
	    is_pci, is_tun, is_indirect, is_any_layout);
	  n_buffers_left--;
	  if (PREDICT_FALSE (n_added == 0))
	    continue;

	  used++;
	  next++;
	  if (next >= sz)
	    {
	      next = 0;
	      vring->avail_wrap_counter ^= 1;
	    }
	}
      virtio_txq_clear_scheduled (vring);
    }

  while (n_left && used < sz)
    {
      u16 n_added = 0;

      n_added = add_buffer_to_slot_packed (
	vm, node, vif, vring, buffers[0], next, hdr_sz, do_gso, csum_offload,
	is_pci, is_tun, is_indirect, is_any_layout);
      buffers++;
      n_left--;
      if (PREDICT_FALSE (n_added == 0))
	continue;

      used++;
      next++;
      if (next >= sz)
	{
	  next = 0;
	  vring->avail_wrap_counter ^= 1;
	}
    }

  if (n_left != n_vectors || n_buffers != n_buffers_left)
    {
      CLIB_MEMORY_STORE_BARRIER ();
      vring->desc_next = next;
      vring->desc_in_use = used;
      CLIB_MEMORY_BARRIER ();
      if (vring->device_event->flags != VRING_EVENT_F_DISABLE)
	virtio_kick (vm, vring, vif);
    }

  return n_left;
}

static void
virtio_find_free_desc (vnet_virtio_vring_t *vring, u16 size, u16 mask, u16 req,
		       u16 next, u32 *first_free_desc_index,
		       u16 *free_desc_count)
{
  u16 start = 0;
  /* next is used as hint: from where to start looking */
  for (u16 i = 0; i < size; i++, next++)
    {
      if (vring->buffers[next & mask] == ~0)
	{
	  if (*first_free_desc_index == ~0)
	    {
	      *first_free_desc_index = (next & mask);
	      start = i;
	      (*free_desc_count)++;
	      req--;
	      if (req == 0)
		break;
	    }
	  else
	    {
	      if (start + *free_desc_count == i)
		{
		  (*free_desc_count)++;
		  req--;
		  if (req == 0)
		    break;
		}
	      else
		break;
	    }
	}
    }
}

static u16
virtio_interface_tx_split_gso_inline (vlib_main_t *vm,
				      vlib_node_runtime_t *node,
				      virtio_if_t *vif, virtio_if_type_t type,
				      vnet_virtio_vring_t *vring, u32 *buffers,
				      u16 n_left, int do_gso, int csum_offload)
{
  u16 used, next, avail, n_buffers = 0, n_buffers_left = 0;
  int is_pci = (type == VIRTIO_IF_TYPE_PCI);
  int is_tun = (type == VIRTIO_IF_TYPE_TUN);
  int is_indirect =
    ((vif->features & VIRTIO_FEATURE (VIRTIO_RING_F_INDIRECT_DESC)) != 0);
  int is_any_layout =
    ((vif->features & VIRTIO_FEATURE (VIRTIO_F_ANY_LAYOUT)) != 0);
  u16 sz = vring->queue_size;
  int hdr_sz = vif->virtio_net_hdr_sz;
  u16 mask = sz - 1;
  u16 n_vectors = n_left;

  used = vring->desc_in_use;
  next = vring->desc_next;
  avail = vring->avail->idx;

  u16 free_desc_count = 0;

  if (PREDICT_FALSE (vring->flags & VRING_TX_OUT_OF_ORDER))
    {
      u32 first_free_desc_index = ~0;

      virtio_find_free_desc (vring, sz, mask, n_left, next,
			     &first_free_desc_index, &free_desc_count);

      if (free_desc_count)
	next = first_free_desc_index;
    }
  else
    free_desc_count = sz - used;

  if (vif->packet_buffering)
    {
      n_buffers = n_buffers_left = virtio_vring_n_buffers (vring->buffering);

      while (n_buffers_left && free_desc_count)
	{
	  u16 n_added = 0;

	  u32 bi = virtio_vring_buffering_read_from_front (vring->buffering);
	  if (bi == ~0)
	    break;

	  n_added = add_buffer_to_slot (vm, node, vif, vring, bi,
					free_desc_count, avail, next, mask,
					hdr_sz, do_gso, csum_offload, is_pci,
					is_tun, is_indirect, is_any_layout);
	  if (PREDICT_FALSE (n_added == 0))
	    {
	      n_buffers_left--;
	      continue;
	    }
	  else if (PREDICT_FALSE (n_added > free_desc_count))
	    break;

	  avail++;
	  next = (next + n_added) & mask;
	  used += n_added;
	  n_buffers_left--;
	  free_desc_count -= n_added;
	}
      virtio_txq_clear_scheduled (vring);
    }

  while (n_left && free_desc_count)
    {
      u16 n_added = 0;

      n_added =
	add_buffer_to_slot (vm, node, vif, vring, buffers[0], free_desc_count,
			    avail, next, mask, hdr_sz, do_gso, csum_offload,
			    is_pci, is_tun, is_indirect, is_any_layout);

      if (PREDICT_FALSE (n_added == 0))
	{
	  buffers++;
	  n_left--;
	  continue;
	}
      else if (PREDICT_FALSE (n_added > free_desc_count))
	break;

      avail++;
      next = (next + n_added) & mask;
      used += n_added;
      buffers++;
      n_left--;
      free_desc_count -= n_added;
    }

  if (n_left != n_vectors || n_buffers != n_buffers_left)
    {
      clib_atomic_store_seq_cst (&vring->avail->idx, avail);
      vring->desc_next = next;
      vring->desc_in_use = used;
      if ((clib_atomic_load_seq_cst (&vring->used->flags) &
	   VRING_USED_F_NO_NOTIFY) == 0)
	virtio_kick (vm, vring, vif);
    }

  return n_left;
}

static u16
virtio_interface_tx_gso_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
				virtio_if_t *vif, virtio_if_type_t type,
				vnet_virtio_vring_t *vring, u32 *buffers,
				u16 n_left, int packed, int do_gso,
				int csum_offload)
{
  if (packed)
    return virtio_interface_tx_packed_gso_inline (vm, node, vif, type, vring,
						  buffers, n_left,
						  do_gso, csum_offload);
  else
    return virtio_interface_tx_split_gso_inline (vm, node, vif, type, vring,
						 buffers, n_left,
						 do_gso, csum_offload);
}

static u16
virtio_interface_tx_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
			    virtio_if_t *vif, vnet_virtio_vring_t *vring,
			    virtio_if_type_t type, u32 *buffers, u16 n_left,
			    int packed)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, vif->hw_if_index);

  if (hw->caps & VNET_HW_IF_CAP_TCP_GSO)
    return virtio_interface_tx_gso_inline (vm, node, vif, type, vring,
					   buffers, n_left, packed,
					   1 /* do_gso */ ,
					   1 /* checksum offload */ );
  else if (hw->caps & VNET_HW_IF_CAP_L4_TX_CKSUM)
    return virtio_interface_tx_gso_inline (vm, node, vif, type, vring,
					   buffers, n_left, packed,
					   0 /* no do_gso */ ,
					   1 /* checksum offload */ );
  else
    return virtio_interface_tx_gso_inline (vm, node, vif, type, vring,
					   buffers, n_left, packed,
					   0 /* no do_gso */ ,
					   0 /* no checksum offload */ );
}

VNET_DEVICE_CLASS_TX_FN (virtio_device_class) (vlib_main_t * vm,
					       vlib_node_runtime_t * node,
					       vlib_frame_t * frame)
{
  virtio_main_t *nm = &virtio_main;
  vnet_interface_output_runtime_t *rund = (void *) node->runtime_data;
  virtio_if_t *vif = pool_elt_at_index (nm->interfaces, rund->dev_instance);
  vnet_hw_if_tx_frame_t *tf = vlib_frame_scalar_args (frame);
  u16 qid = tf->queue_id;
  vnet_virtio_vring_t *vring = vec_elt_at_index (vif->txq_vrings, qid);
  u16 n_left = frame->n_vectors;
  u32 *buffers = vlib_frame_vector_args (frame);
  u32 to[GRO_TO_VECTOR_SIZE (n_left)];
  int packed = vif->is_packed;
  u16 n_vectors = frame->n_vectors;

  if (tf->shared_queue)
    clib_spinlock_lock (&vring->lockp);

  if (vif->packet_coalesce)
    {
      n_vectors = n_left =
	vnet_gro_inline (vm, vring->flow_table, buffers, n_left, to);
      buffers = to;
      virtio_txq_clear_scheduled (vring);
    }

  u16 retry_count = 2;

retry:
  /* free consumed buffers */
  virtio_free_used_device_desc (vm, vring, node->node_index, packed);

  if (vif->type == VIRTIO_IF_TYPE_TAP)
    n_left = virtio_interface_tx_inline (vm, node, vif, vring,
					 VIRTIO_IF_TYPE_TAP,
					 &buffers[n_vectors - n_left],
					 n_left, packed);
  else if (vif->type == VIRTIO_IF_TYPE_PCI)
    n_left = virtio_interface_tx_inline (vm, node, vif, vring,
					 VIRTIO_IF_TYPE_PCI,
					 &buffers[n_vectors - n_left],
					 n_left, packed);
  else if (vif->type == VIRTIO_IF_TYPE_TUN)
    n_left = virtio_interface_tx_inline (vm, node, vif, vring,
					 VIRTIO_IF_TYPE_TUN,
					 &buffers[n_vectors - n_left],
					 n_left, packed);
  else
    ASSERT (0);

  if (n_left && retry_count--)
    goto retry;

  if (vif->packet_buffering && n_left)
    {
      u16 n_buffered = virtio_vring_buffering_store_packets (vring->buffering,
							     &buffers
							     [n_vectors
							      - n_left],
							     n_left);
      n_left -= n_buffered;
    }
  if (n_left)
    virtio_interface_drop_inline (vm, vif, node->node_index,
				  &buffers[n_vectors - n_left], n_left,
				  VIRTIO_TX_ERROR_NO_FREE_SLOTS);

  if (tf->shared_queue)
    clib_spinlock_unlock (&vring->lockp);

  return frame->n_vectors - n_left;
}

static void
virtio_set_interface_next_node (vnet_main_t * vnm, u32 hw_if_index,
				u32 node_index)
{
  virtio_main_t *apm = &virtio_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  virtio_if_t *vif = pool_elt_at_index (apm->interfaces, hw->dev_instance);

  /* Shut off redirection */
  if (node_index == ~0)
    {
      vif->per_interface_next_index = node_index;
      return;
    }

  vif->per_interface_next_index =
    vlib_node_add_next (vlib_get_main (), virtio_input_node.index,
			node_index);
}

static void
virtio_clear_hw_interface_counters (u32 instance)
{
  /* Nothing for now */
}

static void
virtio_set_rx_interrupt (virtio_if_t *vif, vnet_virtio_vring_t *vring)
{
  if (vif->is_packed)
    vring->driver_event->flags &= ~VRING_EVENT_F_DISABLE;
  else
    vring->avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
}

static void
virtio_set_rx_polling (virtio_if_t *vif, vnet_virtio_vring_t *vring)
{
  if (vif->is_packed)
    vring->driver_event->flags |= VRING_EVENT_F_DISABLE;
  else
    vring->avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
}

static clib_error_t *
virtio_interface_rx_mode_change (vnet_main_t * vnm, u32 hw_if_index, u32 qid,
				 vnet_hw_if_rx_mode mode)
{
  virtio_main_t *mm = &virtio_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  virtio_if_t *vif = pool_elt_at_index (mm->interfaces, hw->dev_instance);
  vnet_virtio_vring_t *rx_vring = vec_elt_at_index (vif->rxq_vrings, qid);

  if (vif->type == VIRTIO_IF_TYPE_PCI && !(vif->support_int_mode))
    {
      virtio_set_rx_polling (vif, rx_vring);
      return clib_error_return (0, "interrupt mode is not supported");
    }

  if (mode == VNET_HW_IF_RX_MODE_POLLING)
      virtio_set_rx_polling (vif, rx_vring);
  else
      virtio_set_rx_interrupt (vif, rx_vring);

  rx_vring->mode = mode;

  return 0;
}

static clib_error_t *
virtio_interface_admin_up_down (vnet_main_t * vnm, u32 hw_if_index, u32 flags)
{
  virtio_main_t *mm = &virtio_main;
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  virtio_if_t *vif = pool_elt_at_index (mm->interfaces, hw->dev_instance);

  if (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP)
    {
      vif->flags |= VIRTIO_IF_FLAG_ADMIN_UP;
      vnet_hw_interface_set_flags (vnm, vif->hw_if_index,
				   VNET_HW_INTERFACE_FLAG_LINK_UP);
    }
  else
    {
      vif->flags &= ~VIRTIO_IF_FLAG_ADMIN_UP;
      vnet_hw_interface_set_flags (vnm, vif->hw_if_index, 0);
    }
  return 0;
}

static clib_error_t *
virtio_subif_add_del_function (vnet_main_t * vnm,
			       u32 hw_if_index,
			       struct vnet_sw_interface_t *st, int is_add)
{
  /* Nothing for now */
  return 0;
}

/* *INDENT-OFF* */
VNET_DEVICE_CLASS (virtio_device_class) = {
  .name = "virtio",
  .format_device_name = format_virtio_device_name,
  .format_device = format_virtio_device,
  .format_tx_trace = format_virtio_tx_trace,
  .tx_function_n_errors = VIRTIO_TX_N_ERROR,
  .tx_function_error_strings = virtio_tx_func_error_strings,
  .rx_redirect_to_node = virtio_set_interface_next_node,
  .clear_counters = virtio_clear_hw_interface_counters,
  .admin_up_down_function = virtio_interface_admin_up_down,
  .subif_add_del_function = virtio_subif_add_del_function,
  .rx_mode_change_function = virtio_interface_rx_mode_change,
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
