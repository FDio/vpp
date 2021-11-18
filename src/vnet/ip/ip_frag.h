/*---------------------------------------------------------------------------
 * Copyright (c) 2009-2014 Cisco and/or its affiliates.
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
 *---------------------------------------------------------------------------
 */
/*
 * IPv4 and IPv6 Fragmentation Nodes
 *
 * A packet sent to those nodes require the following
 * buffer attributes to be set:
 * ip_frag.header_offset :
 *     Where to find the IPv4 (or IPv6) header in the packet. Previous
 *     bytes are left untouched and copied in every fragment. The fragments
 *     are then appended. This option is used for fragmented packets
 *     that are encapsulated.
 * ip_frag.mtu :
 *     Maximum size of IP packets, header included, but ignoring
 *     the 'ip_frag.header_offset' copied bytes.
 * ip_frag.next_index :
 *     One of ip_frag_next_t, indicating to which exit node the fragments
 *     should be sent to.
 *
 */

#ifndef IP_FRAG_H
#define IP_FRAG_H

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#define IP4_FRAG_NODE_NAME "ip4-frag"
#define IP6_FRAG_NODE_NAME "ip6-frag"

extern vlib_node_registration_t ip4_frag_node;
extern vlib_node_registration_t ip6_frag_node;

typedef enum
{
  IP_FRAG_NEXT_IP_REWRITE,
  IP_FRAG_NEXT_IP_REWRITE_MIDCHAIN,
  IP_FRAG_NEXT_IP4_LOOKUP,
  IP_FRAG_NEXT_IP6_LOOKUP,
  IP_FRAG_NEXT_ICMP_ERROR,
  IP_FRAG_NEXT_DROP,
  IP_FRAG_N_NEXT
} ip_frag_next_t;

#define foreach_ip_frag_error				\
  /* Must be first. */					\
 _(NONE, "packet fragmented")				\
 _(SMALL_PACKET, "packet smaller than MTU")             \
 _(FRAGMENT_SENT, "number of sent fragments")           \
 _(CANT_FRAGMENT_HEADER, "can't fragment header")	\
 _(DONT_FRAGMENT_SET, "can't fragment this packet")	\
 _(MALFORMED, "malformed packet")                       \
 _(MEMORY, "could not allocate buffer")                 \
 _(UNKNOWN, "unknown error")

typedef enum
{
#define _(sym,str) IP_FRAG_ERROR_##sym,
  foreach_ip_frag_error
#undef _
    IP_FRAG_N_ERROR,
} ip_frag_error_t;

extern char *ip4_frag_error_strings[];

static u32 running_fragment_id;

static void
frag_set_sw_if_index (vlib_buffer_t *to, vlib_buffer_t *from)
{
  vnet_buffer (to)->sw_if_index[VLIB_RX] =
    vnet_buffer (from)->sw_if_index[VLIB_RX];
  vnet_buffer (to)->sw_if_index[VLIB_TX] =
    vnet_buffer (from)->sw_if_index[VLIB_TX];

  /* Copy adj_index in case DPO based node is sending for the
   * fragmentation, the packet would be sent back to the proper
   * DPO next node and Index
   */
  vnet_buffer (to)->ip.adj_index[VLIB_RX] =
    vnet_buffer (from)->ip.adj_index[VLIB_RX];
  vnet_buffer (to)->ip.adj_index[VLIB_TX] =
    vnet_buffer (from)->ip.adj_index[VLIB_TX];

  /* Copy QoS Bits */
  if (PREDICT_TRUE (from->flags & VNET_BUFFER_F_QOS_DATA_VALID))
    {
      vnet_buffer2 (to)->qos = vnet_buffer2 (from)->qos;
      to->flags |= VNET_BUFFER_F_QOS_DATA_VALID;
    }
}

always_inline vlib_buffer_t *
frag_buffer_alloc (vlib_buffer_t *org_b, u32 *bi)
{
  vlib_main_t *vm = vlib_get_main ();
  if (vlib_buffer_alloc (vm, bi, 1) != 1)
    return 0;

  vlib_buffer_t *b = vlib_get_buffer (vm, *bi);
  vlib_buffer_copy_trace_flag (vm, org_b, *bi);

  return b;
}

/*
 * Limitation: Does follow buffer chains in the packet to fragment,
 * but does not generate buffer chains. I.e. a fragment is always
 * contained with in a single buffer and limited to the max buffer
 * size.
 * from_bi: current pointer must point to IPv4 header
 */
always_inline ip_frag_error_t
ip4_frag_do_fragment (vlib_main_t *vm, u32 from_bi, u16 mtu,
		      u16 l2unfragmentablesize, u32 **buffer)
{
  vlib_buffer_t *from_b;
  ip4_header_t *ip4;
  u16 len, max, rem, ip_frag_id, ip_frag_offset, head_bytes;
  u8 *org_from_packet, more;

  from_b = vlib_get_buffer (vm, from_bi);
  org_from_packet = vlib_buffer_get_current (from_b);
  ip4 = vlib_buffer_get_current (from_b) + l2unfragmentablesize;

  rem = clib_net_to_host_u16 (ip4->length) - sizeof (ip4_header_t);
  head_bytes = sizeof (ip4_header_t) + l2unfragmentablesize;
  max = (clib_min (mtu, vlib_buffer_get_default_data_size (vm)) - head_bytes) &
	~0x7;

  if (rem > (vlib_buffer_length_in_chain (vm, from_b) - sizeof (ip4_header_t)))
    {
      return IP_FRAG_ERROR_MALFORMED;
    }

  if (mtu < sizeof (ip4_header_t))
    {
      return IP_FRAG_ERROR_CANT_FRAGMENT_HEADER;
    }

  if (ip4->flags_and_fragment_offset &
      clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT))
    {
      return IP_FRAG_ERROR_DONT_FRAGMENT_SET;
    }

  if (ip4_is_fragment (ip4))
    {
      ip_frag_id = ip4->fragment_id;
      ip_frag_offset = ip4_get_fragment_offset (ip4);
      more = !(!(ip4->flags_and_fragment_offset &
		 clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS)));
    }
  else
    {
      ip_frag_id = (++running_fragment_id);
      ip_frag_offset = 0;
      more = 0;
    }

  u8 *from_data = (void *) (ip4 + 1);
  vlib_buffer_t *org_from_b = from_b;
  u16 fo = 0;
  u16 left_in_from_buffer = from_b->current_length - head_bytes;
  u16 ptr = 0;

  /* Do the actual fragmentation */
  while (rem)
    {
      u32 to_bi;
      vlib_buffer_t *to_b;
      ip4_header_t *to_ip4;
      u8 *to_data;

      len = (rem > max ? max : rem);
      if (len != rem) /* Last fragment does not need to divisible by 8 */
	len &= ~0x7;
      if ((to_b = frag_buffer_alloc (org_from_b, &to_bi)) == 0)
	{
	  return IP_FRAG_ERROR_MEMORY;
	}
      vec_add1 (*buffer, to_bi);
      frag_set_sw_if_index (to_b, org_from_b);

      /* Copy ip4 header */
      to_data = vlib_buffer_get_current (to_b);
      clib_memcpy_fast (to_data, org_from_packet, head_bytes);
      to_ip4 = (ip4_header_t *) (to_data + l2unfragmentablesize);
      to_data = (void *) (to_ip4 + 1);
      vnet_buffer (to_b)->l3_hdr_offset = to_b->current_data;
      vlib_buffer_copy_trace_flag (vm, from_b, to_bi);
      to_b->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;

      if (from_b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID)
	{
	  vnet_buffer (to_b)->l4_hdr_offset =
	    (vnet_buffer (to_b)->l3_hdr_offset +
	     (vnet_buffer (from_b)->l4_hdr_offset -
	      vnet_buffer (from_b)->l3_hdr_offset));
	  to_b->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
	}

      /* Spin through from buffers filling up the to buffer */
      u16 left_in_to_buffer = len, to_ptr = 0;
      while (1)
	{
	  u16 bytes_to_copy;

	  /* Figure out how many bytes we can safely copy */
	  bytes_to_copy = left_in_to_buffer <= left_in_from_buffer ?
			    left_in_to_buffer :
			    left_in_from_buffer;
	  clib_memcpy_fast (to_data + to_ptr, from_data + ptr, bytes_to_copy);
	  left_in_to_buffer -= bytes_to_copy;
	  ptr += bytes_to_copy;
	  left_in_from_buffer -= bytes_to_copy;
	  if (left_in_to_buffer == 0)
	    break;

	  ASSERT (left_in_from_buffer <= 0);
	  /* Move buffer */
	  if (!(from_b->flags & VLIB_BUFFER_NEXT_PRESENT))
	    {
	      return IP_FRAG_ERROR_MALFORMED;
	    }
	  from_b = vlib_get_buffer (vm, from_b->next_buffer);
	  from_data = (u8 *) vlib_buffer_get_current (from_b);
	  ptr = 0;
	  left_in_from_buffer = from_b->current_length;
	  to_ptr += bytes_to_copy;
	}

      to_b->flags |= VNET_BUFFER_F_IS_IP4;
      to_b->current_length = len + head_bytes;

      to_ip4->fragment_id = ip_frag_id;
      to_ip4->flags_and_fragment_offset =
	clib_host_to_net_u16 ((fo >> 3) + ip_frag_offset);
      to_ip4->flags_and_fragment_offset |=
	clib_host_to_net_u16 (((len != rem) || more) << 13);
      to_ip4->length = clib_host_to_net_u16 (len + sizeof (ip4_header_t));
      to_ip4->checksum = ip4_header_checksum (to_ip4);

      /* we've just done the IP checksum .. */
      vnet_buffer_offload_flags_clear (to_b, VNET_BUFFER_OFFLOAD_F_IP_CKSUM);

      rem -= len;
      fo += len;
    }

  return IP_FRAG_ERROR_NONE;
}

/*
 * Fragments the packet given in from_bi. Fragments are returned in the buffer
 * vector. Caller must ensure the original packet is freed. from_bi: current
 * pointer must point to IPv6 header
 */
always_inline ip_frag_error_t
ip6_frag_do_fragment (vlib_main_t *vm, u32 from_bi, u16 mtu,
		      u16 l2unfragmentablesize, u32 **buffer)
{
  vlib_buffer_t *from_b;
  ip6_header_t *ip6;
  u16 len, max, rem, ip_frag_id;
  u8 *org_from_packet;
  u16 head_bytes;

  from_b = vlib_get_buffer (vm, from_bi);
  org_from_packet = vlib_buffer_get_current (from_b);
  ip6 = vlib_buffer_get_current (from_b) + l2unfragmentablesize;

  head_bytes =
    (sizeof (ip6_header_t) + sizeof (ip6_frag_hdr_t) + l2unfragmentablesize);
  rem = clib_net_to_host_u16 (ip6->payload_length);
  max = (clib_min (mtu, vlib_buffer_get_default_data_size (vm)) - head_bytes) &
	~0x7;

  if (rem > (vlib_buffer_length_in_chain (vm, from_b) - sizeof (ip6_header_t)))
    {
      return IP_FRAG_ERROR_MALFORMED;
    }

  /* TODO: Look through header chain for fragmentation header */
  if (ip6->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
    {
      return IP_FRAG_ERROR_MALFORMED;
    }

  u8 *from_data = (void *) (ip6 + 1);
  vlib_buffer_t *org_from_b = from_b;
  u16 fo = 0;
  u16 left_in_from_buffer =
    from_b->current_length - (l2unfragmentablesize + sizeof (ip6_header_t));
  u16 ptr = 0;

  ip_frag_id = ++running_fragment_id; // Fix

  /* Do the actual fragmentation */
  while (rem)
    {
      u32 to_bi;
      vlib_buffer_t *to_b;
      ip6_header_t *to_ip6;
      ip6_frag_hdr_t *to_frag_hdr;
      u8 *to_data;

      len = (rem > max ? max : rem);
      if (len != rem) /* Last fragment does not need to divisible by 8 */
	len &= ~0x7;
      if ((to_b = frag_buffer_alloc (org_from_b, &to_bi)) == 0)
	{
	  return IP_FRAG_ERROR_MEMORY;
	}
      vec_add1 (*buffer, to_bi);
      frag_set_sw_if_index (to_b, org_from_b);

      /* Copy ip6 header */
      clib_memcpy_fast (to_b->data, org_from_packet,
			l2unfragmentablesize + sizeof (ip6_header_t));
      to_ip6 = vlib_buffer_get_current (to_b) + l2unfragmentablesize;
      to_frag_hdr = (ip6_frag_hdr_t *) (to_ip6 + 1);
      to_data = (void *) (to_frag_hdr + 1);

      vnet_buffer (to_b)->l3_hdr_offset = to_b->current_data;
      to_b->flags |= VNET_BUFFER_F_L3_HDR_OFFSET_VALID;

      if (from_b->flags & VNET_BUFFER_F_L4_HDR_OFFSET_VALID)
	{
	  vnet_buffer (to_b)->l4_hdr_offset =
	    (vnet_buffer (to_b)->l3_hdr_offset +
	     (vnet_buffer (from_b)->l4_hdr_offset -
	      vnet_buffer (from_b)->l3_hdr_offset));
	  to_b->flags |= VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
	}
      to_b->flags |= VNET_BUFFER_F_IS_IP6;

      /* Spin through from buffers filling up the to buffer */
      u16 left_in_to_buffer = len, to_ptr = 0;
      while (1)
	{
	  u16 bytes_to_copy;

	  /* Figure out how many bytes we can safely copy */
	  bytes_to_copy = left_in_to_buffer <= left_in_from_buffer ?
			    left_in_to_buffer :
			    left_in_from_buffer;
	  clib_memcpy_fast (to_data + to_ptr, from_data + ptr, bytes_to_copy);
	  left_in_to_buffer -= bytes_to_copy;
	  ptr += bytes_to_copy;
	  left_in_from_buffer -= bytes_to_copy;
	  if (left_in_to_buffer == 0)
	    break;

	  ASSERT (left_in_from_buffer <= 0);
	  /* Move buffer */
	  if (!(from_b->flags & VLIB_BUFFER_NEXT_PRESENT))
	    {
	      return IP_FRAG_ERROR_MALFORMED;
	    }
	  from_b = vlib_get_buffer (vm, from_b->next_buffer);
	  from_data = (u8 *) vlib_buffer_get_current (from_b);
	  ptr = 0;
	  left_in_from_buffer = from_b->current_length;
	  to_ptr += bytes_to_copy;
	}

      to_b->current_length = len + head_bytes;
      to_ip6->payload_length =
	clib_host_to_net_u16 (len + sizeof (ip6_frag_hdr_t));
      to_ip6->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
      to_frag_hdr->fragment_offset_and_more =
	ip6_frag_hdr_offset_and_more ((fo >> 3), len != rem);
      to_frag_hdr->identification = ip_frag_id;
      to_frag_hdr->next_hdr = ip6->protocol;
      to_frag_hdr->rsv = 0;

      rem -= len;
      fo += len;
    }

  return IP_FRAG_ERROR_NONE;
}

always_inline void
ip_frag_set_vnet_buffer (vlib_buffer_t *b, u16 mtu, u8 next_index, u8 flags)
{
  vnet_buffer (b)->ip_frag.mtu = mtu;
  vnet_buffer (b)->ip_frag.next_index = next_index;
  vnet_buffer (b)->ip_frag.flags = flags;
}

#endif /* ifndef IP_FRAG_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
