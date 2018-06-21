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

#define IP_FRAG_FLAG_IP4_HEADER 0x01	//Encapsulating IPv4 header
#define IP_FRAG_FLAG_IP6_HEADER 0x02	//Encapsulating IPv6 header

#define IP4_FRAG_NODE_NAME "ip4-frag"
#define IP6_FRAG_NODE_NAME "ip6-frag"

extern vlib_node_registration_t ip4_frag_node;
extern vlib_node_registration_t ip6_frag_node;

typedef enum
{
  IP4_FRAG_NEXT_IP4_LOOKUP,
  IP4_FRAG_NEXT_IP6_LOOKUP,
  IP4_FRAG_NEXT_ICMP_ERROR,
  IP4_FRAG_NEXT_DROP,
  IP4_FRAG_N_NEXT
} ip4_frag_next_t;

typedef enum
{
  IP6_FRAG_NEXT_IP4_LOOKUP,
  IP6_FRAG_NEXT_IP6_LOOKUP,
  IP6_FRAG_NEXT_DROP,
  IP6_FRAG_N_NEXT
} ip6_frag_next_t;

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

void ip_frag_set_vnet_buffer (vlib_buffer_t * b, u16 offset, u16 mtu,
			      u8 next_index, u8 flags);

extern u32 running_fragment_id;

always_inline void
ip4_frag_do_fragment (vlib_main_t * vm, u32 pi, u32 ** buffer,
		      ip_frag_error_t * error)
{
  vlib_buffer_t *p;
  ip4_header_t *ip4;
  u16 mtu, ptr, len, max, rem, offset, ip_frag_id, ip_frag_offset;
  u8 *packet, more;

  vec_add1 (*buffer, pi);
  p = vlib_get_buffer (vm, pi);
  offset = vnet_buffer (p)->ip_frag.header_offset;
  mtu = vnet_buffer (p)->ip_frag.mtu;
  packet = (u8 *) vlib_buffer_get_current (p);
  ip4 = (ip4_header_t *) (packet + offset);

  rem = clib_net_to_host_u16 (ip4->length) - sizeof (*ip4);
  ptr = 0;
  max = (mtu - sizeof (*ip4) - vnet_buffer (p)->ip_frag.header_offset) & ~0x7;

  if (rem < (p->current_length - offset - sizeof (*ip4)))
    {
      *error = IP_FRAG_ERROR_MALFORMED;
      return;
    }

  if (mtu < sizeof (*ip4))
    {
      *error = IP_FRAG_ERROR_CANT_FRAGMENT_HEADER;
      return;
    }

  if (ip4->flags_and_fragment_offset &
      clib_host_to_net_u16 (IP4_HEADER_FLAG_DONT_FRAGMENT))
    {
      *error = IP_FRAG_ERROR_DONT_FRAGMENT_SET;
      return;
    }

  if (p->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      *error = IP_FRAG_ERROR_MALFORMED;
      return;
    }

  if (ip4_is_fragment (ip4))
    {
      ip_frag_id = ip4->fragment_id;
      ip_frag_offset = ip4_get_fragment_offset (ip4);
      more =
	!(!(ip4->flags_and_fragment_offset &
	    clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS)));
    }
  else
    {
      ip_frag_id = (++running_fragment_id);
      ip_frag_offset = 0;
      more = 0;
    }

  //Do the actual fragmentation
  while (rem)
    {
      u32 bi;
      vlib_buffer_t *b;
      ip4_header_t *fip4;

      len =
	(rem >
	 (mtu - sizeof (*ip4) -
	  vnet_buffer (p)->ip_frag.header_offset)) ? max : rem;

      if (ptr == 0)
	{
	  bi = pi;
	  b = p;
	  fip4 = (ip4_header_t *) (vlib_buffer_get_current (b) + offset);
	}
      else
	{
	  if (!vlib_buffer_alloc (vm, &bi, 1))
	    {
	      *error = IP_FRAG_ERROR_MEMORY;
	      return;
	    }
	  vec_add1 (*buffer, bi);
	  b = vlib_get_buffer (vm, bi);
	  vnet_buffer (b)->sw_if_index[VLIB_RX] =
	    vnet_buffer (p)->sw_if_index[VLIB_RX];
	  vnet_buffer (b)->sw_if_index[VLIB_TX] =
	    vnet_buffer (p)->sw_if_index[VLIB_TX];
	  /* Copy Adj_index in case DPO based node is sending for the fragmentation,
	     the packet would be sent back to the proper DPO next node and Index */
	  vnet_buffer (b)->ip.adj_index[VLIB_RX] =
	    vnet_buffer (p)->ip.adj_index[VLIB_RX];
	  vnet_buffer (b)->ip.adj_index[VLIB_TX] =
	    vnet_buffer (p)->ip.adj_index[VLIB_TX];
	  fip4 = (ip4_header_t *) (vlib_buffer_get_current (b) + offset);

	  //Copy offset and ip4 header
	  clib_memcpy (b->data, packet, offset + sizeof (*ip4));
	  //Copy data
	  clib_memcpy (((u8 *) (fip4)) + sizeof (*fip4),
		       packet + offset + sizeof (*fip4) + ptr, len);
	}
      b->current_length = offset + len + sizeof (*fip4);

      fip4->fragment_id = ip_frag_id;
      fip4->flags_and_fragment_offset =
	clib_host_to_net_u16 ((ptr >> 3) + ip_frag_offset);
      fip4->flags_and_fragment_offset |=
	clib_host_to_net_u16 (((len != rem) || more) << 13);
      // ((len0 != rem0) || more0) << 13 is optimization for
      // ((len0 != rem0) || more0) ? IP4_HEADER_FLAG_MORE_FRAGMENTS : 0
      fip4->length = clib_host_to_net_u16 (len + sizeof (*fip4));
      fip4->checksum = ip4_header_checksum (fip4);

      if (vnet_buffer (p)->ip_frag.flags & IP_FRAG_FLAG_IP4_HEADER)
	{
	  //Encapsulating ipv4 header
	  ip4_header_t *encap_header4 =
	    (ip4_header_t *) vlib_buffer_get_current (b);
	  encap_header4->length = clib_host_to_net_u16 (b->current_length);
	  encap_header4->checksum = ip4_header_checksum (encap_header4);
	}
      else if (vnet_buffer (p)->ip_frag.flags & IP_FRAG_FLAG_IP6_HEADER)
	{
	  //Encapsulating ipv6 header
	  ip6_header_t *encap_header6 =
	    (ip6_header_t *) vlib_buffer_get_current (b);
	  encap_header6->payload_length =
	    clib_host_to_net_u16 (b->current_length -
				  sizeof (*encap_header6));
	}

      rem -= len;
      ptr += len;
    }
}

always_inline void
ip6_frag_do_fragment (vlib_main_t * vm, u32 pi, u32 ** buffer,
		      ip_frag_error_t * error)
{
  vlib_buffer_t *p;
  ip6_header_t *ip6_hdr;
  ip6_frag_hdr_t *frag_hdr;
  u8 *payload, *next_header;

  p = vlib_get_buffer (vm, pi);

  //Parsing the IPv6 headers
  ip6_hdr =
    vlib_buffer_get_current (p) + vnet_buffer (p)->ip_frag.header_offset;
  payload = (u8 *) (ip6_hdr + 1);
  next_header = &ip6_hdr->protocol;
  if (*next_header == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
    {
      next_header = payload;
      payload += payload[1] * 8;
    }

  if (*next_header == IP_PROTOCOL_IP6_DESTINATION_OPTIONS)
    {
      next_header = payload;
      payload += payload[1] * 8;
    }

  if (*next_header == IP_PROTOCOL_IPV6_ROUTE)
    {
      next_header = payload;
      payload += payload[1] * 8;
    }

  if (PREDICT_FALSE
      (payload >= (u8 *) vlib_buffer_get_current (p) + p->current_length))
    {
      //A malicious packet could set an extension header with a too big size
      //and make us modify another vlib_buffer
      *error = IP_FRAG_ERROR_MALFORMED;
      return;
    }

  if (p->flags & VLIB_BUFFER_NEXT_PRESENT)
    {
      *error = IP_FRAG_ERROR_MALFORMED;
      return;
    }

  u8 has_more;
  u16 initial_offset;
  if (*next_header == IP_PROTOCOL_IPV6_FRAGMENTATION)
    {
      //The fragmentation header is already there
      frag_hdr = (ip6_frag_hdr_t *) payload;
      has_more = ip6_frag_hdr_more (frag_hdr);
      initial_offset = ip6_frag_hdr_offset (frag_hdr);
    }
  else
    {
      //Insert a fragmentation header in the packet
      u8 nh = *next_header;
      *next_header = IP_PROTOCOL_IPV6_FRAGMENTATION;
      vlib_buffer_advance (p, -sizeof (*frag_hdr));
      u8 *start = vlib_buffer_get_current (p);
      memmove (start, start + sizeof (*frag_hdr),
	       payload - (start + sizeof (*frag_hdr)));
      frag_hdr = (ip6_frag_hdr_t *) (payload - sizeof (*frag_hdr));
      frag_hdr->identification = ++running_fragment_id;
      frag_hdr->next_hdr = nh;
      frag_hdr->rsv = 0;
      has_more = 0;
      initial_offset = 0;
    }
  payload = (u8 *) (frag_hdr + 1);

  u16 headers_len = payload - (u8 *) vlib_buffer_get_current (p);
  u16 max_payload = vnet_buffer (p)->ip_frag.mtu - headers_len;
  u16 rem = p->current_length - headers_len;
  u16 ptr = 0;

  if (max_payload < 8)
    {
      *error = IP_FRAG_ERROR_CANT_FRAGMENT_HEADER;
      return;
    }

  while (rem)
    {
      u32 bi;
      vlib_buffer_t *b;
      u16 len = (rem > max_payload) ? (max_payload & ~0x7) : rem;
      rem -= len;

      if (ptr != 0)
	{
	  if (!vlib_buffer_alloc (vm, &bi, 1))
	    {
	      *error = IP_FRAG_ERROR_MEMORY;
	      return;
	    }
	  b = vlib_get_buffer (vm, bi);
	  vnet_buffer (b)->sw_if_index[VLIB_RX] =
	    vnet_buffer (p)->sw_if_index[VLIB_RX];
	  vnet_buffer (b)->sw_if_index[VLIB_TX] =
	    vnet_buffer (p)->sw_if_index[VLIB_TX];

	  /* Copy Adj_index in case DPO based node is sending for the fragmentation,
	     the packet would be sent back to the proper DPO next node and Index */
	  vnet_buffer (b)->ip.adj_index[VLIB_RX] =
	    vnet_buffer (p)->ip.adj_index[VLIB_RX];
	  vnet_buffer (b)->ip.adj_index[VLIB_TX] =
	    vnet_buffer (p)->ip.adj_index[VLIB_TX];

	  clib_memcpy (vlib_buffer_get_current (b),
		       vlib_buffer_get_current (p), headers_len);
	  clib_memcpy (vlib_buffer_get_current (b) + headers_len,
		       payload + ptr, len);
	  frag_hdr =
	    vlib_buffer_get_current (b) + headers_len - sizeof (*frag_hdr);
	}
      else
	{
	  bi = pi;
	  b = vlib_get_buffer (vm, bi);
	  //frag_hdr already set here
	}

      ip6_hdr =
	vlib_buffer_get_current (b) + vnet_buffer (p)->ip_frag.header_offset;
      frag_hdr->fragment_offset_and_more =
	ip6_frag_hdr_offset_and_more (initial_offset + (ptr >> 3),
				      (rem || has_more));
      b->current_length = headers_len + len;
      ip6_hdr->payload_length =
	clib_host_to_net_u16 (b->current_length -
			      vnet_buffer (p)->ip_frag.header_offset -
			      sizeof (*ip6_hdr));

      if (vnet_buffer (p)->ip_frag.flags & IP_FRAG_FLAG_IP4_HEADER)
	{
	  //Encapsulating ipv4 header
	  ip4_header_t *encap_header4 =
	    (ip4_header_t *) vlib_buffer_get_current (b);
	  encap_header4->length = clib_host_to_net_u16 (b->current_length);
	  encap_header4->checksum = ip4_header_checksum (encap_header4);
	}
      else if (vnet_buffer (p)->ip_frag.flags & IP_FRAG_FLAG_IP6_HEADER)
	{
	  //Encapsulating ipv6 header
	  ip6_header_t *encap_header6 =
	    (ip6_header_t *) vlib_buffer_get_current (b);
	  encap_header6->payload_length =
	    clib_host_to_net_u16 (b->current_length -
				  sizeof (*encap_header6));
	}

      vec_add1 (*buffer, bi);

      ptr += len;
    }
}

#endif /* ifndef IP_FRAG_H */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
