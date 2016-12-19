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
 * IPv4 Fragmentation Node
 *
 *
 */

#include "ip_frag.h"

#include <vnet/ip/ip.h>


typedef struct
{
  u8 ipv6;
  u16 header_offset;
  u16 mtu;
  u8 next;
  u16 n_fragments;
} ip_frag_trace_t;

static u8 *
format_ip_frag_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_frag_trace_t *t = va_arg (*args, ip_frag_trace_t *);
  s = format (s, "IPv%s offset: %u mtu: %u fragments: %u",
	      t->ipv6 ? "6" : "4", t->header_offset, t->mtu, t->n_fragments);
  return s;
}

static u32 running_fragment_id;

static void
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

  if (ip4_is_fragment (ip4))
    {
      ip_frag_id = ip4->fragment_id;
      ip_frag_offset = ip4_get_fragment_offset (ip4);
      more =
	! !(ip4->flags_and_fragment_offset &
	    clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS));
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

void
ip_frag_set_vnet_buffer (vlib_buffer_t * b, u16 offset, u16 mtu,
			 u8 next_index, u8 flags)
{
  vnet_buffer (b)->ip_frag.header_offset = offset;
  vnet_buffer (b)->ip_frag.mtu = mtu;
  vnet_buffer (b)->ip_frag.next_index = next_index;
  vnet_buffer (b)->ip_frag.flags = flags;
}

static uword
ip4_frag (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip4_frag_node.index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  u32 frag_sent = 0, small_packets = 0;
  u32 *buffer = 0;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0, *frag_from, frag_left;
	  vlib_buffer_t *p0;
	  ip_frag_error_t error0;
	  ip4_frag_next_t next0;

	  //Note: The packet is not enqueued now.
	  //It is instead put in a vector where other fragments
	  //will be put as well.
	  pi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  error0 = IP_FRAG_ERROR_NONE;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip4_frag_do_fragment (vm, pi0, &buffer, &error0);

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip_frag_trace_t *tr =
		vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->header_offset = vnet_buffer (p0)->ip_frag.header_offset;
	      tr->mtu = vnet_buffer (p0)->ip_frag.mtu;
	      tr->ipv6 = 0;
	      tr->n_fragments = vec_len (buffer);
	      tr->next = vnet_buffer (p0)->ip_frag.next_index;
	    }

	  if (error0 == IP_FRAG_ERROR_DONT_FRAGMENT_SET)
	    {
	      icmp4_error_set_vnet_buffer (p0, ICMP4_destination_unreachable,
					   ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set,
					   vnet_buffer (p0)->ip_frag.mtu);
	      vlib_buffer_advance (p0,
				   vnet_buffer (p0)->ip_frag.header_offset);
	      next0 = IP4_FRAG_NEXT_ICMP_ERROR;
	    }
	  else
	    next0 =
	      (error0 ==
	       IP_FRAG_ERROR_NONE) ? vnet_buffer (p0)->
	      ip_frag.next_index : IP4_FRAG_NEXT_DROP;

	  if (error0 == IP_FRAG_ERROR_NONE)
	    {
	      frag_sent += vec_len (buffer);
	      small_packets += (vec_len (buffer) == 1);
	    }
	  else
	    vlib_error_count (vm, ip4_frag_node.index, error0, 1);

	  //Send fragments that were added in the frame
	  frag_from = buffer;
	  frag_left = vec_len (buffer);

	  while (frag_left > 0)
	    {
	      while (frag_left > 0 && n_left_to_next > 0)
		{
		  u32 i;
		  i = to_next[0] = frag_from[0];
		  frag_from += 1;
		  frag_left -= 1;
		  to_next += 1;
		  n_left_to_next -= 1;

		  vlib_get_buffer (vm, i)->error = error_node->errors[error0];
		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next, i,
						   next0);
		}
	      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	      vlib_get_next_frame (vm, node, next_index, to_next,
				   n_left_to_next);
	    }
	  vec_reset_length (buffer);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vec_free (buffer);

  vlib_node_increment_counter (vm, ip4_frag_node.index,
			       IP_FRAG_ERROR_FRAGMENT_SENT, frag_sent);
  vlib_node_increment_counter (vm, ip4_frag_node.index,
			       IP_FRAG_ERROR_SMALL_PACKET, small_packets);

  return frame->n_vectors;
}


static void
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

static uword
ip6_frag (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_frag_node.index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  u32 frag_sent = 0, small_packets = 0;
  u32 *buffer = 0;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0, *frag_from, frag_left;
	  vlib_buffer_t *p0;
	  ip_frag_error_t error0;
	  ip6_frag_next_t next0;

	  pi0 = from[0];
	  from += 1;
	  n_left_from -= 1;
	  error0 = IP_FRAG_ERROR_NONE;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip6_frag_do_fragment (vm, pi0, &buffer, &error0);

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip_frag_trace_t *tr =
		vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->header_offset = vnet_buffer (p0)->ip_frag.header_offset;
	      tr->mtu = vnet_buffer (p0)->ip_frag.mtu;
	      tr->ipv6 = 1;
	      tr->n_fragments = vec_len (buffer);
	      tr->next = vnet_buffer (p0)->ip_frag.next_index;
	    }

	  next0 =
	    (error0 ==
	     IP_FRAG_ERROR_NONE) ? vnet_buffer (p0)->
	    ip_frag.next_index : IP6_FRAG_NEXT_DROP;
	  frag_sent += vec_len (buffer);
	  small_packets += (vec_len (buffer) == 1);

	  //Send fragments that were added in the frame
	  frag_from = buffer;
	  frag_left = vec_len (buffer);
	  while (frag_left > 0)
	    {
	      while (frag_left > 0 && n_left_to_next > 0)
		{
		  u32 i;
		  i = to_next[0] = frag_from[0];
		  frag_from += 1;
		  frag_left -= 1;
		  to_next += 1;
		  n_left_to_next -= 1;

		  vlib_get_buffer (vm, i)->error = error_node->errors[error0];
		  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
						   to_next, n_left_to_next, i,
						   next0);
		}
	      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
	      vlib_get_next_frame (vm, node, next_index, to_next,
				   n_left_to_next);
	    }
	  vec_reset_length (buffer);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  vec_free (buffer);
  vlib_node_increment_counter (vm, ip6_frag_node.index,
			       IP_FRAG_ERROR_FRAGMENT_SENT, frag_sent);
  vlib_node_increment_counter (vm, ip6_frag_node.index,
			       IP_FRAG_ERROR_SMALL_PACKET, small_packets);

  return frame->n_vectors;
}

static char *ip4_frag_error_strings[] = {
#define _(sym,string) string,
  foreach_ip_frag_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_frag_node) = {
  .function = ip4_frag,
  .name = IP4_FRAG_NODE_NAME,
  .vector_size = sizeof (u32),
  .format_trace = format_ip_frag_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = IP_FRAG_N_ERROR,
  .error_strings = ip4_frag_error_strings,

  .n_next_nodes = IP4_FRAG_N_NEXT,
  .next_nodes = {
    [IP4_FRAG_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IP4_FRAG_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [IP4_FRAG_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [IP4_FRAG_NEXT_DROP] = "error-drop"
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip6_frag_node) = {
  .function = ip6_frag,
  .name = IP6_FRAG_NODE_NAME,
  .vector_size = sizeof (u32),
  .format_trace = format_ip_frag_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = IP_FRAG_N_ERROR,
  .error_strings = ip4_frag_error_strings,

  .n_next_nodes = IP6_FRAG_N_NEXT,
  .next_nodes = {
    [IP6_FRAG_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IP6_FRAG_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [IP6_FRAG_NEXT_DROP] = "error-drop"
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
