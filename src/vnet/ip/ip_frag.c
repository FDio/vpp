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
  s = format (s, "IPv%s mtu: %u fragments: %u next: %d",
	      t->ipv6 ? "6" : "4", t->mtu, t->n_fragments, t->next);
  return s;
}

static u32 running_fragment_id;

static void
frag_set_sw_if_index (vlib_buffer_t * to, vlib_buffer_t * from)
{
  vnet_buffer (to)->sw_if_index[VLIB_RX] =
    vnet_buffer (from)->sw_if_index[VLIB_RX];
  vnet_buffer (to)->sw_if_index[VLIB_TX] =
    vnet_buffer (from)->sw_if_index[VLIB_TX];

  /* Copy adj_index in case DPO based node is sending for the
   * fragmentation, the packet would be sent back to the proper
   * DPO next node and Index
   */
  vnet_buffer (to)->ip.adj_index = vnet_buffer (from)->ip.adj_index;

  /* Copy QoS Bits */
  if (PREDICT_TRUE (from->flags & VNET_BUFFER_F_QOS_DATA_VALID))
    {
      vnet_buffer2 (to)->qos = vnet_buffer2 (from)->qos;
      to->flags |= VNET_BUFFER_F_QOS_DATA_VALID;
    }
}

static vlib_buffer_t *
frag_buffer_alloc (vlib_buffer_t * org_b, u32 * bi)
{
  vlib_main_t *vm = vlib_get_main ();
  if (vlib_buffer_alloc (vm, bi, 1) != 1)
    return 0;

  vlib_buffer_t *b = vlib_get_buffer (vm, *bi);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b);
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
ip_frag_error_t
ip4_frag_do_fragment (vlib_main_t * vm, u32 from_bi, u16 mtu,
		      u16 l2unfragmentablesize, u32 ** buffer)
{
  vlib_buffer_t *from_b;
  ip4_header_t *ip4;
  u16 len, max, rem, ip_frag_id, ip_frag_offset;
  u8 *org_from_packet, more;

  from_b = vlib_get_buffer (vm, from_bi);
  org_from_packet = vlib_buffer_get_current (from_b);
  ip4 = vlib_buffer_get_current (from_b) + l2unfragmentablesize;

  rem = clib_net_to_host_u16 (ip4->length) - sizeof (ip4_header_t);
  max =
    (clib_min (mtu, vlib_buffer_get_default_data_size (vm)) -
     sizeof (ip4_header_t)) & ~0x7;

  if (rem >
      (vlib_buffer_length_in_chain (vm, from_b) - sizeof (ip4_header_t)))
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

  u8 *from_data = (void *) (ip4 + 1);
  vlib_buffer_t *org_from_b = from_b;
  u16 fo = 0;
  u16 left_in_from_buffer =
    from_b->current_length - (l2unfragmentablesize + sizeof (ip4_header_t));
  u16 ptr = 0;

  /* Do the actual fragmentation */
  while (rem)
    {
      u32 to_bi;
      vlib_buffer_t *to_b;
      ip4_header_t *to_ip4;
      u8 *to_data;

      len = (rem > max ? max : rem);
      if (len != rem)		/* Last fragment does not need to divisible by 8 */
	len &= ~0x7;
      if ((to_b = frag_buffer_alloc (org_from_b, &to_bi)) == 0)
	{
	  return IP_FRAG_ERROR_MEMORY;
	}
      vec_add1 (*buffer, to_bi);
      frag_set_sw_if_index (to_b, org_from_b);

      /* Copy ip4 header */
      to_data = vlib_buffer_get_current (to_b);
      clib_memcpy_fast (to_data, org_from_packet,
			l2unfragmentablesize + sizeof (ip4_header_t));
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
	    left_in_to_buffer : left_in_from_buffer;
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
      to_b->current_length =
	len + sizeof (ip4_header_t) + l2unfragmentablesize;

      to_ip4->fragment_id = ip_frag_id;
      to_ip4->flags_and_fragment_offset =
	clib_host_to_net_u16 ((fo >> 3) + ip_frag_offset);
      to_ip4->flags_and_fragment_offset |=
	clib_host_to_net_u16 (((len != rem) || more) << 13);
      to_ip4->length = clib_host_to_net_u16 (len + sizeof (ip4_header_t));
      to_ip4->checksum = ip4_header_checksum (to_ip4);

      /* we've just done the IP checksum .. */
      to_b->flags &= ~VNET_BUFFER_F_OFFLOAD_IP_CKSUM;

      rem -= len;
      fo += len;
    }

  return IP_FRAG_ERROR_NONE;
}

void
ip_frag_set_vnet_buffer (vlib_buffer_t * b, u16 mtu, u8 next_index, u8 flags)
{
  vnet_buffer (b)->ip_frag.mtu = mtu;
  vnet_buffer (b)->ip_frag.next_index = next_index;
  vnet_buffer (b)->ip_frag.flags = flags;
}


static inline uword
frag_node_inline (vlib_main_t * vm, vlib_node_runtime_t * node,
		  vlib_frame_t * frame, u32 node_index, bool is_ip6)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, node_index);
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
	  int next0;

	  /*
	   * Note: The packet is not enqueued now. It is instead put
	   * in a vector where other fragments will be put as well.
	   */
	  pi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  u16 mtu = vnet_buffer (p0)->ip_frag.mtu;
	  if (is_ip6)
	    error0 = ip6_frag_do_fragment (vm, pi0, mtu, 0, &buffer);
	  else
	    error0 = ip4_frag_do_fragment (vm, pi0, mtu, 0, &buffer);

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip_frag_trace_t *tr =
		vlib_add_trace (vm, node, p0, sizeof (*tr));
	      tr->mtu = mtu;
	      tr->ipv6 = is_ip6 ? 1 : 0;
	      tr->n_fragments = vec_len (buffer);
	      tr->next = vnet_buffer (p0)->ip_frag.next_index;
	    }

	  if (!is_ip6 && error0 == IP_FRAG_ERROR_DONT_FRAGMENT_SET)
	    {
	      icmp4_error_set_vnet_buffer (p0, ICMP4_destination_unreachable,
					   ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set,
					   vnet_buffer (p0)->ip_frag.mtu);
	      next0 = IP_FRAG_NEXT_ICMP_ERROR;
	    }
	  else
	    {
	      next0 = (error0 == IP_FRAG_ERROR_NONE ?
		       vnet_buffer (p0)->ip_frag.next_index :
		       IP_FRAG_NEXT_DROP);
	    }

	  if (error0 == IP_FRAG_ERROR_NONE)
	    {
	      /* Free original buffer chain */
	      frag_sent += vec_len (buffer);
	      small_packets += (vec_len (buffer) == 1);
	      vlib_buffer_free_one (vm, pi0);	/* Free original packet */
	    }
	  else
	    {
	      vlib_error_count (vm, node_index, error0, 1);
	      vec_add1 (buffer, pi0);	/* Get rid of the original buffer */
	    }

	  /* Send fragments that were added in the frame */
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

  vlib_node_increment_counter (vm, node_index,
			       IP_FRAG_ERROR_FRAGMENT_SENT, frag_sent);
  vlib_node_increment_counter (vm, node_index,
			       IP_FRAG_ERROR_SMALL_PACKET, small_packets);

  return frame->n_vectors;
}



static uword
ip4_frag (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return frag_node_inline (vm, node, frame, ip4_frag_node.index,
			   0 /* is_ip6 */ );
}

static uword
ip6_frag (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return frag_node_inline (vm, node, frame, ip6_frag_node.index,
			   1 /* is_ip6 */ );
}

/*
 * Fragments the packet given in from_bi. Fragments are returned in the buffer vector.
 * Caller must ensure the original packet is freed.
 * from_bi: current pointer must point to IPv6 header
 */
ip_frag_error_t
ip6_frag_do_fragment (vlib_main_t * vm, u32 from_bi, u16 mtu,
		      u16 l2unfragmentablesize, u32 ** buffer)
{
  vlib_buffer_t *from_b;
  ip6_header_t *ip6;
  u16 len, max, rem, ip_frag_id;
  u8 *org_from_packet;

  from_b = vlib_get_buffer (vm, from_bi);
  org_from_packet = vlib_buffer_get_current (from_b);
  ip6 = vlib_buffer_get_current (from_b) + l2unfragmentablesize;

  rem = clib_net_to_host_u16 (ip6->payload_length);
  max = (mtu - sizeof (ip6_header_t) - sizeof (ip6_frag_hdr_t)) & ~0x7;	// TODO: Is max correct??

  if (rem >
      (vlib_buffer_length_in_chain (vm, from_b) - sizeof (ip6_header_t)))
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

  ip_frag_id = ++running_fragment_id;	// Fix

  /* Do the actual fragmentation */
  while (rem)
    {
      u32 to_bi;
      vlib_buffer_t *to_b;
      ip6_header_t *to_ip6;
      ip6_frag_hdr_t *to_frag_hdr;
      u8 *to_data;

      len =
	(rem >
	 (mtu - sizeof (ip6_header_t) - sizeof (ip6_frag_hdr_t)) ? max : rem);
      if (len != rem)		/* Last fragment does not need to divisible by 8 */
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
      to_ip6 = vlib_buffer_get_current (to_b);
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
	    left_in_to_buffer : left_in_from_buffer;
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

      to_b->current_length =
	len + sizeof (ip6_header_t) + sizeof (ip6_frag_hdr_t);
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

  .n_next_nodes = IP_FRAG_N_NEXT,
  .next_nodes = {
    [IP_FRAG_NEXT_IP_REWRITE] = "ip4-rewrite",
    [IP_FRAG_NEXT_IP_REWRITE_MIDCHAIN] = "ip4-midchain",
    [IP_FRAG_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IP_FRAG_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [IP_FRAG_NEXT_ICMP_ERROR] = "ip4-icmp-error",
    [IP_FRAG_NEXT_DROP] = "ip4-drop"
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

  .n_next_nodes = IP_FRAG_N_NEXT,
  .next_nodes = {
    [IP_FRAG_NEXT_IP_REWRITE] = "ip6-rewrite",
    [IP_FRAG_NEXT_IP_REWRITE_MIDCHAIN] = "ip6-midchain",
    [IP_FRAG_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IP_FRAG_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [IP_FRAG_NEXT_ICMP_ERROR] = "error-drop",
    [IP_FRAG_NEXT_DROP] = "ip6-drop"
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
