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
  u16 mtu;
  u8 next;
  u16 n_fragments;
  u16 pkt_size;
} ip_frag_trace_t;

#ifndef CLIB_MARCH_VARIANT
vlib_node_registration_t ip4_frag_node;
vlib_node_registration_t ip6_frag_node;

char *ip4_frag_error_strings[] = {
#define _(sym, string) string,
  foreach_ip_frag_error
#undef _
};
#endif

static u8 *
format_ip_frag_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_frag_trace_t *t = va_arg (*args, ip_frag_trace_t *);
  s = format (s, "mtu: %u pkt-size: %u fragments: %u next: %d", t->mtu,
	      t->pkt_size, t->n_fragments, t->next);
  return s;
}

always_inline uword
frag_node_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		  vlib_frame_t *frame, u32 node_index, bool is_ip6)
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
	      tr->pkt_size = vlib_buffer_length_in_chain (vm, p0);
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

VLIB_NODE_FN (ip4_frag_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return frag_node_inline (vm, node, frame, node->node_index, 0 /* is_ip6 */);
}

VLIB_NODE_FN (ip6_frag_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  return frag_node_inline (vm, node, frame, node->node_index, 1 /* is_ip6 */);
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ip4_frag_node) = {
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
