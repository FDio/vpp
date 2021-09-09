/*
 *------------------------------------------------------------------
 * ip_path_mtu.c
 *
 * Copyright (c) 2020 Graphiant.
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

#include <vnet/ip/ip_path_mtu.h>
#include <vnet/ip/ip_frag.h>

typedef enum
{
  IP_PMTU_DROP,
  IP_PMTU_N_NEXT,
} ip_pmtu_next_t;

typedef struct ip_pmtu_trace_t_
{
  u16 pmtu;
  u16 packet_size;
} ip_pmtu_trace_t;

static u8 *
format_ip_pmtu_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ip_pmtu_trace_t *t = va_arg (*args, ip_pmtu_trace_t *);

  s = format (s, "path mtu:%d packet size:%d", t->pmtu, t->packet_size);

  return s;
}

static inline uword
ip_pmtu_dpo_inline (vlib_main_t *vm, vlib_node_runtime_t *node,
		    vlib_frame_t *frame, ip_address_family_t af)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  u32 frag_sent = 0, small_packets = 0;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  u32 *buffer = 0;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  const ip_pmtu_dpo_t *ipm0;
	  u32 pi0, *frag_from, frag_left;
	  vlib_buffer_t *p0;
	  ip_frag_error_t error0;
	  u16 next0;

	  /*
	   * Note: The packet is not enqueued now. It is instead put
	   * in a vector where other fragments will be put as well.
	   */
	  pi0 = from[0];
	  from += 1;
	  n_left_from -= 1;

	  p0 = vlib_get_buffer (vm, pi0);
	  ipm0 = ip_pmtu_dpo_get (vnet_buffer (p0)->ip.adj_index[VLIB_TX]);
	  vnet_buffer (p0)->ip.adj_index[VLIB_TX] = ipm0->ipm_dpo.dpoi_index;
	  next0 = ipm0->ipm_dpo.dpoi_next_node;

	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      ip_pmtu_trace_t *t;
	      t = vlib_add_trace (vm, node, p0, sizeof (*t));
	      t->pmtu = ipm0->ipm_pmtu;
	      t->packet_size = vlib_buffer_length_in_chain (vm, p0);
	    }

	  if (AF_IP6 == af)
	    error0 =
	      ip6_frag_do_fragment (vm, pi0, ipm0->ipm_pmtu, 0, &buffer);
	  else
	    error0 =
	      ip4_frag_do_fragment (vm, pi0, ipm0->ipm_pmtu, 0, &buffer);

	  if (AF_IP4 == af && error0 == IP_FRAG_ERROR_DONT_FRAGMENT_SET)
	    {
	      icmp4_error_set_vnet_buffer (
		p0, ICMP4_destination_unreachable,
		ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set,
		ipm0->ipm_pmtu);
	      next0 = IP_FRAG_NEXT_ICMP_ERROR;
	    }
	  else
	    {
	      next0 =
		(error0 == IP_FRAG_ERROR_NONE ? next0 : IP_FRAG_NEXT_DROP);
	    }

	  if (error0 == IP_FRAG_ERROR_NONE)
	    {
	      /* Free original buffer chain */
	      frag_sent += vec_len (buffer);
	      small_packets += (vec_len (buffer) == 1);
	      vlib_buffer_free_one (vm, pi0); /* Free original packet */
	    }
	  else
	    {
	      vlib_error_count (vm, node->node_index, error0, 1);
	      vec_add1 (buffer, pi0); /* Get rid of the original buffer */
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

		  vlib_get_buffer (vm, i)->error = node->errors[error0];
		  vlib_validate_buffer_enqueue_x1 (
		    vm, node, next_index, to_next, n_left_to_next, i, next0);
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

  return frame->n_vectors;
}

// clang-format off

VLIB_NODE_FN (ip4_ip_pmtu_dpo_node) (vlib_main_t *vm,
                                     vlib_node_runtime_t *node,
                                     vlib_frame_t *from_frame)
{
  return (ip_pmtu_dpo_inline (vm, node, from_frame, 0));
}

VLIB_NODE_FN (ip6_ip_pmtu_dpo_node) (vlib_main_t *vm,
                                     vlib_node_runtime_t *node,
                                     vlib_frame_t *from_frame)
{
  return (ip_pmtu_dpo_inline (vm, node, from_frame, 1));
}

VLIB_REGISTER_NODE (ip4_ip_pmtu_dpo_node) = {
  .name = "ip4-pmtu-dpo",
  .vector_size = sizeof (u32),
  .format_trace = format_ip_pmtu_trace,
  .n_errors = IP_FRAG_N_ERROR,
  .error_strings = ip4_frag_error_strings,
  .n_next_nodes = IP_PMTU_N_NEXT,
  .next_nodes =
  {
   [IP_PMTU_DROP] = "ip4-drop",
  }
};
VLIB_REGISTER_NODE (ip6_ip_pmtu_dpo_node) = {
  .name = "ip6-pmtu-dpo",
  .vector_size = sizeof (u32),
  .format_trace = format_ip_pmtu_trace,
  .n_errors = IP_FRAG_N_ERROR,
  .error_strings = ip4_frag_error_strings,
  .n_next_nodes = IP_PMTU_N_NEXT,
  .next_nodes =
  {
   [IP_PMTU_DROP] = "ip6-drop",
  }
};

// clang-format on

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
