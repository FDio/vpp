/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 */
/**
 * @file
 * @brief NAT66 outside to inside network translation
 */

#include <nat/nat66/nat66.h>
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/fib/fib_table.h>

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
} nat66_out2in_trace_t;

static u8 *
format_nat66_out2in_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nat66_out2in_trace_t *t = va_arg (*args, nat66_out2in_trace_t *);

  s =
    format (s, "NAT66-out2in: sw_if_index %d, next index %d", t->sw_if_index,
	    t->next_index);

  return s;
}

#define foreach_nat66_out2in_error                       \
_(NO_TRANSLATION, "no translation")                      \
_(UNKNOWN, "unknown")

typedef enum
{
#define _(sym,str) NAT66_OUT2IN_ERROR_##sym,
  foreach_nat66_out2in_error
#undef _
    NAT66_OUT2IN_N_ERROR,
} nat66_out2in_error_t;

static char *nat66_out2in_error_strings[] = {
#define _(sym,string) string,
  foreach_nat66_out2in_error
#undef _
};

typedef enum
{
  NAT66_OUT2IN_NEXT_IP6_LOOKUP,
  NAT66_OUT2IN_NEXT_DROP,
  NAT66_OUT2IN_N_NEXT,
} nat66_out2in_next_t;

VLIB_NODE_FN (nat66_out2in_node) (vlib_main_t * vm,
				  vlib_node_runtime_t * node,
				  vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  nat66_out2in_next_t next_index;
  clib_thread_index_t thread_index = vm->thread_index;
  nat66_main_t *nm = &nat66_main;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = NAT66_OUT2IN_NEXT_IP6_LOOKUP;
	  ip6_header_t *ip60;
	  u16 l4_offset0, frag_offset0;
	  u8 l4_protocol0;
	  nat66_static_mapping_t *sm0;
	  u32 sw_if_index0, fib_index0;
	  udp_header_t *udp0;
	  tcp_header_t *tcp0;
	  icmp46_header_t *icmp0;
	  u16 *checksum0 = 0;
	  ip_csum_t csum0;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ip60 = vlib_buffer_get_current (b0);

	  if (PREDICT_FALSE
	      (ip6_parse
	       (vm, b0, ip60, b0->current_length, &l4_protocol0, &l4_offset0,
		&frag_offset0)))
	    {
	      next0 = NAT66_OUT2IN_NEXT_DROP;
	      b0->error = node->errors[NAT66_OUT2IN_ERROR_UNKNOWN];
	      goto trace0;
	    }

	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  fib_index0 =
	    fib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6,
						 sw_if_index0);

	  sm0 = nat66_static_mapping_get (&ip60->dst_address, fib_index0, 0);
	  if (PREDICT_FALSE (!sm0))
	    {
	      goto trace0;
	    }

	  if (l4_protocol0 == IP_PROTOCOL_UDP)
	    {
	      udp0 = (udp_header_t *) u8_ptr_add (ip60, l4_offset0);
	      checksum0 = &udp0->checksum;
	    }
	  else if (l4_protocol0 == IP_PROTOCOL_TCP)
	    {
	      tcp0 = (tcp_header_t *) u8_ptr_add (ip60, l4_offset0);
	      checksum0 = &tcp0->checksum;
	    }
	  else if (l4_protocol0 == IP_PROTOCOL_ICMP6)
	    {
	      icmp0 = (icmp46_header_t *) u8_ptr_add (ip60, l4_offset0);
	      checksum0 = &icmp0->checksum;
	    }
	  else
	    goto skip_csum0;

	  csum0 = ip_csum_sub_even (*checksum0, ip60->dst_address.as_u64[0]);
	  csum0 = ip_csum_sub_even (csum0, ip60->dst_address.as_u64[1]);
	  csum0 = ip_csum_add_even (csum0, sm0->l_addr.as_u64[0]);
	  csum0 = ip_csum_add_even (csum0, sm0->l_addr.as_u64[1]);
	  *checksum0 = ip_csum_fold (csum0);

	skip_csum0:
	  ip60->dst_address.as_u64[0] = sm0->l_addr.as_u64[0];
	  ip60->dst_address.as_u64[1] = sm0->l_addr.as_u64[1];
	  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sm0->fib_index;

	  vlib_increment_combined_counter (&nm->session_counters,
					   thread_index, sm0 - nm->sm, 1,
					   vlib_buffer_length_in_chain (vm,
									b0));

	trace0:
	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      nat66_out2in_trace_t *t =
		vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	      t->next_index = next0;
	    }

	  if (next0 != NAT66_OUT2IN_NEXT_DROP)
	    {
	      vlib_increment_simple_counter (&nm->out2in_packets,
					     thread_index, sw_if_index0, 1);
	    }

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (nat66_out2in_node) = {
  .name = "nat66-out2in",
  .vector_size = sizeof (u32),
  .format_trace = format_nat66_out2in_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (nat66_out2in_error_strings),
  .error_strings = nat66_out2in_error_strings,
  .n_next_nodes = NAT66_OUT2IN_N_NEXT,
  /* edit / add dispositions here */
  .next_nodes = {
    [NAT66_OUT2IN_NEXT_DROP] = "error-drop",
    [NAT66_OUT2IN_NEXT_IP6_LOOKUP] = "ip6-lookup",
  },
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
