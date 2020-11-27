/*
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
 */

#include <vnet/vnet.h>
#include <vnet/adj/adj_l2.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>

/**
 * @brief Trace data for a L2 Midchain
 */
typedef struct adj_l2_trace_t_ {
    /** Adjacency index taken. */
    u32 adj_index;
} adj_l2_trace_t;

static u8 *
format_adj_l2_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    adj_l2_trace_t * t = va_arg (*args, adj_l2_trace_t *);

    s = format (s, "adj-idx %d : %U",
		t->adj_index,
		format_ip_adjacency, t->adj_index, FORMAT_IP_ADJACENCY_NONE);
    return s;
}

typedef enum adj_l2_rewrite_next_t_
{
    ADJ_L2_REWRITE_NEXT_DROP,
} adj_l2_rewrite_next_t;

always_inline uword
adj_l2_rewrite_inline (vlib_main_t * vm,
		       vlib_node_runtime_t * node,
		       vlib_frame_t * frame,
		       int is_midchain,
                       int do_counters)
{
    u32 * from = vlib_frame_vector_args (frame);
    u32 n_left_from, n_left_to_next, * to_next, next_index;
    u32 thread_index = vlib_get_thread_index();
    ethernet_main_t * em = &ethernet_main;

    n_left_from = frame->n_vectors;
    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
	vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

	while (n_left_from > 0 && n_left_to_next > 0)
	{
	    ip_adjacency_t * adj0;
	    vlib_buffer_t * p0;
	    char *h0;
	    u32 pi0, rw_len0, len0, adj_index0, next0 = 0;
	    u32 tx_sw_if_index0;

	    pi0 = to_next[0] = from[0];
	    from += 1;
	    n_left_from -= 1;
	    to_next += 1;
	    n_left_to_next -= 1;

	    p0 = vlib_get_buffer (vm, pi0);
	    h0 = vlib_buffer_get_current (p0);

	    adj_index0 = vnet_buffer (p0)->ip.adj_index;

	    adj0 = adj_get (adj_index0);

	    /* Guess we are writing on ip4 header. */
	    vnet_rewrite_one_header (adj0[0], h0,
                                     //sizeof (gre_header_t) +
                                     sizeof (ip4_header_t));

	    /* Update packet buffer attributes/set output interface. */
	    rw_len0 = adj0[0].rewrite_header.data_bytes;
	    vnet_buffer(p0)->ip.save_rewrite_length = rw_len0;
            vnet_buffer(p0)->sw_if_index[VLIB_TX] = adj0->rewrite_header.sw_if_index;
            len0 = vlib_buffer_length_in_chain (vm, p0);
            /* since we are coming out of the L2 world, where the vlib_buffer
             * union is used for other things, make sure it is clean for
             * MPLS from now on.
             */
            vnet_buffer(p0)->mpls.first = 0;

            if (do_counters)
                vlib_increment_combined_counter(&adjacency_counters,
                                                thread_index,
                                                adj_index0,
                                                0, len0);

	    /* Check MTU of outgoing interface. */
	    if (PREDICT_TRUE(len0 <= adj0[0].rewrite_header.max_l3_packet_bytes))
	    {
		/* Don't adjust the buffer for ttl issue; icmp-error node wants
		 * to see the IP header */
		p0->current_data -= rw_len0;
		p0->current_length += rw_len0;
		tx_sw_if_index0 = adj0[0].rewrite_header.sw_if_index;

		if (is_midchain)
		{
		    adj0->sub_type.midchain.fixup_func(
                        vm, adj0, p0,
                        adj0->sub_type.midchain.fixup_data);
		}

		vnet_buffer (p0)->sw_if_index[VLIB_TX] = tx_sw_if_index0;

		/*
		 * Follow the feature ARC. this will result eventually in
		 * the midchain-tx node
		 */
                if (PREDICT_FALSE (adj0->rewrite_header.flags &
                                   VNET_REWRITE_HAS_FEATURES))
                    vnet_feature_arc_start_w_cfg_index (
                        em->output_feature_arc_index,
                        tx_sw_if_index0,
                        &next0, p0,
                        adj0->ia_cfg_index);
                else
                    next0 = adj0[0].rewrite_header.next_index;
	    }
	    else
	    {
		/* can't fragment L2 */
		next0 = ADJ_L2_REWRITE_NEXT_DROP;
	    }

	    if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
		adj_l2_trace_t *tr = vlib_add_trace (vm, node,
						     p0, sizeof (*tr));
		tr->adj_index = vnet_buffer(p0)->ip.adj_index;
	    }

	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					     to_next, n_left_to_next,
					     pi0, next0);
	}

	vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

    return frame->n_vectors;
}

VLIB_NODE_FN (adj_l2_rewrite_node) (vlib_main_t * vm,
		vlib_node_runtime_t * node,
		vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
      return adj_l2_rewrite_inline (vm, node, frame, 0, 1);
  else
      return adj_l2_rewrite_inline (vm, node, frame, 0, 0);
}

VLIB_NODE_FN (adj_l2_midchain_node) (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * frame)
{
  if (adj_are_counters_enabled ())
      return adj_l2_rewrite_inline (vm, node, frame, 1, 1);
  else
      return adj_l2_rewrite_inline (vm, node, frame, 1, 0);
}

VLIB_REGISTER_NODE (adj_l2_rewrite_node) = {
    .name = "adj-l2-rewrite",
    .vector_size = sizeof (u32),

    .format_trace = format_adj_l2_trace,

    .n_next_nodes = 1,
    .next_nodes = {
	[ADJ_L2_REWRITE_NEXT_DROP] = "error-drop",
    },
};

VLIB_REGISTER_NODE (adj_l2_midchain_node) = {
    .name = "adj-l2-midchain",
    .vector_size = sizeof (u32),

    .format_trace = format_adj_l2_trace,

    .n_next_nodes = 1,
    .next_nodes = {
	[ADJ_L2_REWRITE_NEXT_DROP] = "error-drop",
    },
};
