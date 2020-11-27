/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#include <vnet/adj/adj_nsh.h>
#include <vnet/ip/ip.h>

#ifndef CLIB_MARCH_VARIANT
nsh_main_placeholder_t nsh_main_placeholder;
#endif /* CLIB_MARCH_VARIANT */

/**
 * @brief Trace data for a NSH Midchain
 */
typedef struct adj_nsh_trace_t_ {
    /** Adjacency index taken. */
    u32 adj_index;
} adj_nsh_trace_t;

static u8 *
format_adj_nsh_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    adj_nsh_trace_t * t = va_arg (*args, adj_nsh_trace_t *);

    s = format (s, "adj-idx %d : %U",
                t->adj_index,
                format_ip_adjacency, t->adj_index, FORMAT_IP_ADJACENCY_NONE);
    return s;
}

typedef enum adj_nsh_rewrite_next_t_
{
    ADJ_NSH_REWRITE_NEXT_DROP,
} adj_gpe_rewrite_next_t;

always_inline uword
adj_nsh_rewrite_inline (vlib_main_t * vm,
                       vlib_node_runtime_t * node,
                       vlib_frame_t * frame,
                       int is_midchain)
{
    u32 * from = vlib_frame_vector_args (frame);
    u32 n_left_from, n_left_to_next, * to_next, next_index;
    u32 thread_index = vlib_get_thread_index();

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
            u32 pi0, rw_len0, adj_index0, next0 = 0;
            u32 tx_sw_if_index0;

            pi0 = to_next[0] = from[0];
            from += 1;
            n_left_from -= 1;
            to_next += 1;
            n_left_to_next -= 1;

            p0 = vlib_get_buffer (vm, pi0);
            h0 = vlib_buffer_get_current (p0);

            adj_index0 = vnet_buffer (p0)->ip.adj_index;

            /* We should never rewrite a pkt using the MISS adjacency */
            ASSERT(adj_index0);

            adj0 = adj_get (adj_index0);

            /* Guess we are only writing on simple IP4 header. */
            vnet_rewrite_one_header(adj0[0], h0, sizeof(ip4_header_t));

            /* Update packet buffer attributes/set output interface. */
            rw_len0 = adj0[0].rewrite_header.data_bytes;
            vnet_buffer(p0)->ip.save_rewrite_length = rw_len0;

            vlib_increment_combined_counter(&adjacency_counters,
                                            thread_index,
                                            adj_index0,
                                            /* packet increment */ 0,
                                            /* byte increment */ rw_len0);

            /* Check MTU of outgoing interface. */
            if (PREDICT_TRUE((vlib_buffer_length_in_chain (vm, p0)  <=
                              adj0[0].rewrite_header.max_l3_packet_bytes)))
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
                vnet_feature_arc_start (nsh_main_placeholder.output_feature_arc_index,
                                        tx_sw_if_index0, &next0, p0);
            }
            else
            {
                /* can't fragment NSH */
                next0 = ADJ_NSH_REWRITE_NEXT_DROP;
            }

            if (PREDICT_FALSE(p0->flags & VLIB_BUFFER_IS_TRACED))
            {
                adj_nsh_trace_t *tr = vlib_add_trace (vm, node,
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

VLIB_NODE_FN (adj_nsh_rewrite_node) (vlib_main_t * vm,
                vlib_node_runtime_t * node,
                vlib_frame_t * frame)
{
    return adj_nsh_rewrite_inline (vm, node, frame, 0);
}

VLIB_NODE_FN (adj_nsh_midchain_node) (vlib_main_t * vm,
                 vlib_node_runtime_t * node,
                 vlib_frame_t * frame)
{
    return adj_nsh_rewrite_inline (vm, node, frame, 1);
}

VLIB_REGISTER_NODE (adj_nsh_rewrite_node) = {
    .name = "adj-nsh-rewrite",
    .vector_size = sizeof (u32),

    .format_trace = format_adj_nsh_trace,

    .n_next_nodes = 1,
    .next_nodes = {
        [ADJ_NSH_REWRITE_NEXT_DROP] = "error-drop",
    },
};

VLIB_REGISTER_NODE (adj_nsh_midchain_node) = {
    .name = "adj-nsh-midchain",
    .vector_size = sizeof (u32),

    .format_trace = format_adj_nsh_trace,

    .n_next_nodes = 1,
    .next_nodes = {
        [ADJ_NSH_REWRITE_NEXT_DROP] = "error-drop",
    },
};

/* Built-in ip4 tx feature path definition */
/* *INDENT-OFF* */
VNET_FEATURE_ARC_INIT (nsh_output, static) =
{
  .arc_name  = "nsh-output",
  .start_nodes = VNET_FEATURES ("adj-nsh-midchain"),
  .arc_index_ptr = &nsh_main_placeholder.output_feature_arc_index,
};

VNET_FEATURE_INIT (nsh_tx_drop, static) =
{
  .arc_name = "nsh-output",
  .node_name = "error-drop",
  .runs_before = 0,     /* not before any other features */
};
/* *INDENT-ON* */
