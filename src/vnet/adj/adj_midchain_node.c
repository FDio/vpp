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

#include <vnet/adj/adj_internal.h>
#include <vnet/adj/adj_midchain.h>

/**
 * @brief Trace data for packets traversing the midchain tx node
 */
typedef struct adj_midchain_tx_trace_t_
{
    /**
     * @brief the midchain adj we are traversing
     */
    adj_index_t ai;
} adj_midchain_tx_trace_t;

always_inline uword
adj_midchain_tx_inline (vlib_main_t * vm,
			vlib_node_runtime_t * node,
			vlib_frame_t * frame,
			int interface_count)
{
    vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
    u16 nexts[VLIB_FRAME_SIZE], *next;
    u32 * from, n_left, thread_index;
    vnet_main_t *vnm = vnet_get_main ();
    vnet_interface_main_t *im = &vnm->interface_main;

    thread_index = vm->thread_index;
    n_left = frame->n_vectors;
    from = vlib_frame_vector_args (frame);

    vlib_get_buffers (vm, from, bufs, n_left);

    next = nexts;
    b = bufs;

    while (n_left > 8)
    {
        u32 adj_index0, adj_index1, adj_index2, adj_index3;
        const ip_adjacency_t *adj0, *adj1, *adj2, *adj3;
        const dpo_id_t *dpo0, *dpo1, *dpo2, *dpo3;

        /* Prefetch next iteration. */
        {
            vlib_prefetch_buffer_header (b[4], LOAD);
            vlib_prefetch_buffer_header (b[5], LOAD);
            vlib_prefetch_buffer_header (b[6], LOAD);
            vlib_prefetch_buffer_header (b[7], LOAD);
        }

        /* Follow the DPO on which the midchain is stacked */
        adj_index0 = vnet_buffer(b[0])->ip.adj_index[VLIB_TX];
        adj_index1 = vnet_buffer(b[1])->ip.adj_index[VLIB_TX];
        adj_index2 = vnet_buffer(b[2])->ip.adj_index[VLIB_TX];
        adj_index3 = vnet_buffer(b[3])->ip.adj_index[VLIB_TX];

        adj0 = adj_get(adj_index0);
        adj1 = adj_get(adj_index1);
        adj2 = adj_get(adj_index2);
        adj3 = adj_get(adj_index3);

        dpo0 = &adj0->sub_type.midchain.next_dpo;
        dpo1 = &adj1->sub_type.midchain.next_dpo;
        dpo2 = &adj2->sub_type.midchain.next_dpo;
        dpo3 = &adj3->sub_type.midchain.next_dpo;

        next[0] = dpo0->dpoi_next_node;
        next[1] = dpo1->dpoi_next_node;
        next[2] = dpo2->dpoi_next_node;
        next[3] = dpo3->dpoi_next_node;

        vnet_buffer(b[0])->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;
        vnet_buffer(b[1])->ip.adj_index[VLIB_TX] = dpo1->dpoi_index;
        vnet_buffer(b[2])->ip.adj_index[VLIB_TX] = dpo2->dpoi_index;
        vnet_buffer(b[3])->ip.adj_index[VLIB_TX] = dpo3->dpoi_index;

        if (interface_count)
        {
            vlib_increment_combined_counter (im->combined_sw_if_counters
                                             + VNET_INTERFACE_COUNTER_TX,
                                             thread_index,
                                             adj0->rewrite_header.sw_if_index,
                                             1,
                                             vlib_buffer_length_in_chain (vm, b[0]));
            vlib_increment_combined_counter (im->combined_sw_if_counters
                                             + VNET_INTERFACE_COUNTER_TX,
                                             thread_index,
                                             adj1->rewrite_header.sw_if_index,
                                             1,
                                             vlib_buffer_length_in_chain (vm, b[1]));
            vlib_increment_combined_counter (im->combined_sw_if_counters
                                             + VNET_INTERFACE_COUNTER_TX,
                                             thread_index,
                                             adj2->rewrite_header.sw_if_index,
                                             1,
                                             vlib_buffer_length_in_chain (vm, b[2]));
            vlib_increment_combined_counter (im->combined_sw_if_counters
                                             + VNET_INTERFACE_COUNTER_TX,
                                             thread_index,
                                             adj3->rewrite_header.sw_if_index,
                                             1,
                                             vlib_buffer_length_in_chain (vm, b[3]));
        }

        if (PREDICT_FALSE(node->flags & VLIB_NODE_FLAG_TRACE))
        {
            if (PREDICT_FALSE(b[0]->flags & VLIB_BUFFER_IS_TRACED))
            {
                adj_midchain_tx_trace_t *tr = vlib_add_trace (vm, node,
                                                              b[0], sizeof (*tr));
                tr->ai = adj_index0;
            }
            if (PREDICT_FALSE(b[1]->flags & VLIB_BUFFER_IS_TRACED))
            {
                adj_midchain_tx_trace_t *tr = vlib_add_trace (vm, node,
                                                              b[1], sizeof (*tr));
                tr->ai = adj_index1;
            }
            if (PREDICT_FALSE(b[2]->flags & VLIB_BUFFER_IS_TRACED))
            {
                adj_midchain_tx_trace_t *tr = vlib_add_trace (vm, node,
                                                              b[2], sizeof (*tr));
                tr->ai = adj_index2;
            }
            if (PREDICT_FALSE(b[3]->flags & VLIB_BUFFER_IS_TRACED))
            {
                adj_midchain_tx_trace_t *tr = vlib_add_trace (vm, node,
                                                              b[3], sizeof (*tr));
                tr->ai = adj_index3;
            }
        }
        n_left -= 4;
        b += 4;
        next += 4;
    }

    while (n_left)
    {
        const ip_adjacency_t * adj0;
        const dpo_id_t *dpo0;
        u32 adj_index0;

        /* Follow the DPO on which the midchain is stacked */
        adj_index0 = vnet_buffer(b[0])->ip.adj_index[VLIB_TX];
        adj0 = adj_get(adj_index0);
        dpo0 = &adj0->sub_type.midchain.next_dpo;
        next[0] = dpo0->dpoi_next_node;
        vnet_buffer(b[0])->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

        if (interface_count)
        {
            vlib_increment_combined_counter (im->combined_sw_if_counters
                                             + VNET_INTERFACE_COUNTER_TX,
                                             thread_index,
                                             adj0->rewrite_header.sw_if_index,
                                             1,
                                             vlib_buffer_length_in_chain (vm, b[0]));
        }

        if (PREDICT_FALSE(b[0]->flags & VLIB_BUFFER_IS_TRACED))
        {
            adj_midchain_tx_trace_t *tr = vlib_add_trace (vm, node,
                                                          b[0], sizeof (*tr));
            tr->ai = adj_index0;
        }

        n_left -= 1;
        b += 1;
        next += 1;
    }

    vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

    return frame->n_vectors;
}

static u8 *
format_adj_midchain_tx_trace (u8 * s, va_list * args)
{
    CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
    CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
    adj_midchain_tx_trace_t *tr = va_arg (*args, adj_midchain_tx_trace_t*);

    s = format(s, "adj-midchain:[%d]:%U", tr->ai,
	       format_ip_adjacency, tr->ai,
	       FORMAT_IP_ADJACENCY_NONE);

    return (s);
}

VLIB_NODE_FN (adj_midchain_tx) (vlib_main_t * vm,
                                vlib_node_runtime_t * node,
                                vlib_frame_t * frame)
{
    return (adj_midchain_tx_inline(vm, node, frame, 1));
}
VLIB_NODE_FN (tunnel_output) (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
    return (adj_midchain_tx_inline(vm, node, frame, 1));
}

VLIB_REGISTER_NODE (adj_midchain_tx) = {
    .name = "adj-midchain-tx",
    .vector_size = sizeof (u32),

    .format_trace = format_adj_midchain_tx_trace,

    .n_next_nodes = 1,
    .next_nodes = {
	[0] = "error-drop",
    },
};
VLIB_REGISTER_NODE (tunnel_output) = {
    .name = "tunnel-output",
    .vector_size = sizeof (u32),
    .format_trace = format_adj_midchain_tx_trace,
    .sibling_of = "adj-midchain-tx",
};

VLIB_NODE_FN (tunnel_output_no_count) (vlib_main_t * vm,
                                       vlib_node_runtime_t * node,
                                       vlib_frame_t * frame)
{
    return (adj_midchain_tx_inline(vm, node, frame, 0));
}

VLIB_REGISTER_NODE (tunnel_output_no_count) = {
    .name = "tunnel-output-no-count",
    .vector_size = sizeof (u32),
    .format_trace = format_adj_midchain_tx_trace,
    .sibling_of = "adj-midchain-tx",
};
