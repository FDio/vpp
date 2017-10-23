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

#include <vnet/adj/adj_nbr.h>
#include <vnet/adj/adj_internal.h>
#include <vnet/adj/adj_l2.h>
#include <vnet/adj/adj_nsh.h>
#include <vnet/adj/adj_midchain.h>
#include <vnet/ethernet/arp_packet.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/fib/fib_walk.h>

/**
 * The two midchain tx feature node indices
 */
static u32 adj_midchain_tx_feature_node[VNET_LINK_NUM];
static u32 adj_midchain_tx_no_count_feature_node[VNET_LINK_NUM];

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
    u32 * from, * to_next, n_left_from, n_left_to_next;
    u32 next_index;
    vnet_main_t *vnm = vnet_get_main ();
    vnet_interface_main_t *im = &vnm->interface_main;
    u32 thread_index = vm->thread_index;

    /* Vector of buffer / pkt indices we're supposed to process */
    from = vlib_frame_vector_args (frame);

    /* Number of buffers / pkts */
    n_left_from = frame->n_vectors;

    /* Speculatively send the first buffer to the last disposition we used */
    next_index = node->cached_next_index;

    while (n_left_from > 0)
    {
	/* set up to enqueue to our disposition with index = next_index */
	vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

	while (n_left_from >= 8 && n_left_to_next > 4)
	{
	    u32 bi0, adj_index0, next0;
	    const ip_adjacency_t * adj0;
	    const dpo_id_t *dpo0;
	    vlib_buffer_t * b0;
	    u32 bi1, adj_index1, next1;
	    const ip_adjacency_t * adj1;
	    const dpo_id_t *dpo1;
	    vlib_buffer_t * b1;
	    u32 bi2, adj_index2, next2;
	    const ip_adjacency_t * adj2;
	    const dpo_id_t *dpo2;
	    vlib_buffer_t * b2;
	    u32 bi3, adj_index3, next3;
	    const ip_adjacency_t * adj3;
	    const dpo_id_t *dpo3;
	    vlib_buffer_t * b3;

	    /* Prefetch next iteration. */
	    {
		vlib_buffer_t * p4, * p5;
		vlib_buffer_t * p6, * p7;

		p4 = vlib_get_buffer (vm, from[4]);
		p5 = vlib_get_buffer (vm, from[5]);
		p6 = vlib_get_buffer (vm, from[6]);
		p7 = vlib_get_buffer (vm, from[7]);

		vlib_prefetch_buffer_header (p4, LOAD);
		vlib_prefetch_buffer_header (p5, LOAD);
		vlib_prefetch_buffer_header (p6, LOAD);
		vlib_prefetch_buffer_header (p7, LOAD);
	    }

	    bi0 = from[0];
	    to_next[0] = bi0;
	    bi1 = from[1];
	    to_next[1] = bi1;
	    bi2 = from[2];
	    to_next[2] = bi2;
	    bi3 = from[3];
	    to_next[3] = bi3;

	    from += 4;
	    to_next += 4;
	    n_left_from -= 4;
	    n_left_to_next -= 4;

	    b0 = vlib_get_buffer(vm, bi0);
	    b1 = vlib_get_buffer(vm, bi1);
	    b2 = vlib_get_buffer(vm, bi2);
	    b3 = vlib_get_buffer(vm, bi3);

	    /* Follow the DPO on which the midchain is stacked */
	    adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
	    adj_index1 = vnet_buffer(b1)->ip.adj_index[VLIB_TX];
	    adj_index2 = vnet_buffer(b2)->ip.adj_index[VLIB_TX];
	    adj_index3 = vnet_buffer(b3)->ip.adj_index[VLIB_TX];

	    adj0 = adj_get(adj_index0);
	    adj1 = adj_get(adj_index1);
	    adj2 = adj_get(adj_index2);
	    adj3 = adj_get(adj_index3);

	    dpo0 = &adj0->sub_type.midchain.next_dpo;
	    dpo1 = &adj1->sub_type.midchain.next_dpo;
	    dpo2 = &adj2->sub_type.midchain.next_dpo;
	    dpo3 = &adj3->sub_type.midchain.next_dpo;

	    next0 = dpo0->dpoi_next_node;
	    next1 = dpo1->dpoi_next_node;
	    next2 = dpo2->dpoi_next_node;
	    next3 = dpo3->dpoi_next_node;

            vnet_buffer(b1)->ip.adj_index[VLIB_TX] = dpo1->dpoi_index;
            vnet_buffer(b0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;
            vnet_buffer(b2)->ip.adj_index[VLIB_TX] = dpo2->dpoi_index;
            vnet_buffer(b3)->ip.adj_index[VLIB_TX] = dpo3->dpoi_index;

	    if (interface_count)
	    {
		vlib_increment_combined_counter (im->combined_sw_if_counters
						 + VNET_INTERFACE_COUNTER_TX,
						 thread_index,
						 adj0->rewrite_header.sw_if_index,
						 1,
						 vlib_buffer_length_in_chain (vm, b0));
		vlib_increment_combined_counter (im->combined_sw_if_counters
						 + VNET_INTERFACE_COUNTER_TX,
						 thread_index,
						 adj1->rewrite_header.sw_if_index,
						 1,
						 vlib_buffer_length_in_chain (vm, b1));
		vlib_increment_combined_counter (im->combined_sw_if_counters
						 + VNET_INTERFACE_COUNTER_TX,
						 thread_index,
						 adj2->rewrite_header.sw_if_index,
						 1,
						 vlib_buffer_length_in_chain (vm, b2));
		vlib_increment_combined_counter (im->combined_sw_if_counters
						 + VNET_INTERFACE_COUNTER_TX,
						 thread_index,
						 adj3->rewrite_header.sw_if_index,
						 1,
						 vlib_buffer_length_in_chain (vm, b3));
	    }

	    if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
		adj_midchain_tx_trace_t *tr = vlib_add_trace (vm, node,
							      b0, sizeof (*tr));
		tr->ai = adj_index0;
	    }
	    if (PREDICT_FALSE(b1->flags & VLIB_BUFFER_IS_TRACED))
	    {
		adj_midchain_tx_trace_t *tr = vlib_add_trace (vm, node,
							      b1, sizeof (*tr));
		tr->ai = adj_index1;
	    }
	    if (PREDICT_FALSE(b2->flags & VLIB_BUFFER_IS_TRACED))
	    {
		adj_midchain_tx_trace_t *tr = vlib_add_trace (vm, node,
							      b2, sizeof (*tr));
		tr->ai = adj_index2;
	    }
	    if (PREDICT_FALSE(b3->flags & VLIB_BUFFER_IS_TRACED))
	    {
		adj_midchain_tx_trace_t *tr = vlib_add_trace (vm, node,
							      b3, sizeof (*tr));
		tr->ai = adj_index3;
	    }

	    vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
					     to_next, n_left_to_next,
					     bi0, bi1, bi2, bi3,
					     next0, next1, next2, next3);
	}
	while (n_left_from > 0 && n_left_to_next > 0)
	{
	    u32 bi0, adj_index0, next0;
	    const ip_adjacency_t * adj0;
	    const dpo_id_t *dpo0;
	    vlib_buffer_t * b0;

	    bi0 = from[0];
	    to_next[0] = bi0;
	    from += 1;
	    to_next += 1;
	    n_left_from -= 1;
	    n_left_to_next -= 1;

	    b0 = vlib_get_buffer(vm, bi0);

	    /* Follow the DPO on which the midchain is stacked */
	    adj_index0 = vnet_buffer(b0)->ip.adj_index[VLIB_TX];
	    adj0 = adj_get(adj_index0);
	    dpo0 = &adj0->sub_type.midchain.next_dpo;
	    next0 = dpo0->dpoi_next_node;
            vnet_buffer(b0)->ip.adj_index[VLIB_TX] = dpo0->dpoi_index;

	    if (interface_count)
	    {
		vlib_increment_combined_counter (im->combined_sw_if_counters
						 + VNET_INTERFACE_COUNTER_TX,
						 thread_index,
						 adj0->rewrite_header.sw_if_index,
						 1,
						 vlib_buffer_length_in_chain (vm, b0));
	    }

	    if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
		adj_midchain_tx_trace_t *tr = vlib_add_trace (vm, node,
							      b0, sizeof (*tr));
		tr->ai = adj_index0;
	    }

	    vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					     to_next, n_left_to_next,
					     bi0, next0);
	}

	vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

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

static uword
adj_midchain_tx (vlib_main_t * vm,
		 vlib_node_runtime_t * node,
		 vlib_frame_t * frame)
{
    return (adj_midchain_tx_inline(vm, node, frame, 1));
}

VLIB_REGISTER_NODE (adj_midchain_tx_node, static) = {
    .function = adj_midchain_tx,
    .name = "adj-midchain-tx",
    .vector_size = sizeof (u32),

    .format_trace = format_adj_midchain_tx_trace,

    .n_next_nodes = 1,
    .next_nodes = {
	[0] = "error-drop",
    },
};

static uword
adj_midchain_tx_no_count (vlib_main_t * vm,
			  vlib_node_runtime_t * node,
			  vlib_frame_t * frame)
{
    return (adj_midchain_tx_inline(vm, node, frame, 0));
}

VLIB_REGISTER_NODE (adj_midchain_tx_no_count_node, static) = {
    .function = adj_midchain_tx_no_count,
    .name = "adj-midchain-tx-no-count",
    .vector_size = sizeof (u32),

    .format_trace = format_adj_midchain_tx_trace,

    .n_next_nodes = 1,
    .next_nodes = {
	[0] = "error-drop",
    },
};

VNET_FEATURE_INIT (adj_midchain_tx_ip4, static) = {
    .arc_name = "ip4-output",
    .node_name = "adj-midchain-tx",
    .runs_before = VNET_FEATURES ("interface-output"),
    .feature_index_ptr = &adj_midchain_tx_feature_node[VNET_LINK_IP4],
};
VNET_FEATURE_INIT (adj_midchain_tx_no_count_ip4, static) = {
    .arc_name = "ip4-output",
    .node_name = "adj-midchain-tx-no-count",
    .runs_before = VNET_FEATURES ("interface-output"),
    .feature_index_ptr = &adj_midchain_tx_no_count_feature_node[VNET_LINK_IP4],
};
VNET_FEATURE_INIT (adj_midchain_tx_ip6, static) = {
    .arc_name = "ip6-output",
    .node_name = "adj-midchain-tx",
    .runs_before = VNET_FEATURES ("interface-output"),
    .feature_index_ptr = &adj_midchain_tx_feature_node[VNET_LINK_IP6],
};
VNET_FEATURE_INIT (adj_midchain_tx_no_count_ip6, static) = {
    .arc_name = "ip6-output",
    .node_name = "adj-midchain-tx-no-count",
    .runs_before = VNET_FEATURES ("interface-output"),
    .feature_index_ptr = &adj_midchain_tx_no_count_feature_node[VNET_LINK_IP6],
};
VNET_FEATURE_INIT (adj_midchain_tx_mpls, static) = {
    .arc_name = "mpls-output",
    .node_name = "adj-midchain-tx",
    .runs_before = VNET_FEATURES ("interface-output"),
    .feature_index_ptr = &adj_midchain_tx_feature_node[VNET_LINK_MPLS],
};
VNET_FEATURE_INIT (adj_midchain_tx_no_count_mpls, static) = {
    .arc_name = "mpls-output",
    .node_name = "adj-midchain-tx-no-count",
    .runs_before = VNET_FEATURES ("interface-output"),
    .feature_index_ptr = &adj_midchain_tx_no_count_feature_node[VNET_LINK_MPLS],
};
VNET_FEATURE_INIT (adj_midchain_tx_ethernet, static) = {
    .arc_name = "ethernet-output",
    .node_name = "adj-midchain-tx",
    .runs_before = VNET_FEATURES ("error-drop"),
    .feature_index_ptr = &adj_midchain_tx_feature_node[VNET_LINK_ETHERNET],
};
VNET_FEATURE_INIT (adj_midchain_tx_no_count_ethernet, static) = {
    .arc_name = "ethernet-output",
    .node_name = "adj-midchain-tx-no-count",
    .runs_before = VNET_FEATURES ("error-drop"),
    .feature_index_ptr = &adj_midchain_tx_no_count_feature_node[VNET_LINK_ETHERNET],
};
VNET_FEATURE_INIT (adj_midchain_tx_nsh, static) = {
    .arc_name = "nsh-output",
    .node_name = "adj-midchain-tx",
    .runs_before = VNET_FEATURES ("error-drop"),
    .feature_index_ptr = &adj_midchain_tx_feature_node[VNET_LINK_NSH],
};
VNET_FEATURE_INIT (adj_midchain_tx_no_count_nsh, static) = {
    .arc_name = "nsh-output",
    .node_name = "adj-midchain-tx-no-count",
    .runs_before = VNET_FEATURES ("error-drop"),
    .feature_index_ptr = &adj_midchain_tx_no_count_feature_node[VNET_LINK_NSH],
};

static inline u32
adj_get_midchain_node (vnet_link_t link)
{
    switch (link) {
    case VNET_LINK_IP4:
	return (ip4_midchain_node.index);
    case VNET_LINK_IP6:
	return (ip6_midchain_node.index);
    case VNET_LINK_MPLS:
	return (mpls_midchain_node.index);
    case VNET_LINK_ETHERNET:
	return (adj_l2_midchain_node.index);
    case VNET_LINK_NSH:
        return (adj_nsh_midchain_node.index);
    case VNET_LINK_ARP:
	break;
    }
    ASSERT(0);
    return (0);
}

static u8
adj_midchain_get_feature_arc_index_for_link_type (const ip_adjacency_t *adj)
{
    u8 arc = (u8) ~0;
    switch (adj->ia_link)
    {
    case VNET_LINK_IP4:
	{
	    arc = ip4_main.lookup_main.output_feature_arc_index;
	    break;
	}
    case VNET_LINK_IP6:
	{
	    arc = ip6_main.lookup_main.output_feature_arc_index;
	    break;
	}
    case VNET_LINK_MPLS:
	{
	    arc = mpls_main.output_feature_arc_index;
	    break;
	}
    case VNET_LINK_ETHERNET:
	{
	    arc = ethernet_main.output_feature_arc_index;
	    break;
	}
    case VNET_LINK_NSH:
        {
          arc = nsh_main_dummy.output_feature_arc_index;
          break;
        }
    case VNET_LINK_ARP:
	ASSERT(0);
	break;
    }

    ASSERT (arc != (u8) ~0);

    return (arc);
}

static u32
adj_nbr_midchain_get_tx_node (ip_adjacency_t *adj)
{
    return ((adj->ia_flags & ADJ_FLAG_MIDCHAIN_NO_COUNT) ?
            adj_midchain_tx_no_count_node.index :
            adj_midchain_tx_node.index);
}

static u32
adj_nbr_midchain_get_feature_node (ip_adjacency_t *adj)
{
    if (adj->ia_flags & ADJ_FLAG_MIDCHAIN_NO_COUNT)
    {
        return (adj_midchain_tx_no_count_feature_node[adj->ia_link]);
    }

    return (adj_midchain_tx_feature_node[adj->ia_link]);
}

/**
 * adj_midchain_setup
 *
 * Setup the adj as a mid-chain
 */
void
adj_midchain_setup (adj_index_t adj_index,
                    adj_midchain_fixup_t fixup,
                    adj_flags_t flags)
{
    u32 feature_index, tx_node;
    ip_adjacency_t *adj;
    u8 arc_index;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);

    adj->sub_type.midchain.fixup_func = fixup;
    adj->ia_flags |= flags;

    arc_index = adj_midchain_get_feature_arc_index_for_link_type (adj);
    feature_index = adj_nbr_midchain_get_feature_node(adj);
    tx_node = adj_nbr_midchain_get_tx_node(adj);

    vnet_feature_enable_disable_with_index (arc_index, feature_index,
					    adj->rewrite_header.sw_if_index,
					    1 /* enable */, 0, 0);

    /*
     * stack the midchain on the drop so it's ready to forward in the adj-midchain-tx.
     * The graph arc used/created here is from the midchain-tx node to the
     * child's registered node. This is because post adj processing the next
     * node are any output features, then the midchain-tx.  from there we
     * need to get to the stacked child's node.
     */
    dpo_stack_from_node(tx_node,
                        &adj->sub_type.midchain.next_dpo,
                        drop_dpo_get(vnet_link_to_dpo_proto(adj->ia_link)));
}

/**
 * adj_nbr_midchain_update_rewrite
 *
 * Update the adjacency's rewrite string. A NULL string implies the
 * rewrite is reset (i.e. when ARP/ND etnry is gone).
 * NB: the adj being updated may be handling traffic in the DP.
 */
void
adj_nbr_midchain_update_rewrite (adj_index_t adj_index,
				 adj_midchain_fixup_t fixup,
				 adj_flags_t flags,
				 u8 *rewrite)
{
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);

    /*
     * one time only update. since we don't support chainging the tunnel
     * src,dst, this is all we need.
     */
    ASSERT(adj->lookup_next_index == IP_LOOKUP_NEXT_ARP);
    /*
     * tunnels can always provide a rewrite.
     */
    ASSERT(NULL != rewrite);

    adj_midchain_setup(adj_index, fixup, flags);

    /*
     * update the rewirte with the workers paused.
     */
    adj_nbr_update_rewrite_internal(adj,
				    IP_LOOKUP_NEXT_MIDCHAIN,
				    adj_get_midchain_node(adj->ia_link),
				    adj_nbr_midchain_get_tx_node(adj),
				    rewrite);
}

/**
 * adj_nbr_midchain_unstack
 *
 * Unstack the adj. stack it on drop
 */
void
adj_nbr_midchain_unstack (adj_index_t adj_index)
{
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);

    /*
     * stack on the drop
     */
    dpo_stack(DPO_ADJACENCY_MIDCHAIN,
              vnet_link_to_dpo_proto(adj->ia_link),
              &adj->sub_type.midchain.next_dpo,
              drop_dpo_get(vnet_link_to_dpo_proto(adj->ia_link)));
    CLIB_MEMORY_BARRIER();
}

/**
 * adj_nbr_midchain_stack
 */
void
adj_nbr_midchain_stack (adj_index_t adj_index,
			const dpo_id_t *next)
{
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);

    ASSERT((IP_LOOKUP_NEXT_MIDCHAIN == adj->lookup_next_index) ||
           (IP_LOOKUP_NEXT_MCAST_MIDCHAIN == adj->lookup_next_index));

    dpo_stack_from_node(adj_nbr_midchain_get_tx_node(adj),
			&adj->sub_type.midchain.next_dpo,
			next);
}

u8*
format_adj_midchain (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    u32 indent = va_arg(*ap, u32);
    ip_adjacency_t * adj = adj_get(index);

    s = format (s, "%U", format_vnet_link, adj->ia_link);
    s = format (s, " via %U ",
		format_ip46_address, &adj->sub_type.nbr.next_hop);
    s = format (s, " %U",
		format_vnet_rewrite,
		&adj->rewrite_header, sizeof (adj->rewrite_data), indent);
    s = format (s, "\n%Ustacked-on:\n%U%U",
                format_white_space, indent,
                format_white_space, indent+2,
                format_dpo_id, &adj->sub_type.midchain.next_dpo, indent+2);

    return (s);
}

static void
adj_dpo_lock (dpo_id_t *dpo)
{
    adj_lock(dpo->dpoi_index);
}
static void
adj_dpo_unlock (dpo_id_t *dpo)
{
    adj_unlock(dpo->dpoi_index);
}

const static dpo_vft_t adj_midchain_dpo_vft = {
    .dv_lock = adj_dpo_lock,
    .dv_unlock = adj_dpo_unlock,
    .dv_format = format_adj_midchain,
    .dv_get_urpf = adj_dpo_get_urpf,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a midchain
 *        object.
 *
 * this means that these graph nodes are ones from which a midchain is the
 * parent object in the DPO-graph.
 */
const static char* const midchain_ip4_nodes[] =
{
    "ip4-midchain",
    NULL,
};
const static char* const midchain_ip6_nodes[] =
{
    "ip6-midchain",
    NULL,
};
const static char* const midchain_mpls_nodes[] =
{
    "mpls-midchain",
    NULL,
};
const static char* const midchain_ethernet_nodes[] =
{
    "adj-l2-midchain",
    NULL,
};
const static char* const midchain_nsh_nodes[] =
{
    "adj-nsh-midchain",
    NULL,
};

const static char* const * const midchain_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = midchain_ip4_nodes,
    [DPO_PROTO_IP6]  = midchain_ip6_nodes,
    [DPO_PROTO_MPLS] = midchain_mpls_nodes,
    [DPO_PROTO_ETHERNET] = midchain_ethernet_nodes,
    [DPO_PROTO_NSH] = midchain_nsh_nodes,
};

void
adj_midchain_module_init (void)
{
    dpo_register(DPO_ADJACENCY_MIDCHAIN, &adj_midchain_dpo_vft, midchain_nodes);
}
