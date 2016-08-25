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
#include <vnet/ethernet/arp_packet.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/fib/fib_walk.h>

static inline u32
adj_get_midchain_node (fib_link_t link)
{
    switch (link) {
    case FIB_LINK_IP4:
	return (ip4_midchain_node.index);
    case FIB_LINK_IP6:
	return (ip6_midchain_node.index);
    case FIB_LINK_MPLS:
	return (mpls_midchain_node.index);
    }
    ASSERT(0);
    return (0);
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
				 u32 post_rewrite_node,
				 u8 *rewrite)
{
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);
    adj->lookup_next_index = IP_LOOKUP_NEXT_MIDCHAIN;
    adj->sub_type.midchain.tx_function_node = post_rewrite_node;

    if (NULL != rewrite)
    {
	/*
	 * new rewrite provided.
	 * use a dummy rewrite header to get the interface to print into.
	 */
	ip_adjacency_t dummy;
        dpo_id_t tmp = DPO_NULL;

	vnet_rewrite_for_tunnel(vnet_get_main(),
				adj->rewrite_header.sw_if_index,
				adj_get_midchain_node(adj->ia_link),
				adj->sub_type.midchain.tx_function_node,
				&dummy.rewrite_header,
				rewrite,
				vec_len(rewrite));

	/*
	 * this is an update of an existing rewrite.
         * packets are in flight. we'll need to briefly stack on the drop DPO
         * whilst the rewrite is written, so any packets that see the partial update
         * are binned.
         */
        if (!dpo_id_is_valid(&adj->sub_type.midchain.next_dpo))
        {
            /*
             * not stacked yet. stack on the drop
             */
            dpo_stack(DPO_ADJACENCY_MIDCHAIN,
                      fib_proto_to_dpo(adj->ia_nh_proto),
                      &adj->sub_type.midchain.next_dpo,
                      drop_dpo_get(fib_proto_to_dpo(adj->ia_nh_proto)));
        }
            
        dpo_copy(&tmp, &adj->sub_type.midchain.next_dpo);
        dpo_stack(DPO_ADJACENCY_MIDCHAIN,
                  fib_proto_to_dpo(adj->ia_nh_proto),
                  &adj->sub_type.midchain.next_dpo,
                  drop_dpo_get(fib_proto_to_dpo(adj->ia_nh_proto)));

	CLIB_MEMORY_BARRIER();

	clib_memcpy(&adj->rewrite_header,
		    &dummy.rewrite_header,
		    VLIB_BUFFER_PRE_DATA_SIZE);

	CLIB_MEMORY_BARRIER();

        /*
         * The graph arc used/created here is from the post-rewirte node to the
         * child's registered node. This is because post adj processing the next
         * node is the interface's specific node, then the post-write-node (aka
         * the interface's tx-function) - from there we need to get to the stacked
         * child's node.
         */
        dpo_stack_from_node(adj->sub_type.midchain.tx_function_node,
                            &adj->sub_type.midchain.next_dpo,
                            &tmp);
        dpo_reset(&tmp);
    }
    else
    {
	ASSERT(0);
    }

    /*
     * time for walkies fido.
     */
    fib_node_back_walk_ctx_t bw_ctx = {
	.fnbw_reason = FIB_NODE_BW_REASON_ADJ_UPDATE,
    };

    fib_walk_sync(FIB_NODE_TYPE_ADJ, adj->heap_handle, &bw_ctx);
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

    ASSERT(IP_LOOKUP_NEXT_MIDCHAIN == adj->lookup_next_index);

    dpo_stack_from_node(adj->sub_type.midchain.tx_function_node,
                        &adj->sub_type.midchain.next_dpo,
                        next);
}

u8*
format_adj_midchain (u8* s, va_list *ap)
{
    index_t index = va_arg(ap, index_t);
    u32 indent = va_arg(ap, u32);
    vnet_main_t * vnm = vnet_get_main();
    ip_adjacency_t * adj = adj_get(index);

    s = format (s, "%U", format_fib_link, adj->ia_link);
    s = format (s, " via %U ",
		format_ip46_address, &adj->sub_type.nbr.next_hop);
    s = format (s, " %U",
                format_vnet_rewrite,
                vnm->vlib_main, &adj->rewrite_header,
                sizeof (adj->rewrite_data), indent);
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

const static char* const * const midchain_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = midchain_ip4_nodes,
    [DPO_PROTO_IP6]  = midchain_ip6_nodes,
    [DPO_PROTO_MPLS] = midchain_mpls_nodes,
};

void
adj_midchain_module_init (void)
{
    dpo_register(DPO_ADJACENCY_MIDCHAIN, &adj_midchain_dpo_vft, midchain_nodes);
}
