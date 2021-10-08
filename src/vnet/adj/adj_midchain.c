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
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/fib_walk.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>

u8
adj_is_midchain (adj_index_t ai)
{
    ip_adjacency_t *adj;

    adj = adj_get(ai);

    switch (adj->lookup_next_index)
    {
    case IP_LOOKUP_NEXT_MIDCHAIN:
    case IP_LOOKUP_NEXT_MCAST_MIDCHAIN:
        return (1);
    case IP_LOOKUP_NEXT_ARP:
    case IP_LOOKUP_NEXT_GLEAN:
    case IP_LOOKUP_NEXT_BCAST:
    case IP_LOOKUP_NEXT_MCAST:
    case IP_LOOKUP_NEXT_DROP:
    case IP_LOOKUP_NEXT_PUNT:
    case IP_LOOKUP_NEXT_LOCAL:
    case IP_LOOKUP_NEXT_REWRITE:
    case IP_LOOKUP_NEXT_ICMP_ERROR:
    case IP_LOOKUP_N_NEXT:
        return (0);
    }

    return (0);
}

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
adj_midchain_get_feature_arc_index (const ip_adjacency_t *adj)
{
    switch (adj->ia_link)
    {
    case VNET_LINK_IP4:
        return ip4_main.lookup_main.output_feature_arc_index;
    case VNET_LINK_IP6:
        return ip6_main.lookup_main.output_feature_arc_index;
    case VNET_LINK_MPLS:
        return mpls_main.output_feature_arc_index;
    case VNET_LINK_ETHERNET:
        return ethernet_main.output_feature_arc_index;
    case VNET_LINK_NSH:
    case VNET_LINK_ARP:
	break;
    }
    ASSERT (0);
    return (0);
}

static u32
adj_nbr_midchain_get_tx_node (ip_adjacency_t *adj)
{
    return (adj_midchain_tx.index);
}

static u32
adj_nbr_midchain_get_next_node (ip_adjacency_t *adj)
{
    return (vnet_feature_get_end_node(adj_midchain_get_feature_arc_index(adj),
                                      adj->rewrite_header.sw_if_index));
}

/**
 * adj_midchain_setup
 *
 * Setup the adj as a mid-chain
 */
void
adj_midchain_teardown (ip_adjacency_t *adj)
{
    dpo_reset(&adj->sub_type.midchain.next_dpo);
}

/**
 * adj_midchain_setup
 *
 * Setup the adj as a mid-chain
 */
void
adj_midchain_setup (adj_index_t adj_index,
                    adj_midchain_fixup_t fixup,
                    const void *data,
                    adj_flags_t flags)
{
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);

    adj->sub_type.midchain.fixup_func = fixup;
    adj->sub_type.midchain.fixup_data = data;
    adj->sub_type.midchain.fei = FIB_NODE_INDEX_INVALID;
    adj->ia_flags |= flags;

    if (flags & ADJ_FLAG_MIDCHAIN_FIXUP_IP4O4_HDR)
    {
        adj->rewrite_header.flags |= VNET_REWRITE_FIXUP_IP4_O_4;
    }
    else
    {
        adj->rewrite_header.flags &= ~VNET_REWRITE_FIXUP_IP4_O_4;
    }
    if (!(flags & ADJ_FLAG_MIDCHAIN_FIXUP_FLOW_HASH))
    {
        adj->rewrite_header.flags &= ~VNET_REWRITE_FIXUP_FLOW_HASH;
    }

    /*
     * stack the midchain on the drop so it's ready to forward in the adj-midchain-tx.
     * The graph arc used/created here is from the midchain-tx node to the
     * child's registered node. This is because post adj processing the next
     * node are any output features, then the midchain-tx.  from there we
     * need to get to the stacked child's node.
     */
    dpo_stack_from_node(adj_nbr_midchain_get_tx_node(adj),
                        &adj->sub_type.midchain.next_dpo,
                        drop_dpo_get(vnet_link_to_dpo_proto(adj->ia_link)));
}

/**
 * adj_nbr_midchain_update_rewrite
 *
 * Update the adjacency's rewrite string. A NULL string implies the
 * rewrite is reset (i.e. when ARP/ND entry is gone).
 * NB: the adj being updated may be handling traffic in the DP.
 */
void
adj_nbr_midchain_update_rewrite (adj_index_t adj_index,
				 adj_midchain_fixup_t fixup,
                                 const void *fixup_data,
				 adj_flags_t flags,
				 u8 *rewrite)
{
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);

    /*
     * one time only update. since we don't support changing the tunnel
     * src,dst, this is all we need.
     */
    if (adj->lookup_next_index != IP_LOOKUP_NEXT_MIDCHAIN &&
        adj->lookup_next_index != IP_LOOKUP_NEXT_MCAST_MIDCHAIN)
    {
        adj_midchain_setup(adj_index, fixup, fixup_data, flags);
    }

    /*
     * update the rewrite with the workers paused.
     */
    adj_nbr_update_rewrite_internal(adj,
				    IP_LOOKUP_NEXT_MIDCHAIN,
				    adj_get_midchain_node(adj->ia_link),
				    adj_nbr_midchain_get_next_node(adj),
				    rewrite);
}

void
adj_nbr_midchain_update_next_node (adj_index_t adj_index,
                                   u32 next_node)
{
    ip_adjacency_t *adj;
    vlib_main_t * vm;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);
    vm = vlib_get_main();

    vlib_worker_thread_barrier_sync(vm);

    adj->rewrite_header.next_index = vlib_node_add_next(vlib_get_main(),
                                                        adj->ia_node_index,
                                                        next_node);

    vlib_worker_thread_barrier_release(vm);
}

void
adj_nbr_midchain_reset_next_node (adj_index_t adj_index)
{
    ip_adjacency_t *adj;
    vlib_main_t * vm;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);
    vm = vlib_get_main();

    vlib_worker_thread_barrier_sync(vm);

    adj->rewrite_header.next_index =
        vlib_node_add_next(vlib_get_main(),
                           adj->ia_node_index,
                           adj_nbr_midchain_get_next_node(adj));

    vlib_worker_thread_barrier_release(vm);
}

/**
 * adj_nbr_midchain_unstack
 *
 * Unstack the adj. stack it on drop
 */
void
adj_nbr_midchain_unstack (adj_index_t adj_index)
{
    fib_node_index_t *entry_indicies, tmp;
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != adj_index);
    adj = adj_get (adj_index);

    /*
     * check to see if this unstacking breaks a recursion loop
     */
    entry_indicies = NULL;
    tmp = adj->sub_type.midchain.fei;
    adj->sub_type.midchain.fei = FIB_NODE_INDEX_INVALID;

    if (FIB_NODE_INDEX_INVALID != tmp)
    {
        fib_entry_recursive_loop_detect(tmp, &entry_indicies);
        vec_free(entry_indicies);
    }

    /*
     * stack on the drop
     */
    dpo_stack(DPO_ADJACENCY_MIDCHAIN,
              vnet_link_to_dpo_proto(adj->ia_link),
              &adj->sub_type.midchain.next_dpo,
              drop_dpo_get(vnet_link_to_dpo_proto(adj->ia_link)));
    CLIB_MEMORY_BARRIER();
}

void
adj_nbr_midchain_stack_on_fib_entry (adj_index_t ai,
                                     fib_node_index_t fei,
                                     fib_forward_chain_type_t fct)
{
    fib_node_index_t *entry_indicies;
    dpo_id_t tmp = DPO_INVALID;
    ip_adjacency_t *adj;

    adj = adj_get (ai);

    /*
     * check to see if this stacking will form a recursion loop
     */
    entry_indicies = NULL;
    adj->sub_type.midchain.fei = fei;

    if (fib_entry_recursive_loop_detect(adj->sub_type.midchain.fei, &entry_indicies))
    {
        /*
         * loop formed, stack on the drop.
         */
        dpo_copy(&tmp, drop_dpo_get(fib_forw_chain_type_to_dpo_proto(fct)));
    }
    else
    {
        fib_entry_contribute_forwarding (fei, fct, &tmp);

        if (DPO_LOAD_BALANCE == tmp.dpoi_type)
        {
            load_balance_t *lb;

            lb = load_balance_get (tmp.dpoi_index);

            if ((adj->ia_flags & ADJ_FLAG_MIDCHAIN_IP_STACK) ||
                lb->lb_n_buckets == 1)
            {
                /*
                 * do that hash now and stack on the choice.
                 * If the choice is an incomplete adj then we will need a poke when
                 * it becomes complete. This happens since the adj update walk propagates
                 * as far a recursive paths.
                 */
                const dpo_id_t *choice;
                int hash;

                if (FIB_FORW_CHAIN_TYPE_UNICAST_IP4 == fct)
                {
                    hash = ip4_compute_flow_hash ((ip4_header_t *) adj_get_rewrite (ai),
                                                  lb->lb_hash_config);
                }
                else if (FIB_FORW_CHAIN_TYPE_UNICAST_IP6 == fct)
                {
                    hash = ip6_compute_flow_hash ((ip6_header_t *) adj_get_rewrite (ai),
                                                  lb->lb_hash_config);
                }
                else
                {
                    hash = 0;
                    ASSERT(0);
                }

                choice = load_balance_get_bucket_i (lb, hash & lb->lb_n_buckets_minus_1);
                dpo_copy (&tmp, choice);
            }
            else if (lb->lb_n_buckets > 1)
            {
                /*
                 * the client has chosen not to use the stacking to select a
                 * bucket, and there are more than one buckets. there's no
                 * value in using the midchain's fixed rewrite string to select
                 * the path, so force a flow hash on the inner.
                 */
                adj->rewrite_header.flags |= VNET_REWRITE_FIXUP_FLOW_HASH;
            }

            if (adj->ia_flags & ADJ_FLAG_MIDCHAIN_FIXUP_FLOW_HASH)
            {
                /*
                 * The client, for reasons unbeknownst to adj, wants to force
                 * a flow hash on the inner, we will oblige.
                 */
                adj->rewrite_header.flags |= VNET_REWRITE_FIXUP_FLOW_HASH;
            }
        }
    }
    adj_nbr_midchain_stack (ai, &tmp);
    dpo_reset(&tmp);
    vec_free(entry_indicies);
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

int
adj_ndr_midchain_recursive_loop_detect (adj_index_t ai,
                                        fib_node_index_t **entry_indicies)
{
    fib_node_index_t *entry_index, *entries;
    ip_adjacency_t * adj;

    adj = adj_get(ai);
    entries = *entry_indicies;

    vec_foreach(entry_index, entries)
    {
        if (*entry_index == adj->sub_type.midchain.fei)
        {
            /*
             * The entry this midchain links to is already in the set
             * of visited entries, this is a loop
             */
            adj->ia_flags |= ADJ_FLAG_MIDCHAIN_LOOPED;
            return (1);
        }
    }

    adj->ia_flags &= ~ADJ_FLAG_MIDCHAIN_LOOPED;
    return (0);
}

u8*
format_adj_midchain (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    u32 indent = va_arg(*ap, u32);
    ip_adjacency_t * adj = adj_get(index);

    s = format (s, "%U", format_vnet_link, adj->ia_link);
    if (adj->rewrite_header.flags & VNET_REWRITE_HAS_FEATURES)
        s = format(s, " [features]");
    s = format (s, " via %U",
		format_ip46_address, &adj->sub_type.nbr.next_hop,
		adj_proto_to_46(adj->ia_nh_proto));
    s = format (s, " %U",
		format_vnet_rewrite,
		&adj->rewrite_header, sizeof (adj->rewrite_data), indent);
    s = format (s, "\n%Ustacked-on",
                format_white_space, indent);

    if (FIB_NODE_INDEX_INVALID != adj->sub_type.midchain.fei)
    {
        s = format (s, " entry:%d", adj->sub_type.midchain.fei);

    }
    s = format (s, ":\n%U%U",
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
    .dv_get_mtu = adj_dpo_get_mtu,
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
