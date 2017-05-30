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

#include <vnet/adj/adj_mcast.h>
#include <vnet/adj/adj_internal.h>
#include <vnet/fib/fib_walk.h>
#include <vnet/ip/ip.h>

/*
 * The 'DB' of all mcast adjs.
 * There is only one mcast per-interface per-protocol, so this is a per-interface
 * vector
 */
static adj_index_t *adj_mcasts[FIB_PROTOCOL_MAX];

static u32
adj_get_mcast_node (fib_protocol_t proto)
{
    switch (proto) {
    case FIB_PROTOCOL_IP4:
	return (ip4_rewrite_mcast_node.index);
    case FIB_PROTOCOL_IP6:
	return (ip6_rewrite_mcast_node.index);
    case FIB_PROTOCOL_MPLS:
	break;
    }
    ASSERT(0);
    return (0);
}

/*
 * adj_mcast_add_or_lock
 *
 * The next_hop address here is used for source address selection in the DP.
 * The mcast adj is added to an interface's connected prefix, the next-hop
 * passed here is the local prefix on the same interface.
 */
adj_index_t
adj_mcast_add_or_lock (fib_protocol_t proto,
                       vnet_link_t link_type,
		       u32 sw_if_index)
{
    ip_adjacency_t * adj;

    vec_validate_init_empty(adj_mcasts[proto], sw_if_index, ADJ_INDEX_INVALID);

    if (ADJ_INDEX_INVALID == adj_mcasts[proto][sw_if_index])
    {
        vnet_main_t *vnm;

        vnm = vnet_get_main();
	adj = adj_alloc(proto);

	adj->lookup_next_index = IP_LOOKUP_NEXT_MCAST;
	adj->ia_nh_proto = proto;
	adj->ia_link = link_type;
	adj_mcasts[proto][sw_if_index] = adj_get_index(adj);
        adj_lock(adj_get_index(adj));

	vnet_rewrite_init(vnm, sw_if_index,
			  adj_get_mcast_node(proto),
			  vnet_tx_node_index_for_sw_interface(vnm, sw_if_index),
			  &adj->rewrite_header);

	/*
	 * we need a rewrite where the destination IP address is converted
	 * to the appropriate link-layer address. This is interface specific.
	 * So ask the interface to do it.
	 */
	vnet_update_adjacency_for_sw_interface(vnm, sw_if_index,
                                               adj_get_index(adj));
    }
    else
    {
	adj = adj_get(adj_mcasts[proto][sw_if_index]);
        adj_lock(adj_get_index(adj));
    }

    return (adj_get_index(adj));
}

/**
 * adj_mcast_update_rewrite
 *
 * Update the adjacency's rewrite string. A NULL string implies the
 * rewirte is reset (i.e. when ARP/ND etnry is gone).
 * NB: the adj being updated may be handling traffic in the DP.
 */
void
adj_mcast_update_rewrite (adj_index_t adj_index,
                          u8 *rewrite,
                          u8 offset,
                          u32 mask)
{
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);

    /*
     * update the adj's rewrite string and build the arc
     * from the rewrite node to the interface's TX node
     */
    adj_nbr_update_rewrite_internal(adj, IP_LOOKUP_NEXT_MCAST,
                                    adj_get_mcast_node(adj->ia_nh_proto),
                                    vnet_tx_node_index_for_sw_interface(
                                        vnet_get_main(),
                                        adj->rewrite_header.sw_if_index),
                                    rewrite);
    /*
     * set the fields corresponding to the mcast IP address rewrite
     * The mask must be stored in network byte order, since the packet's
     * IP address will also be in network order.
     */
    adj->rewrite_header.dst_mcast_offset = offset;
    adj->rewrite_header.dst_mcast_mask = clib_host_to_net_u32(mask);
}

/**
 * adj_mcast_midchain_update_rewrite
 *
 * Update the adjacency's rewrite string. A NULL string implies the
 * rewirte is reset (i.e. when ARP/ND etnry is gone).
 * NB: the adj being updated may be handling traffic in the DP.
 */
void
adj_mcast_midchain_update_rewrite (adj_index_t adj_index,
                                   adj_midchain_fixup_t fixup,
                                   adj_flags_t flags,
                                   u8 *rewrite,
                                   u8 offset,
                                   u32 mask)
{
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);

    /*
     * one time only update. since we don't support chainging the tunnel
     * src,dst, this is all we need.
     */
    ASSERT(adj->lookup_next_index == IP_LOOKUP_NEXT_MCAST);
    /*
     * tunnels can always provide a rewrite.
     */
    ASSERT(NULL != rewrite);

    adj_midchain_setup(adj_index, fixup, flags);

    /*
     * update the adj's rewrite string and build the arc
     * from the rewrite node to the interface's TX node
     */
    adj_nbr_update_rewrite_internal(adj, IP_LOOKUP_NEXT_MCAST_MIDCHAIN,
                                    adj_get_mcast_node(adj->ia_nh_proto),
                                    vnet_tx_node_index_for_sw_interface(
                                        vnet_get_main(),
                                        adj->rewrite_header.sw_if_index),
                                    rewrite);

    /*
     * set the fields corresponding to the mcast IP address rewrite
     * The mask must be stored in network byte order, since the packet's
     * IP address will also be in network order.
     */
    adj->rewrite_header.dst_mcast_offset = offset;
    adj->rewrite_header.dst_mcast_mask = clib_host_to_net_u32(mask);
}

void
adj_mcast_remove (fib_protocol_t proto,
		  u32 sw_if_index)
{
    ASSERT(sw_if_index < vec_len(adj_mcasts[proto]));

    adj_mcasts[proto][sw_if_index] = ADJ_INDEX_INVALID;
}

static clib_error_t *
adj_mcast_interface_state_change (vnet_main_t * vnm,
				  u32 sw_if_index,
				  u32 flags)
{
    /*
     * for each mcast on the interface trigger a walk back to the children
     */
    fib_protocol_t proto;
    ip_adjacency_t *adj;


    for (proto = FIB_PROTOCOL_IP4; proto <= FIB_PROTOCOL_IP6; proto++)
    {
	if (sw_if_index >= vec_len(adj_mcasts[proto]) ||
	    ADJ_INDEX_INVALID == adj_mcasts[proto][sw_if_index])
	    continue;

	adj = adj_get(adj_mcasts[proto][sw_if_index]);

	fib_node_back_walk_ctx_t bw_ctx = {
	    .fnbw_reason = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP ?
			    FIB_NODE_BW_REASON_FLAG_INTERFACE_UP :
			    FIB_NODE_BW_REASON_FLAG_INTERFACE_DOWN),
	};

	fib_walk_sync(FIB_NODE_TYPE_ADJ, adj_get_index(adj), &bw_ctx);
    }

    return (NULL);
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION(adj_mcast_interface_state_change);

/**
 * @brief Invoked on each SW interface of a HW interface when the
 * HW interface state changes
 */
static void
adj_mcast_hw_sw_interface_state_change (vnet_main_t * vnm,
                                        u32 sw_if_index,
                                        void *arg)
{
    adj_mcast_interface_state_change(vnm, sw_if_index, (uword) arg);
}

/**
 * @brief Registered callback for HW interface state changes
 */
static clib_error_t *
adj_mcast_hw_interface_state_change (vnet_main_t * vnm,
                                     u32 hw_if_index,
                                     u32 flags)
{
    /*
     * walk SW interfaces on the HW
     */
    uword sw_flags;

    sw_flags = ((flags & VNET_HW_INTERFACE_FLAG_LINK_UP) ?
                VNET_SW_INTERFACE_FLAG_ADMIN_UP :
                0);

    vnet_hw_interface_walk_sw(vnm, hw_if_index,
                              adj_mcast_hw_sw_interface_state_change,
                              (void*) sw_flags);

    return (NULL);
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION(
    adj_mcast_hw_interface_state_change);

static clib_error_t *
adj_mcast_interface_delete (vnet_main_t * vnm,
			    u32 sw_if_index,
			    u32 is_add)
{
    /*
     * for each mcast on the interface trigger a walk back to the children
     */
    fib_protocol_t proto;
    ip_adjacency_t *adj;

    if (is_add)
    {
	/*
	 * not interested in interface additions. we will not back walk
	 * to resolve paths through newly added interfaces. Why? The control
	 * plane should have the brains to add interfaces first, then routes.
	 * So the case where there are paths with a interface that matches
	 * one just created is the case where the path resolved through an
	 * interface that was deleted, and still has not been removed. The
	 * new interface added, is NO GUARANTEE that the interface being
	 * added now, even though it may have the same sw_if_index, is the
	 * same interface that the path needs. So tough!
	 * If the control plane wants these routes to resolve it needs to
	 * remove and add them again.
	 */
	return (NULL);
    }

    for (proto = FIB_PROTOCOL_IP4; proto <= FIB_PROTOCOL_IP6; proto++)
    {
	if (sw_if_index >= vec_len(adj_mcasts[proto]) ||
	    ADJ_INDEX_INVALID == adj_mcasts[proto][sw_if_index])
	    continue;

	adj = adj_get(adj_mcasts[proto][sw_if_index]);

	fib_node_back_walk_ctx_t bw_ctx = {
	    .fnbw_reason =  FIB_NODE_BW_REASON_FLAG_INTERFACE_DELETE,
	};

	fib_walk_sync(FIB_NODE_TYPE_ADJ, adj_get_index(adj), &bw_ctx);
    }

    return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION(adj_mcast_interface_delete);

/**
 * @brief Walk the multicast Adjacencies on a given interface
 */
void
adj_mcast_walk (u32 sw_if_index,
                fib_protocol_t proto,
                adj_walk_cb_t cb,
                void *ctx)
{
    if (vec_len(adj_mcasts[proto]) > sw_if_index)
    {
        if (ADJ_INDEX_INVALID != adj_mcasts[proto][sw_if_index])
        {
            cb(adj_mcasts[proto][sw_if_index], ctx);
        }
    }
}

u8*
format_adj_mcast (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    ip_adjacency_t * adj = adj_get(index);

    s = format(s, "%U-mcast: ",
               format_fib_protocol, adj->ia_nh_proto);
    if (adj->rewrite_header.flags & VNET_REWRITE_HAS_FEATURES)
        s = format(s, "[features] ");
    s = format (s, "%U",
		format_vnet_rewrite,
                &adj->rewrite_header, sizeof (adj->rewrite_data), 0);

    return (s);
}

u8*
format_adj_mcast_midchain (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    vnet_main_t * vnm = vnet_get_main();
    ip_adjacency_t * adj = adj_get(index);

    s = format(s, "%U-mcast-midchain: ",
               format_fib_protocol, adj->ia_nh_proto);
    s = format (s, "%U",
		format_vnet_rewrite,
		vnm->vlib_main, &adj->rewrite_header,
                sizeof (adj->rewrite_data), 0);
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

const static dpo_vft_t adj_mcast_dpo_vft = {
    .dv_lock = adj_dpo_lock,
    .dv_unlock = adj_dpo_unlock,
    .dv_format = format_adj_mcast,
};
const static dpo_vft_t adj_mcast_midchain_dpo_vft = {
    .dv_lock = adj_dpo_lock,
    .dv_unlock = adj_dpo_unlock,
    .dv_format = format_adj_mcast_midchain,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a mcast
 *        object.
 *
 * this means that these graph nodes are ones from which a mcast is the
 * parent object in the DPO-graph.
 */
const static char* const adj_mcast_ip4_nodes[] =
{
    "ip4-rewrite-mcast",
    NULL,
};
const static char* const adj_mcast_ip6_nodes[] =
{
    "ip6-rewrite-mcast",
    NULL,
};

const static char* const * const adj_mcast_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = adj_mcast_ip4_nodes,
    [DPO_PROTO_IP6]  = adj_mcast_ip6_nodes,
    [DPO_PROTO_MPLS] = NULL,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a mcast
 *        object.
 *
 * this means that these graph nodes are ones from which a mcast is the
 * parent object in the DPO-graph.
 */
const static char* const adj_mcast_midchain_ip4_nodes[] =
{
    "ip4-mcast-midchain",
    NULL,
};
const static char* const adj_mcast_midchain_ip6_nodes[] =
{
    "ip6-mcast-midchain",
    NULL,
};

const static char* const * const adj_mcast_midchain_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = adj_mcast_midchain_ip4_nodes,
    [DPO_PROTO_IP6]  = adj_mcast_midchain_ip6_nodes,
    [DPO_PROTO_MPLS] = NULL,
};

/**
 * @brief Return the size of the adj DB.
 * This is only for testing purposes so an efficient implementation is not needed
 */
u32
adj_mcast_db_size (void)
{
    u32 n_adjs, sw_if_index;
    fib_protocol_t proto;

    n_adjs = 0;
    for (proto = FIB_PROTOCOL_IP4; proto <= FIB_PROTOCOL_IP6; proto++)
    {
        for (sw_if_index = 0;
             sw_if_index < vec_len(adj_mcasts[proto]);
             sw_if_index++)
        {
            if (ADJ_INDEX_INVALID != adj_mcasts[proto][sw_if_index])
            {
                n_adjs++;
            }
        }
    }
    
    return (n_adjs);
}

void
adj_mcast_module_init (void)
{
    dpo_register(DPO_ADJACENCY_MCAST,
                 &adj_mcast_dpo_vft,
                 adj_mcast_nodes);
    dpo_register(DPO_ADJACENCY_MCAST_MIDCHAIN,
                 &adj_mcast_midchain_dpo_vft,
                 adj_mcast_midchain_nodes);
}
