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

#include <vnet/adj/adj.h>
#include <vnet/adj/adj_internal.h>
#include <vnet/fib/fib_walk.h>

/*
 * The 'DB' of all glean adjs.
 * There is only one glean per-interface per-protocol, so this is a per-interface
 * vector
 */
static adj_index_t *adj_gleans[FIB_PROTOCOL_MAX];

static inline vlib_node_registration_t*
adj_get_glean_node (fib_protocol_t proto)
{
    switch (proto) {
    case FIB_PROTOCOL_IP4:
	return (&ip4_glean_node);
    case FIB_PROTOCOL_IP6:
	return (&ip6_glean_node);
    case FIB_PROTOCOL_MPLS:
	break;
    }
    ASSERT(0);
    return (NULL);
}

/*
 * adj_glean_add_or_lock
 *
 * The next_hop address here is used for source address selection in the DP.
 * The glean adj is added to an interface's connected prefix, the next-hop
 * passed here is the local prefix on the same interface.
 */
adj_index_t
adj_glean_add_or_lock (fib_protocol_t proto,
		       u32 sw_if_index,
		       const ip46_address_t *nh_addr)
{
    ip_adjacency_t * adj;

    vec_validate_init_empty(adj_gleans[proto], sw_if_index, ADJ_INDEX_INVALID);

    if (ADJ_INDEX_INVALID == adj_gleans[proto][sw_if_index])
    {
	adj = adj_alloc(proto);

	adj->lookup_next_index = IP_LOOKUP_NEXT_GLEAN;
	adj->ia_nh_proto = proto;
	adj_gleans[proto][sw_if_index] = adj_get_index(adj);

	if (NULL != nh_addr)
	{
	    adj->sub_type.glean.receive_addr = *nh_addr;
	}

	adj->rewrite_header.data_bytes = 0;

	vnet_rewrite_for_sw_interface(vnet_get_main(),
				      adj_fib_proto_2_nd(proto),
				      sw_if_index,
				      adj_get_glean_node(proto)->index,
				      VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST,
				      &adj->rewrite_header,
				      sizeof (adj->rewrite_data));
    }
    else
    {
	adj = adj_get(adj_gleans[proto][sw_if_index]);
    }

    adj_lock(adj_get_index(adj));

    return (adj_get_index(adj));
}

void
adj_glean_remove (fib_protocol_t proto,
		  u32 sw_if_index)
{
    ASSERT(sw_if_index < vec_len(adj_gleans[proto]));

    adj_gleans[proto][sw_if_index] = ADJ_INDEX_INVALID;
}

static clib_error_t *
adj_glean_interface_state_change (vnet_main_t * vnm,
				  u32 sw_if_index,
				  u32 flags)
{
    /*
     * for each glean on the interface trigger a walk back to the children
     */
    fib_protocol_t proto;
    ip_adjacency_t *adj;


    for (proto = FIB_PROTOCOL_IP4; proto <= FIB_PROTOCOL_IP6; proto++)
    {
	if (sw_if_index >= vec_len(adj_gleans[proto]) ||
	    ADJ_INDEX_INVALID == adj_gleans[proto][sw_if_index])
	    continue;

	adj = adj_get(adj_gleans[proto][sw_if_index]);

	fib_node_back_walk_ctx_t bw_ctx = {
	    .fnbw_reason = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP ?
			    FIB_NODE_BW_REASON_FLAG_INTERFACE_UP :
			    FIB_NODE_BW_REASON_FLAG_INTERFACE_DOWN),
	};

	fib_walk_sync(FIB_NODE_TYPE_ADJ, adj_get_index(adj), &bw_ctx);
    }

    return (NULL);
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION(adj_glean_interface_state_change);

/**
 * @brief Invoked on each SW interface of a HW interface when the
 * HW interface state changes
 */
static void
adj_nbr_hw_sw_interface_state_change (vnet_main_t * vnm,
                                      u32 sw_if_index,
                                      void *arg)
{
    adj_glean_interface_state_change(vnm, sw_if_index, (uword) arg);
}

/**
 * @brief Registered callback for HW interface state changes
 */
static clib_error_t *
adj_glean_hw_interface_state_change (vnet_main_t * vnm,
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
                              adj_nbr_hw_sw_interface_state_change,
                              (void*) sw_flags);

    return (NULL);
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION(
    adj_glean_hw_interface_state_change);

static clib_error_t *
adj_glean_interface_delete (vnet_main_t * vnm,
			    u32 sw_if_index,
			    u32 is_add)
{
    /*
     * for each glean on the interface trigger a walk back to the children
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
	if (sw_if_index >= vec_len(adj_gleans[proto]) ||
	    ADJ_INDEX_INVALID == adj_gleans[proto][sw_if_index])
	    continue;

	adj = adj_get(adj_gleans[proto][sw_if_index]);

	fib_node_back_walk_ctx_t bw_ctx = {
	    .fnbw_reason =  FIB_NODE_BW_REASON_FLAG_INTERFACE_DELETE,
	};

	fib_walk_sync(FIB_NODE_TYPE_ADJ, adj_get_index(adj), &bw_ctx);
    }

    return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION(adj_glean_interface_delete);

u8*
format_adj_glean (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    vnet_main_t * vnm = vnet_get_main();
    ip_adjacency_t * adj = adj_get(index);

    return (format(s, "%U-glean: %U",
		   format_fib_protocol, adj->ia_nh_proto,
                   format_vnet_sw_interface_name,
                   vnm,
                   vnet_get_sw_interface(vnm,
                                         adj->rewrite_header.sw_if_index)));
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

const static dpo_vft_t adj_glean_dpo_vft = {
    .dv_lock = adj_dpo_lock,
    .dv_unlock = adj_dpo_unlock,
    .dv_format = format_adj_glean,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to a glean
 *        object.
 *
 * this means that these graph nodes are ones from which a glean is the
 * parent object in the DPO-graph.
 */
const static char* const glean_ip4_nodes[] =
{
    "ip4-glean",
    NULL,
};
const static char* const glean_ip6_nodes[] =
{
    "ip6-glean",
    NULL,
};

const static char* const * const glean_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = glean_ip4_nodes,
    [DPO_PROTO_IP6]  = glean_ip6_nodes,
    [DPO_PROTO_MPLS] = NULL,
};

void
adj_glean_module_init (void)
{
    dpo_register(DPO_ADJACENCY_GLEAN, &adj_glean_dpo_vft, glean_nodes);
}
