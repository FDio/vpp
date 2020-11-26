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
 * There is one glean per-{interface, protocol, connected prefix}
 */
static uword **adj_gleans[FIB_PROTOCOL_IP_MAX];

static inline u32
adj_get_glean_node (fib_protocol_t proto)
{
    switch (proto) {
    case FIB_PROTOCOL_IP4:
	return (ip4_glean_node.index);
    case FIB_PROTOCOL_IP6:
	return (ip6_glean_node.index);
    case FIB_PROTOCOL_MPLS:
	break;
    }
    ASSERT(0);
    return (~0);
}

static adj_index_t
adj_glean_db_lookup (fib_protocol_t proto,
                     u32 sw_if_index,
                     const ip46_address_t *nh_addr)
{
    uword *p;

    if (vec_len(adj_gleans[proto]) <= sw_if_index)
        return (ADJ_INDEX_INVALID);

    p = hash_get_mem (adj_gleans[proto][sw_if_index], nh_addr);

    if (p)
        return (p[0]);

    return (ADJ_INDEX_INVALID);
}

static void
adj_glean_db_insert (fib_protocol_t proto,
                     u32 sw_if_index,
                     const ip46_address_t *nh_addr,
                     adj_index_t ai)
{
    vlib_main_t *vm = vlib_get_main();

    vlib_worker_thread_barrier_sync(vm);

    vec_validate(adj_gleans[proto], sw_if_index);

    if (NULL == adj_gleans[proto][sw_if_index])
    {
        adj_gleans[proto][sw_if_index] =
            hash_create_mem (0, sizeof(ip46_address_t), sizeof(adj_index_t));
    }

    hash_set_mem_alloc (&adj_gleans[proto][sw_if_index],
                        nh_addr, ai);

    vlib_worker_thread_barrier_release(vm);
}

static void
adj_glean_db_remove (fib_protocol_t proto,
                     u32 sw_if_index,
                     const ip46_address_t *nh_addr)
{
    vlib_main_t *vm = vlib_get_main();

    vlib_worker_thread_barrier_sync(vm);

    ASSERT(ADJ_INDEX_INVALID != adj_glean_db_lookup(proto, sw_if_index, nh_addr));
    hash_unset_mem_free (&adj_gleans[proto][sw_if_index],
                         nh_addr);

    if (0 == hash_elts(adj_gleans[proto][sw_if_index]))
    {
        hash_free(adj_gleans[proto][sw_if_index]);
        adj_gleans[proto][sw_if_index] = NULL;
    }
    vlib_worker_thread_barrier_release(vm);
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
                       vnet_link_t linkt,
		       u32 sw_if_index,
		       const fib_prefix_t *conn)
{
    ip_adjacency_t * adj;
    adj_index_t ai;

    ai = adj_glean_db_lookup(proto, sw_if_index, &conn->fp_addr);

    if (ADJ_INDEX_INVALID == ai)
    {
	adj = adj_alloc(proto);

	adj->lookup_next_index = IP_LOOKUP_NEXT_GLEAN;
	adj->ia_nh_proto = proto;
        adj->ia_link = linkt;
        adj->ia_node_index = adj_get_glean_node(proto);
        ai = adj_get_index(adj);
        adj_lock(ai);

	ASSERT(conn);
        fib_prefix_normalize(conn, &adj->sub_type.glean.rx_pfx);
	adj->rewrite_header.sw_if_index = sw_if_index;
	adj->rewrite_header.data_bytes = 0;
        adj->rewrite_header.max_l3_packet_bytes =
	  vnet_sw_interface_get_mtu(vnet_get_main(), sw_if_index,
                                    vnet_link_to_mtu(linkt));

	vnet_update_adjacency_for_sw_interface(vnet_get_main(),
                                               sw_if_index,
                                               ai);

	adj_glean_db_insert(proto, sw_if_index,
                            &adj->sub_type.glean.rx_pfx.fp_addr, ai);
    }
    else
    {
	adj = adj_get(ai);
        adj_lock(ai);
    }

    adj_delegate_adj_created(adj);

    return (ai);
}

/**
 * adj_glean_update_rewrite
 */
void
adj_glean_update_rewrite (adj_index_t adj_index)
{
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);

    vnet_rewrite_for_sw_interface(vnet_get_main(),
                                  adj_fib_proto_2_nd(adj->ia_nh_proto),
                                  adj->rewrite_header.sw_if_index,
                                  adj->ia_node_index,
                                  VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST,
                                  &adj->rewrite_header,
                                  sizeof (adj->rewrite_data));
}

static adj_walk_rc_t
adj_glean_update_rewrite_walk (adj_index_t ai,
                               void *data)
{
    adj_glean_update_rewrite(ai);

    return (ADJ_WALK_RC_CONTINUE);
}

void
adj_glean_update_rewrite_itf (u32 sw_if_index)
{
    adj_glean_walk (sw_if_index, adj_glean_update_rewrite_walk, NULL);
}

void
adj_glean_walk (u32 sw_if_index,
                adj_walk_cb_t cb,
                void *data)
{
    fib_protocol_t proto;

    FOR_EACH_FIB_IP_PROTOCOL(proto)
    {
        adj_index_t ai, *aip, *ais = NULL;
        ip46_address_t *conn;

        if (vec_len(adj_gleans[proto]) <= sw_if_index ||
            NULL == adj_gleans[proto][sw_if_index])
            continue;

        /*
         * Walk first to collect the indices
         * then walk the collection. This is safe
         * to modifications of the hash table
         */
        hash_foreach_mem(conn, ai, adj_gleans[proto][sw_if_index],
        ({
            vec_add1(ais, ai);
        }));

        vec_foreach(aip, ais)
        {
            if (ADJ_WALK_RC_STOP == cb(*aip, data))
                break;
        }
        vec_free(ais);
    }
}

adj_index_t
adj_glean_get (fib_protocol_t proto,
               u32 sw_if_index,
               const ip46_address_t *nh)
{
    if (NULL != nh)
    {
        return adj_glean_db_lookup(proto, sw_if_index, nh);
    }
    else
    {
        ip46_address_t *conn;
        adj_index_t ai;

        if (vec_len(adj_gleans[proto]) <= sw_if_index ||
            NULL == adj_gleans[proto][sw_if_index])
            return (ADJ_INDEX_INVALID);

        hash_foreach_mem(conn, ai, adj_gleans[proto][sw_if_index],
        ({
            return (ai);
        }));
    }
    return (ADJ_INDEX_INVALID);
}

const ip46_address_t *
adj_glean_get_src (fib_protocol_t proto,
                   u32 sw_if_index,
                   const ip46_address_t *nh)
{
    const ip_adjacency_t *adj;
    ip46_address_t *conn;
    adj_index_t ai;

    if (vec_len(adj_gleans[proto]) <= sw_if_index ||
        NULL == adj_gleans[proto][sw_if_index])
        return (NULL);

    fib_prefix_t pfx = {
        .fp_len = fib_prefix_get_host_length(proto),
        .fp_proto = proto,
    };

    if (nh)
        pfx.fp_addr = *nh;

    hash_foreach_mem(conn, ai, adj_gleans[proto][sw_if_index],
    ({
        adj = adj_get(ai);

        if (adj->sub_type.glean.rx_pfx.fp_len > 0)
        {
            /* if no destination is specified use the just glean */
            if (NULL == nh)
                return (&adj->sub_type.glean.rx_pfx.fp_addr);

            /* check the clean covers the desintation */
            if (fib_prefix_is_cover(&adj->sub_type.glean.rx_pfx, &pfx))
                return (&adj->sub_type.glean.rx_pfx.fp_addr);
        }
    }));

    return (NULL);
}

void
adj_glean_remove (ip_adjacency_t *adj)
{
    fib_prefix_t norm;

    fib_prefix_normalize(&adj->sub_type.glean.rx_pfx,
                         &norm);
    adj_glean_db_remove(adj->ia_nh_proto,
                        adj->rewrite_header.sw_if_index,
                        &norm.fp_addr);
}

static adj_walk_rc_t
adj_glean_start_backwalk (adj_index_t ai,
                          void *data)
{
    fib_node_back_walk_ctx_t bw_ctx = *(fib_node_back_walk_ctx_t*) data;

    fib_walk_sync(FIB_NODE_TYPE_ADJ, ai, &bw_ctx);

    return (ADJ_WALK_RC_CONTINUE);
}

static clib_error_t *
adj_glean_interface_state_change (vnet_main_t * vnm,
				  u32 sw_if_index,
				  u32 flags)
{
    /*
     * for each glean on the interface trigger a walk back to the children
     */
    fib_node_back_walk_ctx_t bw_ctx = {
        .fnbw_reason = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP ?
                        FIB_NODE_BW_REASON_FLAG_INTERFACE_UP :
                        FIB_NODE_BW_REASON_FLAG_INTERFACE_DOWN),
    };

    adj_glean_walk (sw_if_index, adj_glean_start_backwalk, &bw_ctx);

    return (NULL);
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION(adj_glean_interface_state_change);

/**
 * @brief Invoked on each SW interface of a HW interface when the
 * HW interface state changes
 */
static walk_rc_t
adj_nbr_hw_sw_interface_state_change (vnet_main_t * vnm,
                                      u32 sw_if_index,
                                      void *arg)
{
    adj_glean_interface_state_change(vnm, sw_if_index, (uword) arg);

    return (WALK_CONTINUE);
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

    /*
     * for each glean on the interface trigger a walk back to the children
     */
    fib_node_back_walk_ctx_t bw_ctx = {
        .fnbw_reason =  FIB_NODE_BW_REASON_FLAG_INTERFACE_DELETE,
    };

    adj_glean_walk (sw_if_index, adj_glean_start_backwalk, &bw_ctx);

    return (NULL);
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION(adj_glean_interface_delete);

u8*
format_adj_glean (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    ip_adjacency_t * adj = adj_get(index);

    s = format(s, "%U-glean: [src:%U] %U",
               format_fib_protocol, adj->ia_nh_proto,
               format_fib_prefix, &adj->sub_type.glean.rx_pfx,
               format_vnet_rewrite,
               &adj->rewrite_header, sizeof (adj->rewrite_data), 0);

    return (s);
}

u32
adj_glean_db_size (void)
{
    fib_protocol_t proto;
    u32 sw_if_index = 0;
    u64 count = 0;

    FOR_EACH_FIB_IP_PROTOCOL(proto)
    {
	vec_foreach_index(sw_if_index, adj_gleans[proto])
	{
	    if (NULL != adj_gleans[proto][sw_if_index])
	    {
		count += hash_elts(adj_gleans[proto][sw_if_index]);
	    }
	}
    }
    return (count);
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
    .dv_get_urpf = adj_dpo_get_urpf,
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
