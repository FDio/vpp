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
#include <vnet/fib/fib_walk.h>

/*
 * Vector Hash tables of neighbour (traditional) adjacencies
 *  Key: interface(for the vector index), address (and its proto),
 *       link-type/ether-type.
 */
static BVT(clib_bihash) **adj_nbr_tables[FIB_PROTOCOL_MAX];

// FIXME SIZE APPROPRIATELY. ASK DAVEB.
#define ADJ_NBR_DEFAULT_HASH_NUM_BUCKETS (64 * 64)
#define ADJ_NBR_DEFAULT_HASH_MEMORY_SIZE (32<<20)


#define ADJ_NBR_SET_KEY(_key, _lt, _nh)         \
{						\
    _key.key[0] = (_nh)->as_u64[0];		\
    _key.key[1] = (_nh)->as_u64[1];		\
    _key.key[2] = (_lt);			\
}

#define ADJ_NBR_ITF_OK(_proto, _itf)			\
    (((_itf) < vec_len(adj_nbr_tables[_proto])) &&	\
     (NULL != adj_nbr_tables[_proto][sw_if_index]))

static void
adj_nbr_insert (fib_protocol_t nh_proto,
		vnet_link_t link_type,
		const ip46_address_t *nh_addr,
		u32 sw_if_index,
		adj_index_t adj_index)
{
    BVT(clib_bihash_kv) kv;

    if (sw_if_index >= vec_len(adj_nbr_tables[nh_proto]))
    {
	vec_validate(adj_nbr_tables[nh_proto], sw_if_index);
    }
    if (NULL == adj_nbr_tables[nh_proto][sw_if_index])
    {
	adj_nbr_tables[nh_proto][sw_if_index] =
	    clib_mem_alloc_aligned(sizeof(BVT(clib_bihash)),
				   CLIB_CACHE_LINE_BYTES);
	clib_memset(adj_nbr_tables[nh_proto][sw_if_index],
	       0,
	       sizeof(BVT(clib_bihash)));

	BV(clib_bihash_init) (adj_nbr_tables[nh_proto][sw_if_index],
			      "Adjacency Neighbour table",
			      ADJ_NBR_DEFAULT_HASH_NUM_BUCKETS,
			      ADJ_NBR_DEFAULT_HASH_MEMORY_SIZE);
    }

    ADJ_NBR_SET_KEY(kv, link_type, nh_addr);
    kv.value = adj_index;

    BV(clib_bihash_add_del) (adj_nbr_tables[nh_proto][sw_if_index], &kv, 1);
}

void
adj_nbr_remove (adj_index_t ai,
                fib_protocol_t nh_proto,
		vnet_link_t link_type,
		const ip46_address_t *nh_addr,
		u32 sw_if_index)
{
    BVT(clib_bihash_kv) kv;

    if (!ADJ_NBR_ITF_OK(nh_proto, sw_if_index))
	return;

    ADJ_NBR_SET_KEY(kv, link_type, nh_addr);
    kv.value = ai;

    BV(clib_bihash_add_del) (adj_nbr_tables[nh_proto][sw_if_index], &kv, 0);
}

adj_index_t
adj_nbr_find (fib_protocol_t nh_proto,
	      vnet_link_t link_type,
	      const ip46_address_t *nh_addr,
	      u32 sw_if_index)
{
    BVT(clib_bihash_kv) kv;

    ADJ_NBR_SET_KEY(kv, link_type, nh_addr);

    if (!ADJ_NBR_ITF_OK(nh_proto, sw_if_index))
	return (ADJ_INDEX_INVALID);

    if (BV(clib_bihash_search)(adj_nbr_tables[nh_proto][sw_if_index],
			       &kv, &kv) < 0)
    {
	return (ADJ_INDEX_INVALID);
    }
    else
    {
	return (kv.value);
    }
}

static inline u32
adj_get_nd_node (fib_protocol_t proto)
{
    switch (proto) {
    case FIB_PROTOCOL_IP4:
	return (ip4_arp_node.index);
    case FIB_PROTOCOL_IP6:
	return (ip6_discover_neighbor_node.index);
    case FIB_PROTOCOL_MPLS:
	break;
    }
    ASSERT(0);
    return (ip4_arp_node.index);
}

/**
 * @brief Check and set feature flags if o/p interface has any o/p features.
 */
static void
adj_nbr_evaluate_feature (adj_index_t ai)
{
    ip_adjacency_t *adj;
    vnet_feature_main_t *fm = &feature_main;
    i16 feature_count;
    u8 arc_index;
    u32 sw_if_index;

    adj = adj_get(ai);

    switch (adj->ia_link)
    {
    case VNET_LINK_IP4:
        arc_index = ip4_main.lookup_main.output_feature_arc_index;
        break;
    case VNET_LINK_IP6:
        arc_index = ip6_main.lookup_main.output_feature_arc_index;
        break;
    case VNET_LINK_MPLS:
        arc_index = mpls_main.output_feature_arc_index;
        break;
    default:
        return;
    }

    sw_if_index = adj->rewrite_header.sw_if_index;
    if (vec_len(fm->feature_count_by_sw_if_index[arc_index]) > sw_if_index)
    {
        feature_count = fm->feature_count_by_sw_if_index[arc_index][sw_if_index];
        if (feature_count > 0)
            adj->rewrite_header.flags |= VNET_REWRITE_HAS_FEATURES;
    }

    return;
}

static ip_adjacency_t*
adj_nbr_alloc (fib_protocol_t nh_proto,
	       vnet_link_t link_type,
	       const ip46_address_t *nh_addr,
	       u32 sw_if_index)
{
    ip_adjacency_t *adj;

    adj = adj_alloc(nh_proto);

    adj_nbr_insert(nh_proto, link_type, nh_addr,
		   sw_if_index,
		   adj_get_index(adj));

    /*
     * since we just added the ADJ we have no rewrite string for it,
     * so its for ARP
     */
    adj->lookup_next_index = IP_LOOKUP_NEXT_ARP;
    adj->sub_type.nbr.next_hop = *nh_addr;
    adj->ia_link = link_type;
    adj->ia_nh_proto = nh_proto;
    adj->rewrite_header.sw_if_index = sw_if_index;
    vnet_rewrite_update_mtu(vnet_get_main(), adj->ia_link,
                            &adj->rewrite_header);

    adj_nbr_evaluate_feature (adj_get_index(adj));
    return (adj);
}

/*
 * adj_nbr_add_or_lock
 *
 * Add an adjacency for the neighbour requested.
 *
 * The key for an adj is:
 *   - the Next-hops protocol (i.e. v4 or v6)
 *   - the address of the next-hop
 *   - the interface the next-hop is reachable through
 */
adj_index_t
adj_nbr_add_or_lock (fib_protocol_t nh_proto,
		     vnet_link_t link_type,
		     const ip46_address_t *nh_addr,
		     u32 sw_if_index)
{
    adj_index_t adj_index;
    ip_adjacency_t *adj;

    adj_index = adj_nbr_find(nh_proto, link_type, nh_addr, sw_if_index);

    if (ADJ_INDEX_INVALID == adj_index)
    {
	vnet_main_t *vnm;

	vnm = vnet_get_main();
	adj = adj_nbr_alloc(nh_proto, link_type, nh_addr, sw_if_index);
	adj_index = adj_get_index(adj);
	adj_lock(adj_index);

        if (ip46_address_is_equal(&ADJ_BCAST_ADDR, nh_addr))
        {
            adj->lookup_next_index = IP_LOOKUP_NEXT_BCAST;
        }

	vnet_rewrite_init(vnm, sw_if_index, link_type,
			  adj_get_nd_node(nh_proto),
			  vnet_tx_node_index_for_sw_interface(vnm, sw_if_index),
			  &adj->rewrite_header);

	/*
	 * we need a rewrite where the destination IP address is converted
	 * to the appropriate link-layer address. This is interface specific.
	 * So ask the interface to do it.
	 */
	vnet_update_adjacency_for_sw_interface(vnm, sw_if_index, adj_index);
    }
    else
    {
	adj_lock(adj_index);
    }

    return (adj_index);
}

adj_index_t
adj_nbr_add_or_lock_w_rewrite (fib_protocol_t nh_proto,
			       vnet_link_t link_type,
			       const ip46_address_t *nh_addr,
			       u32 sw_if_index,
			       u8 *rewrite)
{
    adj_index_t adj_index;
    ip_adjacency_t *adj;

    adj_index = adj_nbr_find(nh_proto, link_type, nh_addr, sw_if_index);

    if (ADJ_INDEX_INVALID == adj_index)
    {
	adj = adj_nbr_alloc(nh_proto, link_type, nh_addr, sw_if_index);
	adj->rewrite_header.sw_if_index = sw_if_index;
    }
    else
    {
        adj = adj_get(adj_index);
    }

    adj_lock(adj_get_index(adj));
    adj_nbr_update_rewrite(adj_get_index(adj),
			   ADJ_NBR_REWRITE_FLAG_COMPLETE,
			   rewrite);

    return (adj_get_index(adj));
}

/**
 * adj_nbr_update_rewrite
 *
 * Update the adjacency's rewrite string. A NULL string implies the
 * rewirte is reset (i.e. when ARP/ND etnry is gone).
 * NB: the adj being updated may be handling traffic in the DP.
 */
void
adj_nbr_update_rewrite (adj_index_t adj_index,
			adj_nbr_rewrite_flag_t flags,
			u8 *rewrite)
{
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);

    if (flags & ADJ_NBR_REWRITE_FLAG_COMPLETE)
    {
	/*
	 * update the adj's rewrite string and build the arc
	 * from the rewrite node to the interface's TX node
	 */
	adj_nbr_update_rewrite_internal(adj, IP_LOOKUP_NEXT_REWRITE,
					adj_get_rewrite_node(adj->ia_link),
					vnet_tx_node_index_for_sw_interface(
					    vnet_get_main(),
					    adj->rewrite_header.sw_if_index),
					rewrite);
    }
    else
    {
	adj_nbr_update_rewrite_internal(adj, IP_LOOKUP_NEXT_ARP,
					adj_get_nd_node(adj->ia_nh_proto),
					vnet_tx_node_index_for_sw_interface(
					    vnet_get_main(),
					    adj->rewrite_header.sw_if_index),
					rewrite);
    }
}

/**
 * adj_nbr_update_rewrite_internal
 *
 * Update the adjacency's rewrite string. A NULL string implies the
 * rewirte is reset (i.e. when ARP/ND etnry is gone).
 * NB: the adj being updated may be handling traffic in the DP.
 */
void
adj_nbr_update_rewrite_internal (ip_adjacency_t *adj,
				 ip_lookup_next_t adj_next_index,
				 u32 this_node,
				 u32 next_node,
				 u8 *rewrite)
{
    ip_adjacency_t *walk_adj;
    adj_index_t walk_ai;
    vlib_main_t * vm;
    u32 old_next;
    int do_walk;

    vm = vlib_get_main();
    old_next = adj->lookup_next_index;

    walk_ai = adj_get_index(adj);
    if (VNET_LINK_MPLS == adj->ia_link)
    {
        /*
         * The link type MPLS has no children in the control plane graph, it only
         * has children in the data-palne graph. The backwalk is up the former.
         * So we need to walk from its IP cousin.
         */
        walk_ai = adj_nbr_find(adj->ia_nh_proto,
                               fib_proto_to_link(adj->ia_nh_proto),
                               &adj->sub_type.nbr.next_hop,
                               adj->rewrite_header.sw_if_index);
    }

    /*
     * Don't call the walk re-entrantly
     */
    if (ADJ_INDEX_INVALID != walk_ai)
    {
        walk_adj = adj_get(walk_ai);
        if (ADJ_FLAG_SYNC_WALK_ACTIVE & walk_adj->ia_flags)
        {
            do_walk = 0;
        }
        else
        {
            /*
             * Prevent re-entrant walk of the same adj
             */
            walk_adj->ia_flags |= ADJ_FLAG_SYNC_WALK_ACTIVE;
            do_walk = 1;
        }
    }
    else
    {
        do_walk = 0;
    }

    /*
     * lock the adjacencies that are affected by updates this walk will provoke.
     * Since the aim of the walk is to update children to link to a different
     * DPO, this adj will no longer be in use and its lock count will drop to 0.
     * We don't want it to be deleted as part of this endevour.
     */
    adj_lock(adj_get_index(adj));
    adj_lock(walk_ai);

    /*
     * Updating a rewrite string is not atomic;
     *  - the rewrite string is too long to write in one instruction
     *  - when swapping from incomplete to complete, we also need to update
     *    the VLIB graph next-index of the adj.
     * ideally we would only want to suspend forwarding via this adj whilst we
     * do this, but we do not have that level of granularity - it's suspend all
     * worker threads or nothing.
     * The other chioces are:
     *  - to mark the adj down and back walk so child load-balances drop this adj
     *    from the set.
     *  - update the next_node index of this adj to point to error-drop
     * both of which will mean for MAC change we will drop for this adj
     * which is not acceptable. However, when the adj changes type (from
     * complete to incomplete and vice-versa) the child DPOs, which have the
     * VLIB graph next node index, will be sending packets to the wrong graph
     * node. So from the options above, updating the next_node of the adj to
     * be drop will work, but it relies on each graph node v4/v6/mpls, rewrite/
     * arp/midchain always be valid w.r.t. a mis-match of adj type and node type
     * (i.e. a rewrite adj in the arp node). This is not enforcable. Getting it
     * wrong will lead to hard to find bugs since its a race condition. So we
     * choose the more reliable method of updating the children to use the drop,
     * then switching adj's type, then updating the children again. Did I mention
     * that this doesn't happen often...
     * So we need to distinguish between the two cases:
     *  1 - mac change
     *  2 - adj type change
     */
    if (do_walk &&
        old_next != adj_next_index &&
        ADJ_INDEX_INVALID != walk_ai)
    {
        /*
         * the adj is changing type. we need to fix all children so that they
         * stack momentarily on a drop, while the adj changes. If we don't do
         * this  the children will send packets to a VLIB graph node that does
         * not correspond to the adj's type - and it goes downhill from there.
         */
	fib_node_back_walk_ctx_t bw_ctx = {
	    .fnbw_reason = FIB_NODE_BW_REASON_FLAG_ADJ_DOWN,
            /*
             * force this walk to be synchrous. if we don't and a node in the graph
             * (a heavily shared path-list) chooses to back-ground the walk (make it
             * async) then it will pause and we will do the adj update below, before
             * all the children are updated. not good.
             */
            .fnbw_flags = FIB_NODE_BW_FLAG_FORCE_SYNC,
	};

	fib_walk_sync(FIB_NODE_TYPE_ADJ, walk_ai, &bw_ctx);
    }

    /*
     * If we are just updating the MAC string of the adj (which we also can't
     * do atomically), then we need to stop packets switching through the adj.
     * We can't do that on a per-adj basis, so it's all the packets.
     * If we are updating the type, and we walked back to the children above,
     * then this barrier serves to flush the queues/frames.
     */
    vlib_worker_thread_barrier_sync(vm);

    adj->lookup_next_index = adj_next_index;

    if (NULL != rewrite)
    {
	/*
	 * new rewrite provided.
	 * fill in the adj's rewrite string, and build the VLIB graph arc.
	 */
	vnet_rewrite_set_data_internal(&adj->rewrite_header,
				       sizeof(adj->rewrite_data),
				       rewrite,
				       vec_len(rewrite));
	vec_free(rewrite);
    }
    else
    {
	vnet_rewrite_clear_data_internal(&adj->rewrite_header,
					 sizeof(adj->rewrite_data));
    }
    adj->rewrite_header.next_index = vlib_node_add_next(vlib_get_main(),
                                                        this_node,
                                                        next_node);

    /*
     * done with the rewirte update - let the workers loose.
     */
    vlib_worker_thread_barrier_release(vm);

    if (do_walk &&
        (old_next != adj->lookup_next_index) &&
        (ADJ_INDEX_INVALID != walk_ai))
    {
        /*
         * backwalk to the children so they can stack on the now updated
         * adjacency
         */
        fib_node_back_walk_ctx_t bw_ctx = {
	    .fnbw_reason = FIB_NODE_BW_REASON_FLAG_ADJ_UPDATE,
	};

	fib_walk_sync(FIB_NODE_TYPE_ADJ, walk_ai, &bw_ctx);
    }
    /*
     * Prevent re-entrant walk of the same adj
     */
    if (do_walk)
    {
        walk_adj->ia_flags &= ~ADJ_FLAG_SYNC_WALK_ACTIVE;
    }

    adj_unlock(adj_get_index(adj));
    adj_unlock(walk_ai);
}

typedef struct adj_db_count_ctx_t_ {
    u64 count;
} adj_db_count_ctx_t;

static void
adj_db_count (BVT(clib_bihash_kv) * kvp,
	      void *arg)
{
    adj_db_count_ctx_t * ctx = arg;
    ctx->count++;
}

u32
adj_nbr_db_size (void)
{
    adj_db_count_ctx_t ctx = {
	.count = 0,
    };
    fib_protocol_t proto;
    u32 sw_if_index = 0;

    for (proto = FIB_PROTOCOL_IP4; proto <= FIB_PROTOCOL_IP6; proto++)
    {
	vec_foreach_index(sw_if_index, adj_nbr_tables[proto])
	{
	    if (NULL != adj_nbr_tables[proto][sw_if_index])
	    {
		BV(clib_bihash_foreach_key_value_pair) (
		    adj_nbr_tables[proto][sw_if_index],
		    adj_db_count,
		    &ctx);
	    }
	}
    }
    return (ctx.count);
}

/**
 * @brief Context for a walk of the adjacency neighbour DB
 */
typedef struct adj_walk_ctx_t_
{
    adj_walk_cb_t awc_cb;
    void *awc_ctx;
} adj_walk_ctx_t;

static void
adj_nbr_walk_cb (BVT(clib_bihash_kv) * kvp,
		 void *arg)
{
    adj_walk_ctx_t *ctx = arg;

    // FIXME: can't stop early...
    ctx->awc_cb(kvp->value, ctx->awc_ctx);
}

void
adj_nbr_walk (u32 sw_if_index,
	      fib_protocol_t adj_nh_proto,
	      adj_walk_cb_t cb,
	      void *ctx)
{
    if (!ADJ_NBR_ITF_OK(adj_nh_proto, sw_if_index))
	return;

    adj_walk_ctx_t awc = {
	.awc_ctx = ctx,
	.awc_cb = cb,
    };

    BV(clib_bihash_foreach_key_value_pair) (
	adj_nbr_tables[adj_nh_proto][sw_if_index],
	adj_nbr_walk_cb,
	&awc);
}

/**
 * @brief Walk adjacencies on a link with a given v4 next-hop.
 * that is visit the adjacencies with different link types.
 */
void
adj_nbr_walk_nh4 (u32 sw_if_index,
		 const ip4_address_t *addr,
		 adj_walk_cb_t cb,
		 void *ctx)
{
    if (!ADJ_NBR_ITF_OK(FIB_PROTOCOL_IP4, sw_if_index))
	return;

    ip46_address_t nh = {
	.ip4 = *addr,
    };
    vnet_link_t linkt;
    adj_index_t ai;

    FOR_EACH_VNET_LINK(linkt)
    {
        ai = adj_nbr_find (FIB_PROTOCOL_IP4, linkt, &nh, sw_if_index);

        if (INDEX_INVALID != ai)
            cb(ai, ctx);
    }
}

/**
 * @brief Walk adjacencies on a link with a given v6 next-hop.
 * that is visit the adjacencies with different link types.
 */
void
adj_nbr_walk_nh6 (u32 sw_if_index,
		 const ip6_address_t *addr,
		 adj_walk_cb_t cb,
		 void *ctx)
{
    if (!ADJ_NBR_ITF_OK(FIB_PROTOCOL_IP6, sw_if_index))
	return;

    ip46_address_t nh = {
	.ip6 = *addr,
    };
    vnet_link_t linkt;
    adj_index_t ai;

    FOR_EACH_VNET_LINK(linkt)
    {
        ai = adj_nbr_find (FIB_PROTOCOL_IP6, linkt, &nh, sw_if_index);

        if (INDEX_INVALID != ai)
            cb(ai, ctx);
    }
}

/**
 * @brief Walk adjacencies on a link with a given next-hop.
 * that is visit the adjacencies with different link types.
 */
void
adj_nbr_walk_nh (u32 sw_if_index,
		 fib_protocol_t adj_nh_proto,
		 const ip46_address_t *nh,
		 adj_walk_cb_t cb,
		 void *ctx)
{
    if (!ADJ_NBR_ITF_OK(adj_nh_proto, sw_if_index))
	return;

    vnet_link_t linkt;
    adj_index_t ai;

    FOR_EACH_VNET_LINK(linkt)
    {
        ai = adj_nbr_find (FIB_PROTOCOL_IP4, linkt, nh, sw_if_index);

        if (INDEX_INVALID != ai)
            cb(ai, ctx);
    }
}

/**
 * Flags associated with the interface state walks
 */
typedef enum adj_nbr_interface_flags_t_
{
    ADJ_NBR_INTERFACE_UP = (1 << 0),
} adj_nbr_interface_flags_t;

/**
 * Context for the state change walk of the DB
 */
typedef struct adj_nbr_interface_state_change_ctx_t_
{
    /**
     * Flags on the interface
     */
    adj_nbr_interface_flags_t flags;
} adj_nbr_interface_state_change_ctx_t;

static adj_walk_rc_t
adj_nbr_interface_state_change_one (adj_index_t ai,
                                    void *arg)
{
    /*
     * Back walk the graph to inform the forwarding entries
     * that this interface state has changed. Do this synchronously
     * since this is the walk that provides convergence
     */
    adj_nbr_interface_state_change_ctx_t *ctx = arg;
    fib_node_back_walk_ctx_t bw_ctx = {
	.fnbw_reason = ((ctx->flags & ADJ_NBR_INTERFACE_UP) ?
                        FIB_NODE_BW_REASON_FLAG_INTERFACE_UP :
                        FIB_NODE_BW_REASON_FLAG_INTERFACE_DOWN),
        /*
         * the force sync applies only as far as the first fib_entry.
         * And it's the fib_entry's we need to converge away from
         * the adjacencies on the now down link
         */
        .fnbw_flags = (!(ctx->flags & ADJ_NBR_INTERFACE_UP) ?
                       FIB_NODE_BW_FLAG_FORCE_SYNC :
                       FIB_NODE_BW_FLAG_NONE),
    };
    ip_adjacency_t *adj;

    adj = adj_get(ai);

    adj->ia_flags |= ADJ_FLAG_SYNC_WALK_ACTIVE;
    fib_walk_sync(FIB_NODE_TYPE_ADJ, ai, &bw_ctx);
    adj->ia_flags &= ~ADJ_FLAG_SYNC_WALK_ACTIVE;

    return (ADJ_WALK_RC_CONTINUE);
}

/**
 * @brief Registered function for SW interface state changes
 */
static clib_error_t *
adj_nbr_sw_interface_state_change (vnet_main_t * vnm,
                                   u32 sw_if_index,
                                   u32 flags)
{
    fib_protocol_t proto;

    /*
     * walk each adj on the interface and trigger a walk from that adj
     */
    for (proto = FIB_PROTOCOL_IP4; proto <= FIB_PROTOCOL_IP6; proto++)
    {
	adj_nbr_interface_state_change_ctx_t ctx = {
	    .flags = ((flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ?
                      ADJ_NBR_INTERFACE_UP :
                      0),
	};

	adj_nbr_walk(sw_if_index, proto,
		     adj_nbr_interface_state_change_one,
		     &ctx);
    }

    return (NULL);
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION_PRIO(
    adj_nbr_sw_interface_state_change,
    VNET_ITF_FUNC_PRIORITY_HIGH);

/**
 * @brief Invoked on each SW interface of a HW interface when the
 * HW interface state changes
 */
static walk_rc_t
adj_nbr_hw_sw_interface_state_change (vnet_main_t * vnm,
                                      u32 sw_if_index,
                                      void *arg)
{
    adj_nbr_interface_state_change_ctx_t *ctx = arg;
    fib_protocol_t proto;

    /*
     * walk each adj on the interface and trigger a walk from that adj
     */
    for (proto = FIB_PROTOCOL_IP4; proto <= FIB_PROTOCOL_IP6; proto++)
    {
	adj_nbr_walk(sw_if_index, proto,
		     adj_nbr_interface_state_change_one,
		     ctx);
    }
    return (WALK_CONTINUE);
}

/**
 * @brief Registered callback for HW interface state changes
 */
static clib_error_t *
adj_nbr_hw_interface_state_change (vnet_main_t * vnm,
                                   u32 hw_if_index,
                                   u32 flags)
{
    /*
     * walk SW interface on the HW
     */
    adj_nbr_interface_state_change_ctx_t ctx = {
        .flags = ((flags & VNET_HW_INTERFACE_FLAG_LINK_UP) ?
                  ADJ_NBR_INTERFACE_UP :
                  0),
    };

    vnet_hw_interface_walk_sw(vnm, hw_if_index,
                              adj_nbr_hw_sw_interface_state_change,
                              &ctx);

    return (NULL);
}

VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION_PRIO(
    adj_nbr_hw_interface_state_change,
    VNET_ITF_FUNC_PRIORITY_HIGH);

static adj_walk_rc_t
adj_nbr_interface_delete_one (adj_index_t ai,
			      void *arg)
{
    /*
     * Back walk the graph to inform the forwarding entries
     * that this interface has been deleted.
     */
    fib_node_back_walk_ctx_t bw_ctx = {
	.fnbw_reason = FIB_NODE_BW_REASON_FLAG_INTERFACE_DELETE,
    };
    ip_adjacency_t *adj;

    adj = adj_get(ai);

    adj->ia_flags |= ADJ_FLAG_SYNC_WALK_ACTIVE;
    fib_walk_sync(FIB_NODE_TYPE_ADJ, ai, &bw_ctx);
    adj->ia_flags &= ~ADJ_FLAG_SYNC_WALK_ACTIVE;

    return (ADJ_WALK_RC_CONTINUE);
}

/**
 * adj_nbr_interface_add_del
 *
 * Registered to receive interface Add and delete notifications
 */
static clib_error_t *
adj_nbr_interface_add_del (vnet_main_t * vnm,
			   u32 sw_if_index,
			   u32 is_add)
{
    fib_protocol_t proto;

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
	adj_nbr_walk(sw_if_index, proto,
		     adj_nbr_interface_delete_one,
		     NULL);
    }

    return (NULL);
   
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION(adj_nbr_interface_add_del);


static adj_walk_rc_t
adj_nbr_show_one (adj_index_t ai,
		  void *arg)
{
    vlib_cli_output (arg, "[@%d]  %U",
                     ai,
                     format_ip_adjacency, ai,
		     FORMAT_IP_ADJACENCY_NONE);

    return (ADJ_WALK_RC_CONTINUE);
}

static clib_error_t *
adj_nbr_show (vlib_main_t * vm,
	      unformat_input_t * input,
	      vlib_cli_command_t * cmd)
{
    adj_index_t ai = ADJ_INDEX_INVALID;
    u32 sw_if_index = ~0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
	if (unformat (input, "%d", &ai))
	    ;
	else if (unformat (input, "%U",
			   unformat_vnet_sw_interface, vnet_get_main(),
			   &sw_if_index))
	    ;
	else
	    break;
    }

    if (ADJ_INDEX_INVALID != ai)
    {
	vlib_cli_output (vm, "[@%d] %U",
                         ai,
                         format_ip_adjacency, ai,
			 FORMAT_IP_ADJACENCY_DETAIL);
    }
    else if (~0 != sw_if_index)
    {
	fib_protocol_t proto;

	for (proto = FIB_PROTOCOL_IP4; proto <= FIB_PROTOCOL_IP6; proto++)
	{
	    adj_nbr_walk(sw_if_index, proto,
			 adj_nbr_show_one,
			 vm);
	}
    }
    else
    {
	fib_protocol_t proto;

	for (proto = FIB_PROTOCOL_IP4; proto <= FIB_PROTOCOL_IP6; proto++)
	{
	    vec_foreach_index(sw_if_index, adj_nbr_tables[proto])
	    {
		adj_nbr_walk(sw_if_index, proto,
			     adj_nbr_show_one,
			     vm);
	    }
	}
    }

    return 0;
}

/*?
 * Show all neighbour adjacencies.
 * @cliexpar
 * @cliexstart{sh adj nbr}
 * [@2] ipv4 via 1.0.0.2 loop0: IP4: 00:00:22:aa:bb:cc -> 00:00:11:aa:bb:cc
 * [@3] mpls via 1.0.0.2 loop0: MPLS_UNICAST: 00:00:22:aa:bb:cc -> 00:00:11:aa:bb:cc
 * [@4] ipv4 via 1.0.0.3 loop0: IP4: 00:00:22:aa:bb:cc -> 00:00:11:aa:bb:cc
 * [@5] mpls via 1.0.0.3 loop0: MPLS_UNICAST: 00:00:22:aa:bb:cc -> 00:00:11:aa:bb:cc
 * @cliexend
 ?*/
VLIB_CLI_COMMAND (ip4_show_fib_command, static) = {
    .path = "show adj nbr",
    .short_help = "show adj nbr [<adj_index>] [interface]",
    .function = adj_nbr_show,
};

u8*
format_adj_nbr_incomplete (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    vnet_main_t * vnm = vnet_get_main();
    ip_adjacency_t * adj = adj_get(index);

    s = format (s, "arp-%U", format_vnet_link, adj->ia_link);
    s = format (s, ": via %U",
                format_ip46_address, &adj->sub_type.nbr.next_hop,
		adj_proto_to_46(adj->ia_nh_proto));
    s = format (s, " %U",
                format_vnet_sw_if_index_name,
                vnm, adj->rewrite_header.sw_if_index);

    return (s);
}

u8*
format_adj_nbr (u8* s, va_list *ap)
{
    index_t index = va_arg(*ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*ap, u32);
    ip_adjacency_t * adj = adj_get(index);

    s = format (s, "%U", format_vnet_link, adj->ia_link);
    s = format (s, " via %U ",
		format_ip46_address, &adj->sub_type.nbr.next_hop,
		adj_proto_to_46(adj->ia_nh_proto));
    s = format (s, "%U",
		format_vnet_rewrite,
		&adj->rewrite_header, sizeof (adj->rewrite_data), 0);

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

static void
adj_mem_show (void)
{
    fib_show_memory_usage("Adjacency",
			  pool_elts(adj_pool),
			  pool_len(adj_pool),
			  sizeof(ip_adjacency_t));
}

const static dpo_vft_t adj_nbr_dpo_vft = {
    .dv_lock = adj_dpo_lock,
    .dv_unlock = adj_dpo_unlock,
    .dv_format = format_adj_nbr,
    .dv_mem_show = adj_mem_show,
    .dv_get_urpf = adj_dpo_get_urpf,
};
const static dpo_vft_t adj_nbr_incompl_dpo_vft = {
    .dv_lock = adj_dpo_lock,
    .dv_unlock = adj_dpo_unlock,
    .dv_format = format_adj_nbr_incomplete,
    .dv_get_urpf = adj_dpo_get_urpf,
};

/**
 * @brief The per-protocol VLIB graph nodes that are assigned to an adjacency
 *        object.
 *
 * this means that these graph nodes are ones from which a nbr is the
 * parent object in the DPO-graph.
 */
const static char* const nbr_ip4_nodes[] =
{
    "ip4-rewrite",
    NULL,
};
const static char* const nbr_ip6_nodes[] =
{
    "ip6-rewrite",
    NULL,
};
const static char* const nbr_mpls_nodes[] =
{
    "mpls-output",
    NULL,
};
const static char* const nbr_ethernet_nodes[] =
{
    "adj-l2-rewrite",
    NULL,
};
const static char* const * const nbr_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = nbr_ip4_nodes,
    [DPO_PROTO_IP6]  = nbr_ip6_nodes,
    [DPO_PROTO_MPLS] = nbr_mpls_nodes,
    [DPO_PROTO_ETHERNET] = nbr_ethernet_nodes,
};

const static char* const nbr_incomplete_ip4_nodes[] =
{
    "ip4-arp",
    NULL,
};
const static char* const nbr_incomplete_ip6_nodes[] =
{
    "ip6-discover-neighbor",
    NULL,
};
const static char* const nbr_incomplete_mpls_nodes[] =
{
    "mpls-adj-incomplete",
    NULL,
};

const static char* const * const nbr_incomplete_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = nbr_incomplete_ip4_nodes,
    [DPO_PROTO_IP6]  = nbr_incomplete_ip6_nodes,
    [DPO_PROTO_MPLS] = nbr_incomplete_mpls_nodes,
};

void
adj_nbr_module_init (void)
{
    dpo_register(DPO_ADJACENCY,
                 &adj_nbr_dpo_vft,
                 nbr_nodes);
    dpo_register(DPO_ADJACENCY_INCOMPLETE,
                 &adj_nbr_incompl_dpo_vft,
                 nbr_incomplete_nodes);
}
