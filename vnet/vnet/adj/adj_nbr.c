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
		fib_link_t link_type,
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
	memset(adj_nbr_tables[nh_proto][sw_if_index],
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
adj_nbr_remove (fib_protocol_t nh_proto,
		fib_link_t link_type,
		const ip46_address_t *nh_addr,
		u32 sw_if_index)
{
    BVT(clib_bihash_kv) kv;

    if (!ADJ_NBR_ITF_OK(nh_proto, sw_if_index))
	return;

    ADJ_NBR_SET_KEY(kv, link_type, nh_addr);

    BV(clib_bihash_add_del) (adj_nbr_tables[nh_proto][sw_if_index], &kv, 0);
}

static adj_index_t
adj_nbr_find (fib_protocol_t nh_proto,
	      fib_link_t link_type,
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

static inline vlib_node_registration_t*
adj_get_nd_node (fib_protocol_t proto)
{
    switch (proto) {
    case FIB_PROTOCOL_IP4:
	return (&ip4_arp_node);
    case FIB_PROTOCOL_IP6:
	return (&ip6_discover_neighbor_node);
    case FIB_PROTOCOL_MPLS:
	break;
    }
    ASSERT(0);
    return (NULL);
}

static void
adj_ip4_nbr_probe (ip_adjacency_t *adj)
{
    vnet_main_t * vnm = vnet_get_main();
    ip4_main_t * im = &ip4_main;
    ip_interface_address_t * ia;
    ethernet_arp_header_t * h;
    vnet_hw_interface_t * hi;
    vnet_sw_interface_t * si;
    ip4_address_t * src;
    vlib_buffer_t * b;
    vlib_main_t * vm;
    u32 bi = 0;

    vm = vlib_get_main();

    si = vnet_get_sw_interface (vnm,
				adj->rewrite_header.sw_if_index);

    if (!(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
    {
        return;
    }

    src =
      ip4_interface_address_matching_destination(im,
						 &adj->sub_type.nbr.next_hop.ip4,
						 adj->rewrite_header.sw_if_index,
						 &ia);
    if (! src)
    {
        return;
    }

    h = vlib_packet_template_get_packet (vm, &im->ip4_arp_request_packet_template, &bi);

    hi = vnet_get_sup_hw_interface (vnm, adj->rewrite_header.sw_if_index);

    clib_memcpy (h->ip4_over_ethernet[0].ethernet,
		 hi->hw_address,
		 sizeof (h->ip4_over_ethernet[0].ethernet));

    h->ip4_over_ethernet[0].ip4 = src[0];
    h->ip4_over_ethernet[1].ip4 = adj->sub_type.nbr.next_hop.ip4;

    b = vlib_get_buffer (vm, bi);
    vnet_buffer (b)->sw_if_index[VLIB_RX] =
      vnet_buffer (b)->sw_if_index[VLIB_TX] =
          adj->rewrite_header.sw_if_index;

    /* Add encapsulation string for software interface (e.g. ethernet header). */
    vnet_rewrite_one_header (adj[0], h, sizeof (ethernet_header_t));
    vlib_buffer_advance (b, -adj->rewrite_header.data_bytes);

    {
        vlib_frame_t * f = vlib_get_frame_to_node (vm, hi->output_node_index);
	u32 * to_next = vlib_frame_vector_args (f);
	to_next[0] = bi;
	f->n_vectors = 1;
	vlib_put_frame_to_node (vm, hi->output_node_index, f);
    }
}

static void
adj_ip6_nbr_probe (ip_adjacency_t *adj)
{
    icmp6_neighbor_solicitation_header_t * h;
    vnet_main_t * vnm = vnet_get_main();
    ip6_main_t * im = &ip6_main;
    ip_interface_address_t * ia;
    ip6_address_t * dst, *src;
    vnet_hw_interface_t * hi;
    vnet_sw_interface_t * si;
    vlib_buffer_t * b;
    int bogus_length;
    vlib_main_t * vm;
    u32 bi = 0;

    vm = vlib_get_main();

    si = vnet_get_sw_interface(vnm, adj->rewrite_header.sw_if_index);
    dst = &adj->sub_type.nbr.next_hop.ip6;

    if (!(si->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP))
    {
        return;
    }
    src = ip6_interface_address_matching_destination(im, dst,
						     adj->rewrite_header.sw_if_index,
						     &ia);
    if (! src)
    {
       return;
    }

    h = vlib_packet_template_get_packet(vm,
					&im->discover_neighbor_packet_template,
					&bi);

    hi = vnet_get_sup_hw_interface(vnm, adj->rewrite_header.sw_if_index);

    h->ip.dst_address.as_u8[13] = dst->as_u8[13];
    h->ip.dst_address.as_u8[14] = dst->as_u8[14];
    h->ip.dst_address.as_u8[15] = dst->as_u8[15];
    h->ip.src_address = src[0];
    h->neighbor.target_address = dst[0];

    clib_memcpy (h->link_layer_option.ethernet_address,
		 hi->hw_address,
		 vec_len(hi->hw_address));

    h->neighbor.icmp.checksum = 
	ip6_tcp_udp_icmp_compute_checksum(vm, 0, &h->ip, &bogus_length);
    ASSERT(bogus_length == 0);

    b = vlib_get_buffer (vm, bi);
    vnet_buffer (b)->sw_if_index[VLIB_RX] =
	vnet_buffer (b)->sw_if_index[VLIB_TX] =
          adj->rewrite_header.sw_if_index;

    /* Add encapsulation string for software interface (e.g. ethernet header). */
    vnet_rewrite_one_header(adj[0], h, sizeof (ethernet_header_t));
    vlib_buffer_advance(b, -adj->rewrite_header.data_bytes);

    {
	vlib_frame_t * f = vlib_get_frame_to_node(vm, hi->output_node_index);
	u32 * to_next = vlib_frame_vector_args(f);
	to_next[0] = bi;
	f->n_vectors = 1;
	vlib_put_frame_to_node(vm, hi->output_node_index, f);
    }
}

static ip_adjacency_t*
adj_nbr_alloc (fib_protocol_t nh_proto,
	       fib_link_t link_type,
	       const ip46_address_t *nh_addr,
	       u32 sw_if_index)
{
    ip_adjacency_t *adj;

    adj = adj_alloc(nh_proto);

    adj_nbr_insert(nh_proto, link_type, nh_addr,
		   sw_if_index,
		   adj->heap_handle);

    /*
     * since we just added the ADJ we have no rewrite string for it,
     * so its for ARP
     */
    adj->lookup_next_index = IP_LOOKUP_NEXT_ARP;
    adj->sub_type.nbr.next_hop = *nh_addr;
    adj->ia_link = link_type;
    adj->ia_nh_proto = nh_proto;
    memset(&adj->sub_type.midchain.next_dpo, 0,
           sizeof(adj->sub_type.midchain.next_dpo));

    return (adj);
}

/*
 * adj_add_for_nbr
 *
 * Add an adjacency for the neighbour requested.
 *
 * The key for an adj is:
 *   - the Next-hops protocol (i.e. v4 or v6)
 *   - the address of the next-hop
 *   - the interface the next-hop is reachable through
 *   - fib_index; this is broken. i will fix it.
 *     the adj lookup currently occurs in the FIB.
 */
adj_index_t
adj_nbr_add_or_lock (fib_protocol_t nh_proto,
		     fib_link_t link_type,
		     const ip46_address_t *nh_addr,
		     u32 sw_if_index)
{
    adj_index_t adj_index;
    ip_adjacency_t *adj;

    adj_index = adj_nbr_find(nh_proto, link_type, nh_addr, sw_if_index);

    if (ADJ_INDEX_INVALID == adj_index)
    {
	adj = adj_nbr_alloc(nh_proto, link_type, nh_addr, sw_if_index);

	/*
	 * If there is no next-hop, this is the 'auto-adj' used on p2p
	 * links instead of a glean.
	 */
	if (ip46_address_is_zero(nh_addr))
	{
	    adj->lookup_next_index = IP_LOOKUP_NEXT_REWRITE;

	    vnet_rewrite_for_sw_interface(vnet_get_main(),
					  adj_fib_link_2_vnet(link_type),
					  sw_if_index,
					  adj_get_rewrite_node(link_type)->index,
					  VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST,
					  &adj->rewrite_header,
					  sizeof (adj->rewrite_data));
	}
	else
	{
	    vnet_rewrite_for_sw_interface(vnet_get_main(),
					  adj_fib_proto_2_nd(nh_proto),
					  sw_if_index,
					  adj_get_nd_node(nh_proto)->index,
					  VNET_REWRITE_FOR_SW_INTERFACE_ADDRESS_BROADCAST,
					  &adj->rewrite_header,
					  sizeof (adj->rewrite_data));

	    switch (nh_proto)
	    {
	    case FIB_PROTOCOL_IP4:
		adj_ip4_nbr_probe(adj);
		break;
	    case FIB_PROTOCOL_IP6:
		adj_ip6_nbr_probe(adj);
		break;
	    case FIB_PROTOCOL_MPLS:
		break;
	    }
	}
    }
    else
    {
	adj = adj_get(adj_index);
    }

    adj_lock(adj->heap_handle);

    return (adj->heap_handle);
}

adj_index_t
adj_nbr_add_or_lock_w_rewrite (fib_protocol_t nh_proto,
			       fib_link_t link_type,
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

    adj_lock(adj->heap_handle);
    adj_nbr_update_rewrite(adj->heap_handle, rewrite);

    return (adj->heap_handle);
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
			u8 *rewrite)
{
    ip_adjacency_t *adj;

    ASSERT(ADJ_INDEX_INVALID != adj_index);

    adj = adj_get(adj_index);

    if (NULL != rewrite)
    {
	/*
	 * new rewrite provided.
	 * use a dummy rewrite header to get the interface to print into.
	 */
	ip_adjacency_t dummy;

	vnet_rewrite_for_sw_interface(vnet_get_main(),
				      adj_fib_link_2_vnet(adj->ia_link),
				      adj->rewrite_header.sw_if_index,
				      adj_get_rewrite_node(adj->ia_link)->index,
				      rewrite,
				      &dummy.rewrite_header,
				      sizeof (dummy.rewrite_data));

	if (IP_LOOKUP_NEXT_REWRITE == adj->lookup_next_index)
	{
	    /*
	     * this is an update of an existing rewrite.
	     * we can't just paste in the new rewrite as that is not atomic.
	     * So we briefly swap the ADJ to ARP type, paste, then swap back.
	     */
	    adj->lookup_next_index = IP_LOOKUP_NEXT_ARP;
	    CLIB_MEMORY_BARRIER();
	}
	/*
	 * else
	 *   this is the first time the rewrite is added.
	 *   paste it on then swap the next type.
	 */
	clib_memcpy(&adj->rewrite_header,
		    &dummy.rewrite_header,
		    VLIB_BUFFER_PRE_DATA_SIZE);

	adj->lookup_next_index = IP_LOOKUP_NEXT_REWRITE;
    }
    else
    {
	/*
	 * clear the rewrite.
	 */
	adj->lookup_next_index = IP_LOOKUP_NEXT_ARP;
	CLIB_MEMORY_BARRIER();

	adj->rewrite_header.data_bytes = 0;
    }

    /*
     * time for walkies fido.
     * The link type MPLS Adj never has children. So if it is this adj
     * that is updated, we need to walk from its IP sibling.
     */
    if (FIB_LINK_MPLS == adj->ia_link)
    {
        adj_index = adj_nbr_find(adj->ia_nh_proto,
				 fib_proto_to_link(adj->ia_nh_proto),
				 &adj->sub_type.nbr.next_hop,
				 adj->rewrite_header.sw_if_index);

        ASSERT(ADJ_INDEX_INVALID != adj_index);
    }

    fib_node_back_walk_ctx_t bw_ctx = {
	.fnbw_reason = FIB_NODE_BW_REASON_FLAG_ADJ_UPDATE,
	/*
	 * This walk only needs to go back one level, but there is no control here.
         * the first receiving fib_entry_t will quash the walk
	 */
    };

    fib_walk_sync(FIB_NODE_TYPE_ADJ, adj_index, &bw_ctx);
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
 * Context for the state change walk of the DB
 */
typedef struct adj_nbr_interface_state_change_ctx_t_
{
    /**
     * Flags passed from the vnet notifiy function
     */
    int flags;
} adj_nbr_interface_state_change_ctx_t;

static void
adj_nbr_interface_state_change_one (BVT(clib_bihash_kv) * kvp,
				    void *arg)
{
    /*
     * Back walk the graph to inform the forwarding entries
     * that this interface state has changed.
     */
    adj_nbr_interface_state_change_ctx_t *ctx = arg;

    fib_node_back_walk_ctx_t bw_ctx = {
	.fnbw_reason = (ctx->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP ?
			FIB_NODE_BW_REASON_FLAG_INTERFACE_UP :
			FIB_NODE_BW_REASON_FLAG_INTERFACE_DOWN),
    };

    fib_walk_sync(FIB_NODE_TYPE_ADJ, kvp->value, &bw_ctx);
}

static clib_error_t *
adj_nbr_interface_state_change (vnet_main_t * vnm,
				u32 sw_if_index,
				u32 flags)
{
    fib_protocol_t proto;

    /*
     * walk each adj on the interface and trigger a walk from that adj
     */
    for (proto = FIB_PROTOCOL_IP4; proto <= FIB_PROTOCOL_IP6; proto++)
    {
	if (!ADJ_NBR_ITF_OK(proto, sw_if_index))
	    continue;

	adj_nbr_interface_state_change_ctx_t ctx = {
	    .flags = flags,
	};

	BV(clib_bihash_foreach_key_value_pair) (
	    adj_nbr_tables[proto][sw_if_index],
	    adj_nbr_interface_state_change_one,
	    &ctx);
    }

    return (NULL);
}

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION(adj_nbr_interface_state_change);

static void
adj_nbr_interface_delete_one (BVT(clib_bihash_kv) * kvp,
			      void *arg)
{
    /*
     * Back walk the graph to inform the forwarding entries
     * that this interface has been deleted.
     */
    fib_node_back_walk_ctx_t bw_ctx = {
	.fnbw_reason = FIB_NODE_BW_REASON_FLAG_INTERFACE_DELETE,
    };

    fib_walk_sync(FIB_NODE_TYPE_ADJ, kvp->value, &bw_ctx);
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
	if (!ADJ_NBR_ITF_OK(proto, sw_if_index))
	    continue;

	BV(clib_bihash_foreach_key_value_pair) (
	    adj_nbr_tables[proto][sw_if_index],
	    adj_nbr_interface_delete_one,
	    NULL);
    }

    return (NULL);
   
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION(adj_nbr_interface_add_del);


static void
adj_nbr_show_one (BVT(clib_bihash_kv) * kvp,
		  void *arg)
{
    vlib_cli_output (arg, "[@%d]  %U",
                     kvp->value,
                     format_ip_adjacency,
                     vnet_get_main(), kvp->value,
		     FORMAT_IP_ADJACENCY_NONE);
}

static clib_error_t *
adj_nbr_show (vlib_main_t * vm,
	      unformat_input_t * input,
	      vlib_cli_command_t * cmd)
{
    adj_index_t ai = ADJ_INDEX_INVALID;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
	if (unformat (input, "%d", &ai))
	    ;
	else
	    break;
    }

    if (ADJ_INDEX_INVALID != ai)
    {
	vlib_cli_output (vm, "[@%d] %U",
                         ai,

                         format_ip_adjacency,
			 vnet_get_main(), ai,
			 FORMAT_IP_ADJACENCY_DETAIL);
    }
    else
    {
	fib_protocol_t proto;

	for (proto = FIB_PROTOCOL_IP4; proto <= FIB_PROTOCOL_IP6; proto++)
	{
	    u32 sw_if_index;

	    vec_foreach_index(sw_if_index, adj_nbr_tables[proto])
	    {
		if (!ADJ_NBR_ITF_OK(proto, sw_if_index))
		    continue;

		BV(clib_bihash_foreach_key_value_pair) (
		    adj_nbr_tables[proto][sw_if_index],
		    adj_nbr_show_one,
		    vm);
	    }
	}
    }

    return 0;
}

VLIB_CLI_COMMAND (ip4_show_fib_command, static) = {
    .path = "show adj nbr",
    .short_help = "show adj nbr [<adj_index>] [sw_if_index <index>]",
    .function = adj_nbr_show,
};

u8*
format_adj_nbr_incomplete (u8* s, va_list *ap)
{
    index_t index = va_arg(ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(ap, u32);
    vnet_main_t * vnm = vnet_get_main();
    ip_adjacency_t * adj = adj_get(index);

    s = format (s, "arp-%U", format_fib_link, adj->ia_link);
    s = format (s, ": via %U",
                format_ip46_address, &adj->sub_type.nbr.next_hop);
    s = format (s, " %U",
                format_vnet_sw_interface_name,
                vnm,
                vnet_get_sw_interface(vnm,
                                      adj->rewrite_header.sw_if_index));

    return (s);
}

u8*
format_adj_nbr (u8* s, va_list *ap)
{
    index_t index = va_arg(ap, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(ap, u32);
    vnet_main_t * vnm = vnet_get_main();
    ip_adjacency_t * adj = adj_get(index);

    s = format (s, "%U", format_fib_link, adj->ia_link);
    s = format (s, " via %U ",
		format_ip46_address, &adj->sub_type.nbr.next_hop);
    s = format (s, "%U",
		format_vnet_rewrite,
		vnm->vlib_main, &adj->rewrite_header, sizeof (adj->rewrite_data), 0);

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

const static dpo_vft_t adj_nbr_dpo_vft = {
    .dv_lock = adj_dpo_lock,
    .dv_unlock = adj_dpo_unlock,
    .dv_format = format_adj_nbr,
};
const static dpo_vft_t adj_nbr_incompl_dpo_vft = {
    .dv_lock = adj_dpo_lock,
    .dv_unlock = adj_dpo_unlock,
    .dv_format = format_adj_nbr_incomplete,
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
    "ip4-rewrite-transit",
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
const static char* const * const nbr_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = nbr_ip4_nodes,
    [DPO_PROTO_IP6]  = nbr_ip6_nodes,
    [DPO_PROTO_MPLS] = nbr_mpls_nodes,
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
