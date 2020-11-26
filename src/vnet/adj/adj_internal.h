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

#ifndef __ADJ_INTERNAL_H__
#define __ADJ_INTERNAL_H__

#include <vnet/adj/adj.h>
#include <vnet/adj/adj_mcast.h>
#include <vnet/ip/ip.h>
#include <vnet/mpls/mpls.h>
#include <vnet/adj/adj_l2.h>
#include <vnet/adj/adj_nsh.h>

/**
 * big switch to turn on Adjacency debugging
 */
#undef ADJ_DEBUG

/*
 * Debug macro
 */
#ifdef ADJ_DEBUG
#define ADJ_DBG(_adj, _fmt, _args...)		\
{						\
    clib_warning("adj:[%d:%p]:" _fmt,		\
		 _adj - adj_pool, _adj,		\
		 ##_args);			\
}
#else
#define ADJ_DBG(_e, _fmt, _args...)
#endif

static inline u32
adj_get_rewrite_node (vnet_link_t linkt)
{
    switch (linkt) {
    case VNET_LINK_IP4:
	return (ip4_rewrite_node.index);
    case VNET_LINK_IP6:
	return (ip6_rewrite_node.index);
    case VNET_LINK_MPLS:
	return (mpls_output_node.index);
    case VNET_LINK_ETHERNET:
        return (adj_l2_rewrite_node.index);
    case VNET_LINK_NSH:
        return (adj_nsh_rewrite_node.index);
    case VNET_LINK_ARP:
	break;
    }
    ASSERT(0);
    return (0);
}

static inline vnet_link_t
adj_fib_proto_2_nd (fib_protocol_t fp)
{
    switch (fp)
    {
    case FIB_PROTOCOL_IP4:
	return (VNET_LINK_ARP);
    case FIB_PROTOCOL_IP6:
	return (VNET_LINK_IP6);
    case FIB_PROTOCOL_MPLS:
	return (VNET_LINK_MPLS);
    }
    return (0);
}

static inline ip46_type_t
adj_proto_to_46 (fib_protocol_t proto)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	return (IP46_TYPE_IP4);
    case FIB_PROTOCOL_IP6:
	return (IP46_TYPE_IP6);
    default:
	return (IP46_TYPE_IP4);
    }
    return (IP46_TYPE_IP4);
}

/**
 * @brief
 * Get a pointer to an adjacency object from its index
 */
static inline adj_index_t
adj_get_index (const ip_adjacency_t *adj)
{
    return (adj - adj_pool);
}

extern void adj_nbr_update_rewrite_internal(ip_adjacency_t *adj,
                                            ip_lookup_next_t adj_next_index,
                                            u32 complete_next_index,
                                            u32 next_index,
                                            u8 *rewrite);
extern void adj_midchain_setup(adj_index_t adj_index,
                               adj_midchain_fixup_t fixup,
                               const void *data,
                               adj_flags_t flags);

extern ip_adjacency_t * adj_alloc(fib_protocol_t proto);

extern void adj_nbr_remove(adj_index_t ai,
                           fib_protocol_t nh_proto,
			   vnet_link_t link_type,
			   const ip46_address_t *nh_addr,
			   u32 sw_if_index);
extern void adj_glean_remove(ip_adjacency_t *adj);
extern void adj_mcast_remove(fib_protocol_t proto,
			     u32 sw_if_index);
extern void adj_midchain_teardown(ip_adjacency_t *adj);

extern u32 adj_dpo_get_urpf(const dpo_id_t *dpo);

/*
 * Adj BFD
 */
extern int adj_bfd_is_up (adj_index_t ai);

/*
 * Adj delegates
 */ 
extern void adj_delegate_adj_deleted(ip_adjacency_t *adj);
extern void adj_delegate_adj_created(ip_adjacency_t *adj);
extern void adj_delegate_adj_modified(ip_adjacency_t *adj);
extern u8* adj_delegate_format(u8* s, ip_adjacency_t *adj);

#endif
