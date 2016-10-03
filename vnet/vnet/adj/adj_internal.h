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
#include <vnet/ip/ip.h>
#include <vnet/mpls/mpls.h>
#include <vnet/adj/adj_l2.h>


/**
 * big switch to turn on Adjacency debugging
 */
#undef ADJ_DEBUG

/*
 * Debug macro
 */
#ifdef ADJ_DEBUG
#define ADJ_DBG(_adj, _fmt, _args...)			\
{							\
    clib_warning("adj:[%d:%p]:" _fmt,			\
		 _adj->heap_handle, _adj,		\
		 ##_args);				\
}
#else
#define ADJ_DBG(_e, _fmt, _args...)
#endif

static inline vlib_node_registration_t*
adj_get_rewrite_node (fib_link_t linkt)
{
    switch (linkt) {
    case FIB_LINK_IP4:
	return (&ip4_rewrite_node);
    case FIB_LINK_IP6:
	return (&ip6_rewrite_node);
    case FIB_LINK_MPLS:
	return (&mpls_output_node);
    case FIB_LINK_ETHERNET:
	return (&adj_l2_rewrite_node);
    }
    ASSERT(0);
    return (NULL);
}

static inline vnet_l3_packet_type_t
adj_fib_link_2_vnet (fib_link_t linkt)
{
    switch (linkt)
    {
    case FIB_LINK_IP4:
	return (VNET_L3_PACKET_TYPE_IP4);
    case FIB_LINK_IP6:
	return (VNET_L3_PACKET_TYPE_IP6);
    case FIB_LINK_MPLS:
	return (VNET_L3_PACKET_TYPE_MPLS_UNICAST);
    case FIB_LINK_ETHERNET:
	break;
    }
    return (0);
}

static inline vnet_l3_packet_type_t
adj_fib_proto_2_nd (fib_protocol_t fp)
{
    switch (fp)
    {
    case FIB_PROTOCOL_IP4:
	return (VNET_L3_PACKET_TYPE_ARP);
    case FIB_PROTOCOL_IP6:
	return (VNET_L3_PACKET_TYPE_IP6);
    case FIB_PROTOCOL_MPLS:
	return (VNET_L3_PACKET_TYPE_MPLS_UNICAST);
    }
    return (0);
}

extern ip_adjacency_t * adj_alloc(fib_protocol_t proto);

extern void adj_nbr_remove(fib_protocol_t nh_proto,
			   fib_link_t link_type,
			   const ip46_address_t *nh_addr,
			   u32 sw_if_index);
extern void adj_glean_remove(fib_protocol_t proto,
			     u32 sw_if_index);

#endif
