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
/**
 * @brief
 * Neighbour Adjacency sub-type. These adjs represent an L3 peer on a
 * connected link. 
 */

#ifndef __ADJ_NBR_H__
#define __ADJ_NBR_H__

#include <vnet/vnet.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_node.h>
#include <vnet/dpo/dpo.h>

/**
 * @brief
 *  Add (and lock) a new or lock an existing neighbour adjacency
 *
 * @param nh_proto
 *  The protocol for the next-hop address (v4 or v6)
 *
 * @param link_type
 *  A description of the protocol of the packets that will forward
 *  through this adj. On an ethernet interface this is the MAC header's
 *  ether-type
 *
 * @param nh_addr
 *  The address of the next-hop/peer to send the packet to
 *
 * @param sw_if_index
 *  The interface on which the peer resides
 */
extern adj_index_t adj_nbr_add_or_lock(fib_protocol_t nh_proto,
				       vnet_link_t link_type,
				       const ip46_address_t *nh_addr,
				       u32 sw_if_index);

/**
 * @brief
 *  Add (and lock) a new or lock an existing neighbour adjacency
 *
 * @param nh_proto
 *  The protocol for the next-hop address (v4 or v6)
 *
 * @param link_type
 *  A description of the protocol of the packets that will forward
 *  through this adj. On an ethernet interface this is the MAC header's
 *  ether-type
 *
 * @param nh_addr
 *  The address of the next-hop/peer to send the packet to
 *
 * @param sw_if_index
 *  The interface on which the peer resides
 *
 * @param rewrite
 *  The rewrite to prepend to packets
 */
extern adj_index_t adj_nbr_add_or_lock_w_rewrite(fib_protocol_t nh_proto,
						 vnet_link_t link_type,
						 const ip46_address_t *nh_addr,
						 u32 sw_if_index,
						 u8 *rewrite);

/**
 * Set the MTU on an adjacency
 *
 */
extern void adj_nbr_set_mtu(adj_index_t ai, u16 mtu);

/**
 * @brief When adding a rewrite to an adjacency these are flags that
 * apply to that rewrite
 */
typedef enum adj_nbr_rewrite_flag_t_
{
    ADJ_NBR_REWRITE_FLAG_NONE,

    /**
     * An indication that the rewrite is incomplete, i.e. that it describes the
     * ARP/ND rewrite when probing.
     */
    ADJ_NBR_REWRITE_FLAG_INCOMPLETE = ADJ_NBR_REWRITE_FLAG_NONE,

    /**
     * An indication that the rewrite is complete, i.e. that it fully describes
     * the link-layer addressing for the destintation.
     * The opposite of this is an incomplete rewrite that describes the ARP/ND
     * rewrite when probing.
     */
    ADJ_NBR_REWRITE_FLAG_COMPLETE = (1 << 0),
} adj_nbr_rewrite_flag_t;

/**
 * @brief
 *  Update the rewrite string for an existing adjacecny.
 *
 * @param
 *  The index of the adj to update
 *
 * @param
 *  The new rewrite
 */
extern void adj_nbr_update_rewrite(adj_index_t adj_index,
				   adj_nbr_rewrite_flag_t flags,
				   u8 *rewrite);

/**
 * @brief
 * Format aa incomplete neigbour (ARP) adjacency
 */
extern u8* format_adj_nbr_incomplete(u8* s, va_list *ap);

/**
 * @brief
 * Format a neigbour (REWRITE) adjacency
 */
extern u8* format_adj_nbr(u8* s, va_list *ap);

/**
 * @brief Walk the neighbour Adjacencies on a given interface
 */
extern void adj_nbr_walk (u32 sw_if_index,
			  fib_protocol_t adj_nh_proto,
			  adj_walk_cb_t cb,
			  void *ctx);
/**
 * @brief Walk the neighbour Adjacencies on a given interface with a given next-hop
 */
void
adj_nbr_walk_nh (u32 sw_if_index,
		 fib_protocol_t adj_nh_proto,
		 const ip46_address_t *nh,
		 adj_walk_cb_t cb,
		 void *ctx);

/**
 * @brief Walk adjacencies on a link with a given v4 next-hop.
 * that is visit the adjacencies with different link types.
 */
void
adj_nbr_walk_nh4 (u32 sw_if_index,
		  const ip4_address_t *addr,
		  adj_walk_cb_t cb,
		  void *ctx);

/**
 * @brief Walk adjacencies on a link with a given v6 next-hop.
 * that is visit the adjacencies with different link types.
 */
void
adj_nbr_walk_nh6 (u32 sw_if_index,
		  const ip6_address_t *addr,
		  adj_walk_cb_t cb,
		  void *ctx);

/**
 * @brief Lookup neighbor adjancency.
 */
adj_index_t
adj_nbr_find (fib_protocol_t nh_proto,
	      vnet_link_t link_type,
	      const ip46_address_t *nh_addr,
	      u32 sw_if_index);
/**
 * @brief
 *  Module initialisation
 */
extern void adj_nbr_module_init(void);

/**
 * @brief
 *  Return the size of the adjacency database. for testing purposes
 */
extern u32 adj_nbr_db_size(void);

#endif
