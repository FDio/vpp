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
 * An adjacency is a representation of an attached L3 peer.
 *
 * Adjacency Sub-types:
 *   - neighbour: a representation of an attached L3 peer.
 *                Key:{addr,interface,link/ether-type}
 *           SHARED
 *   - glean: used to drive ARP/ND for packets destined to a local sub-net.
 *            'glean' mean use the packet's destination address as the target
 *            address in the ARP packet.
 *          UNSHARED. Only one per-interface.
 *   - midchain: a nighbour adj on a virtual/tunnel interface.
 *   - rewrite: an adj with no key, but with a rewrite string.
 *
 * The API to create and update the adjacency is very sub-type specific. This
 * is intentional as it encourages the user to carefully consider which adjacency
 * sub-type they are really using, and hence assign it data in the appropriate
 * sub-type space in the union of sub-types. This prevents the adj becoming a
 * disorganised dumping group for 'my features needs a u16 somewhere' data. It
 * is important to enforce this approach as space in the adjacency is a premium,
 * as we need it to fit in 1 cache line.
 *
 * the API is also based around an index to an ajdacency not a raw pointer. This
 * is so the user doesn't suffer the same limp inducing firearm injuries that
 * the author suffered as the adjacenices can realloc.
 */

#ifndef __ADJ_H__
#define __ADJ_H__

#include <vnet/ip/lookup.h>
#include <vnet/adj/adj_types.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/adj/adj_rewrite.h>
#include <vnet/adj/adj_glean.h>

/**
 * @brief
 *   Take a reference counting lock on the adjacency
 */
extern void adj_lock(adj_index_t adj_index);
/**
 * @brief
 *   Release a reference counting lock on the adjacency
 */
extern void adj_unlock(adj_index_t adj_index);

/**
 * @brief
 *  Add a child dependent to an adjacency. The child will
 *  thus be informed via its registerd back-walk function
 *  when the adjacency state changes.
 */
extern u32 adj_child_add(adj_index_t adj_index,
			 fib_node_type_t type,
			 fib_node_index_t child_index);
/**
 * @brief
 *  Remove a child dependent
 */
extern void adj_child_remove(adj_index_t adj_index,
			     u32 sibling_index);

/**
 * @brief
 * The global adjacnecy pool. Exposed for fast/inline data-plane access
 */
extern ip_adjacency_t *adj_pool;

/**
 * @brief 
 * Adjacency packet counters
 */
extern vlib_combined_counter_main_t adjacency_counters;

/**
 * @brief
 * Get a pointer to an adjacency object from its index
 */
static inline ip_adjacency_t *
adj_get (adj_index_t adj_index)
{
    return (vec_elt_at_index(adj_pool, adj_index));
}

#endif
