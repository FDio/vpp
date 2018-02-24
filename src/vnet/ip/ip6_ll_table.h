/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __IP6_LL_TABLE_H__
#define __IP6_LL_TABLE_H__

#include <vnet/ip/ip.h>

#include <vnet/ip/ip6_ll_types.h>

/**
 * @brief
 *   A protocol Independent IP multicast FIB table
 */
typedef struct ip6_ll_table_t_
{
  /**
   * A vector, indexed by sw_if_index, of unicast IPv6 FIBs
   */
  u32 *ilt_fibs;

  /**
   * Total route counters
   */
  u32 ilt_total_route_counts;

} ip6_ll_table_t;

/**
 * @brief
 *  Perfom a longest prefix match in the non-forwarding table
 *
 * @param prefix
 *  The prefix to lookup
 *
 * @return
 *  The index of the fib_entry_t for the best match, which may be the default route
 */
extern fib_node_index_t ip6_ll_table_lookup (const ip6_ll_prefix_t * prefix);

/**
 * @brief
 *  Perfom an exact match in the non-forwarding table
 *
 * @param prefix
 *  The prefix to lookup
 *
 * @return
 *  The index of the fib_entry_t for the exact match, or INVALID
 *  is there is no match.
 */
extern fib_node_index_t ip6_ll_table_lookup_exact_match
  (const ip6_ll_prefix_t * prefix);

/**
 * @brief
 * Update an entry in the table. The falgs determine if the entry is
 * LOCAL, in which case it's a receive, or not, in which case the entry
 * will link to an adjacency.
 *
 * @param prefix
 *  The prefix for the entry to add
 *
 * @return
 *  the index of the fib_entry_t that is created (or existed already).
 */
extern fib_node_index_t ip6_ll_table_entry_update
  (const ip6_ll_prefix_t * prefix, fib_route_path_flags_t flags);

/**
 * @brief
 *  Delete a IP6 link-local entry.
 *
 * @param prefix
 *  The prefix for the entry to remove
 */
extern void ip6_ll_table_entry_delete (const ip6_ll_prefix_t * prefix);

/**
 * @brief For use in the data plane. Get the underlying ip6 FIB
 */
extern u32 ip6_ll_fib_get (u32 sw_if_index);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
