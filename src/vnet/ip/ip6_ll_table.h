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
#include <vnet/adj/adj.h>
#include <vnet/dpo/replicate_dpo.h>

#include <vnet/ip/ip6_ll_types.h>

/**
 * Keep a lock per-source and a total
 */
#define IP6_LL_TABLE_N_LOCKS (IP6_LL_N_SOURCES+1)
#define IP6_LL_TABLE_TOTAL_LOCKS IP6_LL_N_SOURCES

/**
 * @brief
 *   A protocol Independent IP multicast FIB table
 */
typedef struct ip6_ll_table_t_
{
    /**
     */
  u32 *ilt_fibs;

    /**
     * Total route counters
     */
  u32 ilt_total_route_counts;

} ip6_ll_table_t;

/**
 * @brief
 *  Format the description/name of the table
 */
extern u8 *format_ip6_ll_table_name (u8 * s, va_list * ap);

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
extern fib_node_index_t ip6_ll_table_lookup_exact_match (const ip6_ll_prefix_t
							 * prefix);

/**
 * @brief
 *  Add n paths to an entry (aka route) in the FIB. If the entry does not
 *  exist, it will be created.
 * See the documentation for fib_route_path_t for more descirptions of
 * the path parameters.
 *
 * @param prefix
 *  The prefix for the entry to add
 *
 * @param source
 *  The ID of the client/source adding the entry.
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
 * @brief
 * Return the number of entries in the FIB added by a given source.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @return number of sourced entries.
 */
extern u32 ip6_ll_table_get_num_entries (void);

/**
 * @brief Call back function when walking entries in a FIB table
 */
typedef int (*ip6_ll_table_walk_fn_t) (fib_node_index_t fei, void *ctx);

/**
 * @brief Walk all entries in a FIB table
 * N.B: This is NOT safe to deletes. If you need to delete, walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void ip6_ll_table_walk (ip6_ll_table_walk_fn_t fn, void *ctx);
/**
 * @brief format (display) the memory usage for ip6_lls
 */
extern u8 *format_ip6_ll_table_memory (u8 * s, va_list * args);

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
