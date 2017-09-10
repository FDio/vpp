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
 * @brief The IPv4 FIB
 *
 * FIBs are composed of two prefix data-bases (akak tables). The non-forwarding
 * table contains all the routes that the control plane has programmed, the
 * forwarding table contains the sub-set of those routes that can be used to
 * forward packets.
 * In the IPv4 FIB the non-forwarding table is an array of hash tables indexed
 * by mask length, the forwarding table is an mtrie
 *
 * This IPv4 FIB is used by the protocol independent FIB. So directly using
 * this APIs in client code is not encouraged. However, this IPv4 FIB can be
 * used if all the client wants is an IPv4 prefix data-base
 */

#ifndef __IP4_FIB_H__
#define __IP4_FIB_H__

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip4_mtrie.h>

typedef struct ip4_fib_t_
{
  /**
   * Mtrie for fast lookups. Hash is used to maintain overlapping prefixes.
   * First member so it's in the first cacheline.
   */
  ip4_fib_mtrie_t mtrie;

  /* Hash table for each prefix length mapping. */
  uword *fib_entry_by_dst_address[33];

  /* Table ID (hash key) for this FIB. */
  u32 table_id;

  /* Index into FIB vector. */
  u32 index;

  /* N-tuple classifier indices */
  u32 fwd_classify_table_index;
  u32 rev_classify_table_index;

} ip4_fib_t;

extern fib_node_index_t ip4_fib_table_lookup(const ip4_fib_t *fib,
					     const ip4_address_t *addr,
					     u32 len);
extern fib_node_index_t ip4_fib_table_lookup_exact_match(const ip4_fib_t *fib,
							 const ip4_address_t *addr,
							 u32 len);

extern void ip4_fib_table_entry_remove(ip4_fib_t *fib,
				       const ip4_address_t *addr,
				       u32 len);

extern void ip4_fib_table_entry_insert(ip4_fib_t *fib,
				       const ip4_address_t *addr,
				       u32 len,
				       fib_node_index_t fib_entry_index);
extern void ip4_fib_table_destroy(u32 fib_index);

extern void ip4_fib_table_fwding_dpo_update(ip4_fib_t *fib,
					    const ip4_address_t *addr,
					    u32 len,
					    const dpo_id_t *dpo);

extern void ip4_fib_table_fwding_dpo_remove(ip4_fib_t *fib,
					    const ip4_address_t *addr,
					    u32 len,
					    const dpo_id_t *dpo,
                                            fib_node_index_t cover_index);
extern u32 ip4_fib_table_lookup_lb (ip4_fib_t *fib,
				    const ip4_address_t * dst);

/**
 * @brief Walk all entries in a FIB table
 * N.B: This is NOT safe to deletes. If you need to delete walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void ip4_fib_table_walk(ip4_fib_t *fib,
                               fib_table_walk_fn_t fn,
                               void *ctx);

/**
 * @brief Get the FIB at the given index
 */
static inline ip4_fib_t *
ip4_fib_get (u32 index)
{
    return (pool_elt_at_index(ip4_main.v4_fibs, index));
}

always_inline u32
ip4_fib_lookup (ip4_main_t * im, u32 sw_if_index, ip4_address_t * dst)
{
    return (ip4_fib_table_lookup_lb(
		ip4_fib_get(vec_elt (im->fib_index_by_sw_if_index, sw_if_index)),
		dst));
}

/**
 * @brief Get or create an IPv4 fib.
 *
 * Get or create an IPv4 fib with the provided table ID.
 *
 * @param table_id
 *      When set to \c ~0, an arbitrary and unused fib ID is picked
 *      and can be retrieved with \c ret->table_id.
 *      Otherwise, the fib ID to be used to retrieve or create the desired fib.
 * @returns A pointer to the retrieved or created fib.
 *
 */
extern u32 ip4_fib_table_find_or_create_and_lock(u32 table_id,
                                                 fib_source_t src);
extern u32 ip4_fib_table_create_and_lock(fib_source_t src);


static inline 
u32 ip4_fib_index_from_table_id (u32 table_id)
{
  ip4_main_t * im = &ip4_main;
  uword * p;

  p = hash_get (im->fib_index_by_table_id, table_id);
  if (!p)
    return ~0;

  return p[0];
}

extern u32 ip4_fib_table_get_index_for_sw_if_index(u32 sw_if_index);

always_inline index_t
ip4_fib_forwarding_lookup (u32 fib_index,
                           const ip4_address_t * addr)
{
    ip4_fib_mtrie_leaf_t leaf;
    ip4_fib_mtrie_t * mtrie;

    mtrie = &ip4_fib_get(fib_index)->mtrie;

    leaf = ip4_fib_mtrie_lookup_step_one (mtrie, addr);
    leaf = ip4_fib_mtrie_lookup_step (mtrie, leaf, addr, 2);
    leaf = ip4_fib_mtrie_lookup_step (mtrie, leaf, addr, 3);

    return (ip4_fib_mtrie_leaf_get_adj_index(leaf));
}


#endif

