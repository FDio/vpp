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

#ifndef __IP6_FIB_H__
#define __IP6_FIB_H__

#include <vlib/vlib.h>
#include <vnet/ip/format.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/lookup.h>
#include <vnet/dpo/load_balance.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.h>

/*
 * Default size of the ip6 fib hash table
 */
#define IP6_FIB_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define IP6_FIB_DEFAULT_HASH_MEMORY_SIZE (32<<20)

/**
 * Enumeration of the FIB table instance types
 */
typedef enum ip6_fib_table_instance_type_t_
{
    /**
     * This table stores the routes that are used to forward traffic.
     * The key is the prefix, the result the adjacency to forward on.
     */
  IP6_FIB_TABLE_FWDING,
    /**
     * The table that stores ALL routes learned by the DP.
     * Some of these routes may not be ready to install in forwarding
     * at a given time.
     * The key in this table is the prefix, the result is the fib_entry_t
     */
  IP6_FIB_TABLE_NON_FWDING,
} ip6_fib_table_instance_type_t;

#define IP6_FIB_NUM_TABLES (IP6_FIB_TABLE_NON_FWDING+1)

/**
 * A representation of a single IP6 table
 */
typedef struct ip6_fib_table_instance_t_
{
  /* The hash table */
  clib_bihash_24_8_t ip6_hash;

  /* bitmap / refcounts / vector of mask widths to search */
  uword *non_empty_dst_address_length_bitmap;
  u8 *prefix_lengths_in_search_order;
  i32 dst_address_length_refcounts[129];
} ip6_fib_table_instance_t;

/**
 * The two FIB tables; fwding and non-fwding
 */
extern ip6_fib_table_instance_t ip6_fib_table[IP6_FIB_NUM_TABLES];

extern fib_node_index_t ip6_fib_table_lookup(u32 fib_index,
					     const ip6_address_t *addr,
					     u32 len);
extern fib_node_index_t ip6_fib_table_lookup_exact_match(u32 fib_index,
							 const ip6_address_t *addr,
							 u32 len);

extern void ip6_fib_table_entry_remove(u32 fib_index,
				       const ip6_address_t *addr,
				       u32 len);

extern void ip6_fib_table_entry_insert(u32 fib_index,
				       const ip6_address_t *addr,
				       u32 len,
				       fib_node_index_t fib_entry_index);
extern void ip6_fib_table_destroy(u32 fib_index);

extern void ip6_fib_table_fwding_dpo_update(u32 fib_index,
					    const ip6_address_t *addr,
					    u32 len,
					    const dpo_id_t *dpo);

extern void ip6_fib_table_fwding_dpo_remove(u32 fib_index,
					    const ip6_address_t *addr,
					    u32 len,
					    const dpo_id_t *dpo);

u32 ip6_fib_table_fwding_lookup_with_if_index(ip6_main_t * im,
					      u32 sw_if_index,
					      const ip6_address_t * dst);

/**
 * @brief Walk all entries in a FIB table
 * N.B: This is NOT safe to deletes. If you need to delete walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void ip6_fib_table_walk(u32 fib_index,
                               fib_table_walk_fn_t fn,
                               void *ctx);

always_inline u32
ip6_fib_table_fwding_lookup (u32 fib_index,
                             const ip6_address_t * dst)
{
    ip6_fib_table_instance_t *table;
    clib_bihash_kv_24_8_t kv, value;
    int i, len;
    int rv;
    u64 fib;

    table = &ip6_fib_table[IP6_FIB_TABLE_FWDING];
    len = vec_len (table->prefix_lengths_in_search_order);

    kv.key[0] = dst->as_u64[0];
    kv.key[1] = dst->as_u64[1];
    fib = ((u64)((fib_index))<<32);

    for (i = 0; i < len; i++)
    {
	int dst_address_length = table->prefix_lengths_in_search_order[i];
	ip6_address_t * mask = &ip6_main.fib_masks[dst_address_length];

	ASSERT(dst_address_length >= 0 && dst_address_length <= 128);
	//As lengths are decreasing, masks are increasingly specific.
	kv.key[0] &= mask->as_u64[0];
	kv.key[1] &= mask->as_u64[1];
	kv.key[2] = fib | dst_address_length;

	rv = clib_bihash_search_inline_2_24_8(&table->ip6_hash, &kv, &value);
	if (rv == 0)
	    return value.value;
    }

    /* default route is always present */
    ASSERT(0);
    return 0;
}

/**
 * @brief Walk all entries in a sub-tree of the FIB table
 * N.B: This is NOT safe to deletes. If you need to delete walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void ip6_fib_table_sub_tree_walk(u32 fib_index,
                                        const fib_prefix_t *root,
                                        fib_table_walk_fn_t fn,
                                        void *ctx);

/**
 * @brief return the DPO that the LB stacks on.
 */
always_inline adj_index_t
ip6_src_lookup_for_packet (ip6_main_t * im,
                           vlib_buffer_t * b,
                           ip6_header_t * i)
{
    const dpo_id_t *dpo;
    index_t lbi;

    lbi = ip6_fib_table_fwding_lookup_with_if_index(
        im,
        vnet_buffer (b)->sw_if_index[VLIB_RX],
        &i->src_address);

    dpo = load_balance_get_bucket_i(load_balance_get(lbi), 0);

    if (dpo_is_adj(dpo))
        return (dpo->dpoi_index);

    return (ADJ_INDEX_INVALID);
}

/**
 * \brief Get or create an IPv6 fib.
 *
 * Get or create an IPv4 fib with the provided table ID.
 *
 * \param im
 *      ip4_main pointer.
 * \param table_id
 *      When set to \c ~0, an arbitrary and unused fib ID is picked
 *      and can be retrieved with \c ret->table_id.
 *      Otherwise, the fib ID to be used to retrieve or create the desired fib.
 * \returns A pointer to the retrieved or created fib.
 *
 */
extern u32 ip6_fib_table_find_or_create_and_lock(u32 table_id,
                                                 fib_source_t src);
extern u32 ip6_fib_table_create_and_lock(fib_source_t src,
                                         fib_table_flags_t flags,
                                         u8* desc);

extern u8 *format_ip6_fib_table_memory(u8 * s, va_list * args);

static inline ip6_fib_t *
ip6_fib_get (fib_node_index_t index)
{
    ASSERT(!pool_is_free_index(ip6_main.fibs, index));
    return (pool_elt_at_index (ip6_main.v6_fibs, index));
}

static inline 
u32 ip6_fib_index_from_table_id (u32 table_id)
{
  ip6_main_t * im = &ip6_main;
  uword * p;

  p = hash_get (im->fib_index_by_table_id, table_id);
  if (!p)
    return ~0;

  return p[0];
}

extern u32 ip6_fib_table_get_index_for_sw_if_index(u32 sw_if_index);

#endif

