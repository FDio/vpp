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
#include <vnet/fib/ip4_fib_8.h>
#include <vnet/fib/ip4_fib_16.h>

// for the VPP_IP_FIB_MTRIE_16 definition
#include <vpp/vnet/config.h>

/**
 * the FIB module uses the 16-8-8 stride trie
 */
#ifdef VPP_IP_FIB_MTRIE_16
typedef ip4_fib_16_t ip4_fib_t;

#define ip4_fibs ip4_fib_16s
#define ip4_fib_table_lookup ip4_fib_16_table_lookup
#define ip4_fib_table_lookup_exact_match ip4_fib_16_table_lookup_exact_match
#define ip4_fib_table_entry_remove ip4_fib_16_table_entry_remove
#define ip4_fib_table_entry_insert ip4_fib_16_table_entry_insert
#define ip4_fib_table_fwding_dpo_update ip4_fib_16_table_fwding_dpo_update
#define ip4_fib_table_fwding_dpo_remove ip4_fib_16_table_fwding_dpo_remove
#define ip4_fib_table_lookup_lb ip4_fib_16_table_lookup_lb
#define ip4_fib_table_walk ip4_fib_16_table_walk
#define ip4_fib_table_sub_tree_walk ip4_fib_16_table_sub_tree_walk
#define ip4_fib_table_init ip4_fib_16_table_init
#define ip4_fib_table_free ip4_fib_16_table_free
#define ip4_mtrie_memory_usage ip4_mtrie_16_memory_usage
#define format_ip4_mtrie format_ip4_mtrie_16

#else
typedef ip4_fib_8_t ip4_fib_t;

#define ip4_fibs ip4_fib_8s
#define ip4_fib_table_lookup ip4_fib_8_table_lookup
#define ip4_fib_table_lookup_exact_match ip4_fib_8_table_lookup_exact_match
#define ip4_fib_table_entry_remove ip4_fib_8_table_entry_remove
#define ip4_fib_table_entry_insert ip4_fib_8_table_entry_insert
#define ip4_fib_table_fwding_dpo_update ip4_fib_8_table_fwding_dpo_update
#define ip4_fib_table_fwding_dpo_remove ip4_fib_8_table_fwding_dpo_remove
#define ip4_fib_table_lookup_lb ip4_fib_8_table_lookup_lb
#define ip4_fib_table_walk ip4_fib_8_table_walk
#define ip4_fib_table_sub_tree_walk ip4_fib_8_table_sub_tree_walk
#define ip4_fib_table_init ip4_fib_8_table_init
#define ip4_fib_table_free ip4_fib_8_table_free
#define ip4_mtrie_memory_usage ip4_mtrie_8_memory_usage
#define format_ip4_mtrie format_ip4_mtrie_8

#endif

/**
 * @brief Get the FIB at the given index
 */
static inline ip4_fib_t *
ip4_fib_get (u32 index)
{
    return (pool_elt_at_index(ip4_fibs, index));
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
extern u32 ip4_fib_table_find_free_table_id ();
extern u32 ip4_fib_table_create_and_lock(fib_source_t src);
extern void ip4_fib_table_destroy(u32 fib_index);

extern u8 *format_ip4_fib_table_memory(u8 * s, va_list * args);

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

#ifdef VPP_IP_FIB_MTRIE_16
always_inline index_t
ip4_fib_forwarding_lookup (u32 fib_index,
                           const ip4_address_t * addr)
{
    ip4_mtrie_leaf_t leaf;
    ip4_mtrie_16_t * mtrie;

    mtrie = &ip4_fib_get(fib_index)->mtrie;

    leaf = ip4_mtrie_16_lookup_step_one (mtrie, addr);
    leaf = ip4_mtrie_16_lookup_step (leaf, addr, 2);
    leaf = ip4_mtrie_16_lookup_step (leaf, addr, 3);

    return (ip4_mtrie_leaf_get_adj_index(leaf));
}

static_always_inline void
ip4_fib_forwarding_lookup_x2 (u32 fib_index0,
                              u32 fib_index1,
                              const ip4_address_t * addr0,
                              const ip4_address_t * addr1,
                              index_t *lb0,
                              index_t *lb1)
{
    ip4_mtrie_leaf_t leaf[2];
    ip4_mtrie_16_t * mtrie[2];

    mtrie[0] = &ip4_fib_get(fib_index0)->mtrie;
    mtrie[1] = &ip4_fib_get(fib_index1)->mtrie;

    leaf[0] = ip4_mtrie_16_lookup_step_one (mtrie[0], addr0);
    leaf[1] = ip4_mtrie_16_lookup_step_one (mtrie[1], addr1);
    leaf[0] = ip4_mtrie_16_lookup_step (leaf[0], addr0, 2);
    leaf[1] = ip4_mtrie_16_lookup_step (leaf[1], addr1, 2);
    leaf[0] = ip4_mtrie_16_lookup_step (leaf[0], addr0, 3);
    leaf[1] = ip4_mtrie_16_lookup_step (leaf[1], addr1, 3);

    *lb0 = ip4_mtrie_leaf_get_adj_index(leaf[0]);
    *lb1 = ip4_mtrie_leaf_get_adj_index(leaf[1]);
}

static_always_inline void
ip4_fib_forwarding_lookup_x4 (u32 fib_index0,
                              u32 fib_index1,
                              u32 fib_index2,
                              u32 fib_index3,
                              const ip4_address_t * addr0,
                              const ip4_address_t * addr1,
                              const ip4_address_t * addr2,
                              const ip4_address_t * addr3,
                              index_t *lb0,
                              index_t *lb1,
                              index_t *lb2,
                              index_t *lb3)
{
    ip4_mtrie_leaf_t leaf[4];
    ip4_mtrie_16_t * mtrie[4];

    mtrie[0] = &ip4_fib_get(fib_index0)->mtrie;
    mtrie[1] = &ip4_fib_get(fib_index1)->mtrie;
    mtrie[2] = &ip4_fib_get(fib_index2)->mtrie;
    mtrie[3] = &ip4_fib_get(fib_index3)->mtrie;

    leaf[0] = ip4_mtrie_16_lookup_step_one (mtrie[0], addr0);
    leaf[1] = ip4_mtrie_16_lookup_step_one (mtrie[1], addr1);
    leaf[2] = ip4_mtrie_16_lookup_step_one (mtrie[2], addr2);
    leaf[3] = ip4_mtrie_16_lookup_step_one (mtrie[3], addr3);

    leaf[0] = ip4_mtrie_16_lookup_step (leaf[0], addr0, 2);
    leaf[1] = ip4_mtrie_16_lookup_step (leaf[1], addr1, 2);
    leaf[2] = ip4_mtrie_16_lookup_step (leaf[2], addr2, 2);
    leaf[3] = ip4_mtrie_16_lookup_step (leaf[3], addr3, 2);

    leaf[0] = ip4_mtrie_16_lookup_step (leaf[0], addr0, 3);
    leaf[1] = ip4_mtrie_16_lookup_step (leaf[1], addr1, 3);
    leaf[2] = ip4_mtrie_16_lookup_step (leaf[2], addr2, 3);
    leaf[3] = ip4_mtrie_16_lookup_step (leaf[3], addr3, 3);

    *lb0 = ip4_mtrie_leaf_get_adj_index(leaf[0]);
    *lb1 = ip4_mtrie_leaf_get_adj_index(leaf[1]);
    *lb2 = ip4_mtrie_leaf_get_adj_index(leaf[2]);
    *lb3 = ip4_mtrie_leaf_get_adj_index(leaf[3]);
}

#else

always_inline index_t
ip4_fib_forwarding_lookup (u32 fib_index,
                           const ip4_address_t * addr)
{
    ip4_mtrie_leaf_t leaf;
    ip4_mtrie_8_t * mtrie;

    mtrie = &ip4_fib_get(fib_index)->mtrie;

    leaf = ip4_mtrie_8_lookup_step_one (mtrie, addr);
    leaf = ip4_mtrie_8_lookup_step (leaf, addr, 1);
    leaf = ip4_mtrie_8_lookup_step (leaf, addr, 2);
    leaf = ip4_mtrie_8_lookup_step (leaf, addr, 3);

    return (ip4_mtrie_leaf_get_adj_index(leaf));
}

static_always_inline void
ip4_fib_forwarding_lookup_x2 (u32 fib_index0,
                              u32 fib_index1,
                              const ip4_address_t * addr0,
                              const ip4_address_t * addr1,
                              index_t *lb0,
                              index_t *lb1)
{
    ip4_mtrie_leaf_t leaf[2];
    ip4_mtrie_8_t * mtrie[2];

    mtrie[0] = &ip4_fib_get(fib_index0)->mtrie;
    mtrie[1] = &ip4_fib_get(fib_index1)->mtrie;

    leaf[0] = ip4_mtrie_8_lookup_step_one (mtrie[0], addr0);
    leaf[1] = ip4_mtrie_8_lookup_step_one (mtrie[1], addr1);
    leaf[0] = ip4_mtrie_8_lookup_step (leaf[0], addr0, 1);
    leaf[1] = ip4_mtrie_8_lookup_step (leaf[1], addr1, 1);
    leaf[0] = ip4_mtrie_8_lookup_step (leaf[0], addr0, 2);
    leaf[1] = ip4_mtrie_8_lookup_step (leaf[1], addr1, 2);
    leaf[0] = ip4_mtrie_8_lookup_step (leaf[0], addr0, 3);
    leaf[1] = ip4_mtrie_8_lookup_step (leaf[1], addr1, 3);

    *lb0 = ip4_mtrie_leaf_get_adj_index(leaf[0]);
    *lb1 = ip4_mtrie_leaf_get_adj_index(leaf[1]);
}

static_always_inline void
ip4_fib_forwarding_lookup_x4 (u32 fib_index0,
                              u32 fib_index1,
                              u32 fib_index2,
                              u32 fib_index3,
                              const ip4_address_t * addr0,
                              const ip4_address_t * addr1,
                              const ip4_address_t * addr2,
                              const ip4_address_t * addr3,
                              index_t *lb0,
                              index_t *lb1,
                              index_t *lb2,
                              index_t *lb3)
{
    ip4_mtrie_leaf_t leaf[4];
    ip4_mtrie_8_t * mtrie[4];

    mtrie[0] = &ip4_fib_get(fib_index0)->mtrie;
    mtrie[1] = &ip4_fib_get(fib_index1)->mtrie;
    mtrie[2] = &ip4_fib_get(fib_index2)->mtrie;
    mtrie[3] = &ip4_fib_get(fib_index3)->mtrie;

    leaf[0] = ip4_mtrie_8_lookup_step_one (mtrie[0], addr0);
    leaf[1] = ip4_mtrie_8_lookup_step_one (mtrie[1], addr1);
    leaf[2] = ip4_mtrie_8_lookup_step_one (mtrie[2], addr2);
    leaf[3] = ip4_mtrie_8_lookup_step_one (mtrie[3], addr3);

    leaf[0] = ip4_mtrie_8_lookup_step (leaf[0], addr0, 1);
    leaf[1] = ip4_mtrie_8_lookup_step (leaf[1], addr1, 1);
    leaf[2] = ip4_mtrie_8_lookup_step (leaf[2], addr2, 1);
    leaf[3] = ip4_mtrie_8_lookup_step (leaf[3], addr3, 1);

    leaf[0] = ip4_mtrie_8_lookup_step (leaf[0], addr0, 2);
    leaf[1] = ip4_mtrie_8_lookup_step (leaf[1], addr1, 2);
    leaf[2] = ip4_mtrie_8_lookup_step (leaf[2], addr2, 2);
    leaf[3] = ip4_mtrie_8_lookup_step (leaf[3], addr3, 2);

    leaf[0] = ip4_mtrie_8_lookup_step (leaf[0], addr0, 3);
    leaf[1] = ip4_mtrie_8_lookup_step (leaf[1], addr1, 3);
    leaf[2] = ip4_mtrie_8_lookup_step (leaf[2], addr2, 3);
    leaf[3] = ip4_mtrie_8_lookup_step (leaf[3], addr3, 3);

    *lb0 = ip4_mtrie_leaf_get_adj_index(leaf[0]);
    *lb1 = ip4_mtrie_leaf_get_adj_index(leaf[1]);
    *lb2 = ip4_mtrie_leaf_get_adj_index(leaf[2]);
    *lb3 = ip4_mtrie_leaf_get_adj_index(leaf[3]);
}

#endif

#endif
