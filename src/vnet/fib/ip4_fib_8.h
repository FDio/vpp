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

#ifndef __IP4_FIB_8_H__
#define __IP4_FIB_8_H__

#include <vnet/fib/ip4_fib_hash.h>
#include <vnet/ip/ip4_mtrie.h>

typedef struct ip4_fib_8_t_
{
  /** Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

  /**
   * Mtrie for fast lookups. Hash is used to maintain overlapping prefixes.
   * First member so it's in the first cacheline.
   */
  ip4_mtrie_8_t mtrie;

  /**
   * The hash table DB
   */
  ip4_fib_hash_t hash;
} ip4_fib_8_t;

extern ip4_fib_8_t *ip4_fib_8s;

extern fib_node_index_t ip4_fib_8_table_lookup(const ip4_fib_8_t *fib,
                                               const ip4_address_t *addr,
                                               u32 len);
extern fib_node_index_t ip4_fib_8_table_lookup_exact_match(const ip4_fib_8_t *fib,
                                                           const ip4_address_t *addr,
                                                           u32 len);

extern void ip4_fib_8_table_entry_remove(ip4_fib_8_t *fib,
                                         const ip4_address_t *addr,
                                         u32 len);

extern void ip4_fib_8_table_entry_insert(ip4_fib_8_t *fib,
                                         const ip4_address_t *addr,
                                         u32 len,
                                         fib_node_index_t fib_entry_index);
extern void ip4_fib_8_table_free(ip4_fib_8_t *fib);
extern void ip4_fib_8_table_init(ip4_fib_8_t *fib);

extern void ip4_fib_8_table_fwding_dpo_update(ip4_fib_8_t *fib,
                                              const ip4_address_t *addr,
                                              u32 len,
                                              const dpo_id_t *dpo);

extern void ip4_fib_8_table_fwding_dpo_remove(ip4_fib_8_t *fib,
                                              const ip4_address_t *addr,
                                              u32 len,
                                              const dpo_id_t *dpo,
                                              fib_node_index_t cover_index);
extern u32 ip4_fib_8_table_lookup_lb (ip4_fib_8_t *fib,
                                      const ip4_address_t * dst);

/**
 * @brief Walk all entries in a FIB table
 * N.B: This is NOT safe to deletes. If you need to delete walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void ip4_fib_8_table_walk(ip4_fib_8_t *fib,
                               fib_table_walk_fn_t fn,
                               void *ctx);

/**
 * @brief Walk all entries in a sub-tree of the FIB table
 * N.B: This is NOT safe to deletes. If you need to delete walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void ip4_fib_8_table_sub_tree_walk(ip4_fib_8_t *fib,
                                        const fib_prefix_t *root,
                                        fib_table_walk_fn_t fn,
                                        void *ctx);

#endif

