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
 * @brief The IPv4 FIB Hash table
 */

#ifndef __IP4_FIB_HASH_H__
#define __IP4_FIB_HASH_H__

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>

typedef struct ip4_fib_hash_t_
{
  /* Hash table for each prefix length mapping. */
  uword *fib_entry_by_dst_address[33];

  /* Table ID (hash key) for this FIB. */
  u32 table_id;
} ip4_fib_hash_t;

extern fib_node_index_t ip4_fib_hash_table_lookup(const ip4_fib_hash_t *fib,
                                                  const ip4_address_t *addr,
                                                  u32 len);
extern index_t ip4_fib_hash_table_lookup_lb(const ip4_fib_hash_t *fib,
                                            const ip4_address_t *addr);
extern fib_node_index_t ip4_fib_hash_table_lookup_exact_match(const ip4_fib_hash_t *fib,
                                                              const ip4_address_t *addr,
                                                              u32 len);

extern void ip4_fib_hash_table_entry_remove(ip4_fib_hash_t *fib,
                                            const ip4_address_t *addr,
                                            u32 len);

extern void ip4_fib_hash_table_entry_insert(ip4_fib_hash_t *fib,
                                            const ip4_address_t *addr,
                                            u32 len,
                                            fib_node_index_t fib_entry_index);
extern void ip4_fib_hash_table_init(ip4_fib_hash_t *fib);
extern void ip4_fib_hash_table_destroy(ip4_fib_hash_t *fib);

/**
 * @brief Walk all entries in a FIB table
 * N.B: This is NOT safe to deletes. If you need to delete walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void ip4_fib_hash_table_walk(ip4_fib_hash_t *fib,
                                    fib_table_walk_fn_t fn,
                                    void *ctx);

/**
 * @brief Walk all entries in a sub-tree of the FIB table
 * N.B: This is NOT safe to deletes. If you need to delete walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void ip4_fib_hash_table_sub_tree_walk(ip4_fib_hash_t *fib,
                                             const fib_prefix_t *root,
                                             fib_table_walk_fn_t fn,
                                             void *ctx);

#endif

