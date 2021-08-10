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

#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/ip4_fib.h>

ip4_fib_8_t *ip4_fib_8s;

void
ip4_fib_8_table_init (ip4_fib_8_t *fib)
{
    ip4_mtrie_8_init(&fib->mtrie);
}

void
ip4_fib_8_table_free (ip4_fib_8_t *fib)
{
    ip4_mtrie_8_free(&fib->mtrie);
}

/*
 * ip4_fib_8_table_lookup_exact_match
 *
 * Exact match prefix lookup
 */
fib_node_index_t
ip4_fib_8_table_lookup_exact_match (const ip4_fib_8_t *fib,
                                     const ip4_address_t *addr,
                                     u32 len)
{
    return (ip4_fib_hash_table_lookup_exact_match(&fib->hash, addr, len));
}

/*
 * ip4_fib_8_table_lookup_adj
 *
 * Longest prefix match
 */
index_t
ip4_fib_8_table_lookup_lb (ip4_fib_8_t *fib,
                           const ip4_address_t *addr)
{
    return (ip4_fib_hash_table_lookup_lb(&fib->hash, addr));
}

/*
 * ip4_fib_8_table_lookup
 *
 * Longest prefix match
 */
fib_node_index_t
ip4_fib_8_table_lookup (const ip4_fib_8_t *fib,
                        const ip4_address_t *addr,
                        u32 len)
{
    return (ip4_fib_hash_table_lookup(&fib->hash, addr, len));
}

void
ip4_fib_8_table_entry_insert (ip4_fib_8_t *fib,
                              const ip4_address_t *addr,
                              u32 len,
                              fib_node_index_t fib_entry_index)
{
    return (ip4_fib_hash_table_entry_insert(&fib->hash, addr, len, fib_entry_index));
}

void
ip4_fib_8_table_entry_remove (ip4_fib_8_t *fib,
                              const ip4_address_t *addr,
                              u32 len)
{
    return (ip4_fib_hash_table_entry_remove(&fib->hash, addr, len));
}

void
ip4_fib_8_table_fwding_dpo_update (ip4_fib_8_t *fib,
                                   const ip4_address_t *addr,
                                   u32 len,
                                   const dpo_id_t *dpo)
{
    ip4_mtrie_8_route_add(&fib->mtrie, addr, len, dpo->dpoi_index);
}

void
ip4_fib_8_table_fwding_dpo_remove (ip4_fib_8_t *fib,
                                    const ip4_address_t *addr,
                                    u32 len,
                                    const dpo_id_t *dpo,
                                    u32 cover_index)
{
    const fib_prefix_t *cover_prefix;
    const dpo_id_t *cover_dpo;

    /*
     * We need to pass the MTRIE the LB index and address length of the
     * covering prefix, so it can fill the plys with the correct replacement
     * for the entry being removed
     */
    cover_prefix = fib_entry_get_prefix(cover_index);
    cover_dpo = fib_entry_contribute_ip_forwarding(cover_index);

    ip4_mtrie_8_route_del(&fib->mtrie,
                            addr, len, dpo->dpoi_index,
                            cover_prefix->fp_len,
                            cover_dpo->dpoi_index);
}

void
ip4_fib_8_table_walk (ip4_fib_8_t *fib,
                       fib_table_walk_fn_t fn,
                       void *ctx)
{
    ip4_fib_hash_table_walk(&fib->hash, fn, ctx);
}

void
ip4_fib_8_table_sub_tree_walk (ip4_fib_8_t *fib,
                               const fib_prefix_t *root,
                               fib_table_walk_fn_t fn,
                               void *ctx)
{
    ip4_fib_hash_table_sub_tree_walk(&fib->hash, root, fn, ctx);
}
