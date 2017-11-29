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
 * @brief The IPv4 Multicast-FIB
 *
 * FIXME
 *
 * This IPv4 FIB is used by the protocol independent FIB. So directly using
 * this APIs in client code is not encouraged. However, this IPv4 FIB can be
 * used if all the client wants is an IPv4 prefix data-base
 */

#ifndef __IP4_MFIB_H__
#define __IP4_MFIB_H__

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>

#include <vnet/mfib/mfib_table.h>

extern fib_node_index_t ip4_mfib_table_lookup(const ip4_mfib_t *fib,
                                              const ip4_address_t *src,
                                              const ip4_address_t *grp,
                                              u32 len);
extern fib_node_index_t ip4_mfib_table_lookup_exact_match(const ip4_mfib_t *fib,
                                                          const ip4_address_t *grp,
                                                          const ip4_address_t *src,
                                                          u32 len);

extern void ip4_mfib_table_entry_remove(ip4_mfib_t *fib,
                                        const ip4_address_t *grp,
                                        const ip4_address_t *src,
                                        u32 len);

extern void ip4_mfib_table_entry_insert(ip4_mfib_t *fib,
                                        const ip4_address_t *grp,
                                        const ip4_address_t *src,
                                        u32 len,
                                        fib_node_index_t fib_entry_index);
extern void ip4_mfib_table_destroy(ip4_mfib_t *fib);

/**
 * @brief Get the FIB at the given index
 */
static inline ip4_mfib_t *
ip4_mfib_get (u32 index)
{
    return (&(pool_elt_at_index(ip4_main.mfibs, index)->v4));
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
extern u32 ip4_mfib_table_find_or_create_and_lock(u32 table_id,
                                                  mfib_source_t src);
extern u32 ip4_mfib_table_create_and_lock(mfib_source_t src);

static inline
u32 ip4_mfib_index_from_table_id (u32 table_id)
{
  ip4_main_t * im = &ip4_main;
  uword * p;

  p = hash_get (im->mfib_index_by_table_id, table_id);
  if (!p)
    return ~0;

  return p[0];
}

extern u32 ip4_mfib_table_get_index_for_sw_if_index(u32 sw_if_index);

/**
 * @brief Walk the IP4 mfib table.
 *
 * @param mfib the table to walk
 * @param fn The function to invoke on each entry visited
 * @param ctx A context passed in the visit function
 */
extern void ip4_mfib_table_walk(ip4_mfib_t *mfib,
                                mfib_table_walk_fn_t fn,
                                void *ctx);

/**
 * @brief format (display) the memory usage for IP4 mfibs
 */
extern u8 * format_ip4_mfib_table_memory(u8 * s, va_list * args);

#endif
