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
u32 ip6_fib_table_fwding_lookup(ip6_main_t * im,
				u32 fib_index, 
				const ip6_address_t * dst);

/**
 * @biref return the DPO that the LB stacks on.
 */
always_inline u32
ip6_src_lookup_for_packet (ip6_main_t * im,
                           vlib_buffer_t * b,
                           ip6_header_t * i)
{
    if (vnet_buffer (b)->ip.adj_index[VLIB_RX] == ~0)
    {
        const dpo_id_t *dpo;
        index_t lbi;

        lbi = ip6_fib_table_fwding_lookup_with_if_index(
                  im,
                  vnet_buffer (b)->sw_if_index[VLIB_RX],
                  &i->src_address);

        dpo = load_balance_get_bucket_i(load_balance_get(lbi), 0);

        if (dpo_is_adj(dpo))
        {
            vnet_buffer (b)->ip.adj_index[VLIB_RX] = dpo->dpoi_index;
        }
    }
    return vnet_buffer (b)->ip.adj_index[VLIB_RX];
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
extern u32 ip6_fib_table_find_or_create_and_lock(u32 table_id);
extern u32 ip6_fib_table_create_and_lock(void);

static inline ip6_fib_t *
ip6_fib_get (fib_node_index_t index)
{
    ASSERT(!pool_is_free_index(ip6_main.fibs, index));
    return (&pool_elt_at_index (ip6_main.fibs, index)->v6);
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

extern flow_hash_config_t ip6_fib_table_get_flow_hash_config(u32 fib_index);

#endif

