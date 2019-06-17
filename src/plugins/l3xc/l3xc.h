/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 * A L3 cross connect will send all traffic that is received on the input
 * interface to the [set of] paths requested.
 * It is a much more memory efficient solution than using a separate IP table
 * for each input interface and much faster than an ABF match all rule.
 */

#ifndef __L3XC_H__
#define __L3XC_H__

#include <vnet/fib/fib_node.h>

#define L3XC_PLUGIN_VERSION_MAJOR 1
#define L3XC_PLUGIN_VERSION_MINOR 0

/**
 */
typedef struct l3xc_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  /**
   * Linkage into the FIB graph
   */
  fib_node_t l3xc_node;

  /**
   * The path-list describing how to forward in case of a match
   */
  fib_node_index_t l3xc_pl;

  fib_protocol_t l3xc_proto;

  /**
   * Sibling index on the path-list
   */
  u32 l3xc_sibling;

  /**
   * The input interface
   */
  u32 l3xc_sw_if_index;

  /**
   * DPO for forwarding
   */
  dpo_id_t l3xc_dpo;
} l3xc_t;

/**
 * Create or update an L3XC Policy
 *
 * @param sw_if_index_index the input interface
 * @param rpaths The set of paths to add to the forwarding set
 * @return error code
 */
extern int l3xc_update (u32 sw_if_index,
			u8 is_ip6, const fib_route_path_t * rpaths);

/**
 * Delete an L3XC.
 *
 * @param sw_if_index_index the input interface
 */
extern int l3xc_delete (u32 sw_if_index, u8 is_ip6);

/**
 * Callback function invoked during a walk of all policies
 */
typedef int (*l3xc_walk_cb_t) (index_t l3xci, void *ctx);

/**
 * Walk/visit each of the L3XC policies
 */
extern void l3xc_walk (l3xc_walk_cb_t cb, void *ctx);

/**
 * Find a L3 XC object from an interfce and FIB protocol
 */
extern index_t l3xc_find (u32 sw_if_index, fib_protocol_t fproto);

/**
 * Data-plane functions
 */
extern l3xc_t *l3xc_pool;

static_always_inline l3xc_t *
l3xc_get (u32 index)
{
  return (pool_elt_at_index (l3xc_pool, index));
}

extern vlib_node_registration_t l3xc_ip4_node;
extern vlib_node_registration_t l3xc_ip6_node;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
