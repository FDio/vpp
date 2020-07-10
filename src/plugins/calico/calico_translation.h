/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __CALICO_TRANSLATION_H__
#define __CALICO_TRANSLATION_H__

#include <calico/calico_types.h>
#include <vnet/ip/ip_types.h>
#include <vppinfra/bihash_8_8.h>

/**
 * Counters for each translation
 */
extern vlib_combined_counter_main_t calico_translation_counters;

/**
 * Data used to track an EP in the FIB
 */
typedef struct calico_ep_trk_t_
{
  /**
   * The EP being tracked
   */
  calico_endpoint_t ct_ep[VLIB_N_DIR];

  /**
   * The FIB entry for the EP
   */
  fib_node_index_t ct_fei;

  /**
   * The sibling on the entry's child list
   */
  u32 ct_sibling;

  /**
   * The forwarding contributed by the entry
   */
  dpo_id_t ct_dpo;
} calico_ep_trk_t;

/**
 * A Translation represents the translation of a VEP to one of a set
 * of real server addresses
 */
typedef struct calico_translation_t_
{
  /**
   * Linkage into the FIB graph
   */
  fib_node_t ct_node;

  /**
   * The LB used to forward to the backends
   */
  dpo_id_t ct_lb;

  /**
   * The Virtual end point
   */
  calico_endpoint_t ct_vip;

  /**
   * The vector of tracked back-ends
   */
  calico_ep_trk_t *ct_paths;

  /**
   * The ip protocol for the translation
   */
  ip_protocol_t ct_proto;

  /**
   * The client object this translation belongs on
   */
  index_t ct_cci;
} calico_translation_t;

extern calico_translation_t *calico_translation_pool;

extern u8 *format_calico_translation (u8 * s, va_list * args);

/**
 * create or update a translation
 *
 * @param vip The Virtual Endpoint
 * @param ip_proto The ip protocol to translate
 * @param backends the backends to choose from
 *
 * @return the ID of the translation. used to delete and gather stats
 */
extern u32 calico_translation_update (const calico_endpoint_t * vip,
				      ip_protocol_t ip_proto,
				      const calico_endpoint_tuple_t *
				      backends, u8 flags);

/**
 * Add a translation to the bihash
 *
 * @param cci the ID of the parent client
 * @param port the translation port
 * @param proto the translation proto
 * @param cti the translation index to be used as value
 */
extern void calico_add_translation (index_t cci, u16 port,
				    ip_protocol_t proto, index_t cti);

/**
 * Remove a translation from the bihash
 *
 * @param cci the ID of the parent client
 * @param port the translation port
 * @param proto the translation proto
 */
extern void calico_remove_translation (index_t cci, u16 port,
				       ip_protocol_t proto);

/**
 * Delete a translation
 *
 * @param id the ID as returned from the create
 */
extern int calico_translation_delete (u32 id);

/**
 * Callback function invoked during a walk of all translations
 */
typedef walk_rc_t (*calico_translation_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the translations
 */
extern void calico_translation_walk (calico_translation_walk_cb_t cb,
				     void *ctx);


/*
 * Data plane functions
 */
extern clib_bihash_8_8_t calico_translation_db;

static_always_inline calico_translation_t *
calico_translation_get (index_t cti)
{
  return (pool_elt_at_index (calico_translation_pool, cti));
}

static_always_inline calico_translation_t *
calico_find_translation (index_t cti, u16 port, ip_protocol_t proto)
{
  clib_bihash_kv_8_8_t bkey, bvalue;
  u64 key;
  int rv;

  key = (proto << 16) | port;
  key = key << 32 | (u32) cti;

  bkey.key = key;
  rv = clib_bihash_search_inline_2_8_8 (&calico_translation_db,
					&bkey, &bvalue);
  if (!rv)
    return (pool_elt_at_index (calico_translation_pool, bvalue.value));

  return (NULL);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
