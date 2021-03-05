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

#ifndef __CNAT_TRANSLATION_H__
#define __CNAT_TRANSLATION_H__

#include <cnat/cnat_types.h>
#include <vnet/ip/ip_types.h>
#include <vppinfra/bihash_8_8.h>

/**
 * Counters for each translation
 */
extern vlib_combined_counter_main_t cnat_translation_counters;


/**
 * Data used to track an EP in the FIB
 */
typedef struct cnat_ep_trk_t_
{
  /**
   * The EP being tracked
   */
  cnat_endpoint_t ct_ep[VLIB_N_DIR];

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

  /**
   * Allows to disable if not resolved yet
   */
  u8 ct_flags; /* cnat_trk_flag_t */
} cnat_ep_trk_t;

typedef enum cnat_translation_flag_t_
{
  /* Do allocate a source port */
  CNAT_TRANSLATION_FLAG_ALLOCATE_PORT = (1 << 0),
  /* Has this translation been satcked ?
   * this allow not being called twice when
   * with more then FIB_PATH_LIST_POPULAR backends  */
  CNAT_TRANSLATION_STACKED = (1 << 1),
} cnat_translation_flag_t;

typedef enum
{
  CNAT_RESOLV_ADDR_ANY,
  CNAT_RESOLV_ADDR_BACKEND,
  CNAT_RESOLV_ADDR_SNAT,
  CNAT_RESOLV_ADDR_TRANSLATION,
  CNAT_ADDR_N_RESOLUTIONS,
} cnat_addr_resol_type_t;

typedef enum __attribute__ ((__packed__))
{
  CNAT_LB_DEFAULT,
  CNAT_LB_MAGLEV,
} cnat_lb_type_t;

/**
 * Entry used to account for a translation's backend
 * waiting for address resolution
 */
typedef struct addr_resolution_t_
{
  /**
   * The interface index to resolve
   */
  u32 sw_if_index;
  /**
   * ip4 or ip6 resolution
   */
  ip_address_family_t af;
  /**
   * The cnat_addr_resolution_t
   */
  cnat_addr_resol_type_t type;
  /**
   * Translation index
   */
  index_t cti;
  /**
   * Callback data
   */
  u64 opaque;
} addr_resolution_t;

/**
 * A Translation represents the translation of a VEP to one of a set
 * of real server addresses
 */
typedef struct cnat_translation_t_
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
  cnat_endpoint_t ct_vip;

  /**
   * The vector of tracked back-ends
   */
  cnat_ep_trk_t *ct_paths;

  /**
   * The vector of active tracked back-ends
   */
  cnat_ep_trk_t *ct_active_paths;

  /**
   * The ip protocol for the translation
   */
  ip_protocol_t ct_proto;

  /**
   * The client object this translation belongs on
   * INDEX_INVALID if vip is unresolved
   */
  index_t ct_cci;

  /**
   * Own index (if copied for trace)
   */
  index_t index;

  /**
   * Translation flags
   */
  u8 flags;

  /**
   * Type of load balancing
   */
  cnat_lb_type_t lb_type;

  union
  {
    u32 *lb_maglev;
  };
} cnat_translation_t;

extern cnat_translation_t *cnat_translation_pool;

extern u8 *format_cnat_translation (u8 * s, va_list * args);

/**
 * create or update a translation
 *
 * @param vip The Virtual Endpoint
 * @param ip_proto The ip protocol to translate
 * @param backends the backends to choose from
 *
 * @return the ID of the translation. used to delete and gather stats
 */
extern u32 cnat_translation_update (cnat_endpoint_t *vip,
				    ip_protocol_t ip_proto,
				    cnat_endpoint_tuple_t *backends, u8 flags,
				    cnat_lb_type_t lb_type);

/**
 * Delete a translation
 *
 * @param id the ID as returned from the create
 */
extern int cnat_translation_delete (u32 id);

/**
 * Callback function invoked during a walk of all translations
 */
typedef walk_rc_t (*cnat_translation_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the translations
 */
extern void cnat_translation_walk (cnat_translation_walk_cb_t cb, void *ctx);

/**
 * Purge all the trahslations
 */
extern int cnat_translation_purge (void);

/**
 * Add an address resolution request
 */
extern void cnat_translation_watch_addr (index_t cti, u64 opaque,
					 cnat_endpoint_t * ep,
					 cnat_addr_resol_type_t type);

/**
 * Cleanup matching addr resolution requests
 */
extern void cnat_translation_unwatch_addr (u32 cti,
					   cnat_addr_resol_type_t type);

/**
 * Register a call back for endpoint->address resolution
 */
typedef void (*cnat_if_addr_add_cb_t) (addr_resolution_t *ar,
				       ip_address_t *address, u8 is_del);

extern void cnat_translation_register_addr_add_cb (cnat_addr_resol_type_t typ,
						   cnat_if_addr_add_cb_t fn);

/*
 * Data plane functions
 */
extern clib_bihash_8_8_t cnat_translation_db;

static_always_inline cnat_translation_t *
cnat_translation_get (index_t cti)
{
  return (pool_elt_at_index (cnat_translation_pool, cti));
}

static_always_inline cnat_translation_t *
cnat_find_translation (index_t cti, u16 port, ip_protocol_t proto)
{
  clib_bihash_kv_8_8_t bkey, bvalue;
  u64 key;
  int rv;

  key = ((u64) proto << 24) | port;
  key = key << 32 | (u32) cti;

  bkey.key = key;
  rv = clib_bihash_search_inline_2_8_8 (&cnat_translation_db, &bkey, &bvalue);
  if (!rv)
    return (pool_elt_at_index (cnat_translation_pool, bvalue.value));

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
