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

#ifndef __CALICO_H__
#define __CALICO_H__

#include <vnet/fib/fib_node.h>
#include <vnet/ip/ip_types.h>

#include <calico/bihash_40_32.h>

/* only in the default table for v4 and v6 */
#define CALICO_FIB_TABLE 0

typedef struct calico_endpoint_t_
{
  ip_address_t ce_ip;
  u16 ce_port;
} calico_endpoint_t;

typedef struct calico_ep_trk_t_
{
  calico_endpoint_t ct_ep;
  fib_node_index_t ct_fei;
  u32 ct_sibling;
  dpo_id_t ct_dpo;
} calico_ep_trk_t;

extern vlib_combined_counter_main_t calico_translation_counters;

typedef struct calico_vip_tx_t_
{
  /* translations key'd on port & proto */
  ip_address_t cvip_ip;
  uword *cvip_translations;
  dpo_id_t cvip_dpo;
  fib_node_index_t cvip_fei;
  u32 cvip_locks;
} calico_vip_tx_t;

extern calico_vip_tx_t *calico_vip_pool;

static_always_inline calico_vip_tx_t *
calico_vip_tx_get (index_t i)
{
  return (pool_elt_at_index (calico_vip_pool, i));
}

typedef struct calico_client_learn_t_
{
  ip46_address_t cl_ip;
  ip_address_family_t cl_af;
  index_t cl_cti;
} calico_client_learn_t;

typedef struct calico_client_rx_t_
{
  ip_address_t cc_ip;
  dpo_id_t cc_parent;
  fib_node_index_t cc_fei;
  u32 cc_locks;
} calico_client_rx_t;

extern calico_client_rx_t *calico_client_pool;

static_always_inline calico_client_rx_t *
calico_client_rx_get (index_t i)
{
  return (pool_elt_at_index (calico_client_pool, i));
}

typedef struct calico_rx_db_t_
{
  /* RX clients */
  uword *crd_cip4;
  uword *crd_cip6;
} calico_rx_db_t;

extern calico_rx_db_t calico_rx_db;

/**
 * Kubenetes Translation
 */
typedef struct calico_translation_t_
{
  /**
   * Linkage into the FIB graph
   */
  fib_node_t ct_node;

  dpo_id_t ct_lb;

  calico_endpoint_t ct_vip;

  calico_ep_trk_t *ct_paths;


  ip_protocol_t ct_proto;
  index_t ct_vipi;
} calico_translation_t;

extern calico_translation_t *calico_translation_pool;

typedef struct calico_session_t_
{
  // this sits in the same memory location a 'key'
  struct
  {
    ip46_address_t cs_ip[VLIB_N_DIR];
    u16 cs_port[VLIB_N_DIR];
    ip_protocol_t cs_proto;
    u8 cs_af;
    u8 cs_dir;
    u8 __cs_pad;
  } key;
  struct
  {
    ip46_address_t cs_ip;
    u16 cs_port;
    index_t cs_lbi;
    f64 cs_timestamp;
  } value;
} calico_session_t;

extern u8 *format_calico_session (u8 * s, va_list * args);

STATIC_ASSERT (STRUCT_OFFSET_OF (calico_session_t, key) ==
	       STRUCT_OFFSET_OF (clib_bihash_kv_40_32_t, key),
	       "key overlaps");
STATIC_ASSERT (STRUCT_OFFSET_OF (calico_session_t, value) ==
	       STRUCT_OFFSET_OF (clib_bihash_kv_40_32_t, value),
	       "key overlaps");
STATIC_ASSERT (sizeof (calico_session_t) == sizeof (clib_bihash_kv_40_32_t),
	       "session kvp");

extern clib_bihash_40_32_t calico_session_db;

/**
 * Get an CALICO object from its VPP index
 */
/* extern calico_translate_t *calico_translate_get (index_t index); */

/**
 * Find a CALICO object from the client's translate ID
 *
 * @param translate_id Client's defined translate ID
 * @return VPP's object index
 */
/* extern index_t calico_translate_find (u32 translate_id); */

/**
 * The FIB node type for CALICO policies
 */

extern u32 calico_translate_update (const calico_endpoint_t * vip,
				    ip_protocol_t ip_proto,
				    const calico_endpoint_t * paths);

extern int calico_translate_delete (u32 id);

/**
 * Callback function invoked during a walk of all policies
 */
typedef walk_rc_t (*calico_translate_walk_cb_t) (index_t index, void *ctx);

/**
 * Walk/visit each of the CALICO policies
 */
extern void calico_translate_walk (calico_translate_walk_cb_t cb, void *ctx);

extern void calico_client_learn (const calico_client_learn_t * l);

extern int calico_session_purge (void);

static_always_inline calico_translation_t *
calico_translation_get (index_t cti)
{
  return (pool_elt_at_index (calico_translation_pool, cti));
}

static_always_inline calico_translation_t *
calico_vip_find_translation (const calico_vip_tx_t * cvip,
			     u16 port, ip_protocol_t proto)
{
  uword *p;
  u32 key;

  key = proto;
  key = (key << 16) | port;

  p = hash_get (cvip->cvip_translations, key);

  if (p)
    return (pool_elt_at_index (calico_translation_pool, p[0]));

  return (NULL);
}

static_always_inline calico_client_rx_t *
calico_client_ip4_find (const ip4_address_t * ip)
{
  uword *p;

  p = hash_get (calico_rx_db.crd_cip4, ip->as_u32);

  if (p)
    return (pool_elt_at_index (calico_client_pool, p[0]));

  return (NULL);
}

static_always_inline calico_client_rx_t *
calico_client_ip6_find (const ip6_address_t * ip)
{
  uword *p;

  p = hash_get_mem (calico_rx_db.crd_cip6, ip);

  if (p)
    return (pool_elt_at_index (calico_client_pool, p[0]));

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
