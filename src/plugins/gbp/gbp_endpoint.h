/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __GBP_ENDPOINT_H__
#define __GBP_ENDPOINT_H__

#include <plugins/gbp/gbp_types.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/mac_address.h>

#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.h>

/**
 * Flags for each endpoint
 */
typedef enum gbp_endpoint_attr_t_
{
  GBP_ENDPOINT_ATTR_FIRST = 0,
  GBP_ENDPOINT_ATTR_BOUNCE = GBP_ENDPOINT_ATTR_FIRST,
  GBP_ENDPOINT_ATTR_REMOTE = 1,
  GBP_ENDPOINT_ATTR_LEARNT = 2,
  GBP_ENDPOINT_ATTR_LAST,
} gbp_endpoint_attr_t;

typedef enum gbp_endpoint_flags_t_
{
  GBP_ENDPOINT_FLAG_NONE = 0,
  GBP_ENDPOINT_FLAG_BOUNCE = (1 << GBP_ENDPOINT_ATTR_BOUNCE),
  GBP_ENDPOINT_FLAG_REMOTE = (1 << GBP_ENDPOINT_ATTR_REMOTE),
  GBP_ENDPOINT_FLAG_LEARNT = (1 << GBP_ENDPOINT_ATTR_LEARNT),
} gbp_endpoint_flags_t;

#define GBP_ENDPOINT_ATTR_NAMES {                 \
    [GBP_ENDPOINT_ATTR_BOUNCE] = "bounce",        \
    [GBP_ENDPOINT_ATTR_REMOTE] = "remote",        \
    [GBP_ENDPOINT_ATTR_LEARNT] = "learnt",        \
}

extern u8 *format_gbp_endpoint_flags (u8 * s, va_list * args);

/**
 * A Group Based Policy Endpoint.
 * This is typically a VM or container. If the endpoint is local (i.e. on
 * the same compute node as VPP) then there is one interface per-endpoint.
 * If the EP is remote,e.g. reachable over a [vxlan] tunnel, then there
 * will be multiple EPs reachable over the tunnel and they can be distinguished
 * via either their MAC or IP Address[es].
 */
typedef struct gbp_endpoint_t_
{
  /**
   * The interface on which the EP is connected
   */
  index_t ge_itf;
  u32 ge_sw_if_index;

  /**
   * A vector of ip addresses that below to the endpoint
   */
  const ip46_address_t *ge_ips;

  /**
   * MAC address of the endpoint
   */
  mac_address_t ge_mac;

  /**
   * Index of the Endpoint's Group
   */
  index_t ge_epg;

  /**
   * Endpoint Group's ID
   */
  index_t ge_epg_id;

  /**
   * Endpoint flags
   */
  gbp_endpoint_flags_t ge_flags;

  /**
   * The L3 adj, if created
   */
  index_t *ge_adjs;

  /**
   * The last time a packet from seen from this end point
   */
  f64 ge_last_time;

  /**
   * Tunnel info for remote endpoints
   */
  struct
  {
    u32 ge_parent_sw_if_index;
    ip46_address_t ge_src;
    ip46_address_t ge_dst;
  } tun;
} gbp_endpoint_t;

extern u8 *format_gbp_endpoint (u8 * s, va_list * args);

/**
 * GBP Endpoint Databases
 */
typedef struct gbp_ep_by_ip_itf_db_t_
{
  index_t *ged_by_sw_if_index;
  clib_bihash_24_8_t ged_by_ip_rd;
  clib_bihash_16_8_t ged_by_mac_bd;
} gbp_ep_db_t;

extern int gbp_endpoint_update (u32 sw_if_index,
				const ip46_address_t * ip,
				const mac_address_t * mac,
				epg_id_t epg_id,
				gbp_endpoint_flags_t flags,
				const ip46_address_t * tun_src,
				const ip46_address_t * tun_dst, u32 * handle);
extern void gbp_endpoint_delete (index_t gbpei);

typedef walk_rc_t (*gbp_endpoint_cb_t) (index_t gbpei, void *ctx);
extern void gbp_endpoint_walk (gbp_endpoint_cb_t cb, void *ctx);
extern void gbp_endpoint_scan (vlib_main_t * vm);
extern f64 gbp_endpoint_scan_threshold (void);
extern int gbp_endpoint_is_remote (const gbp_endpoint_t * ge);

extern void gbp_endpoint_flush (u32 sw_if_index);

/**
 * DP functions and databases
 */
extern gbp_ep_db_t gbp_ep_db;
extern gbp_endpoint_t *gbp_endpoint_pool;

/**
 * Get the endpoint from a port/interface
 */
always_inline gbp_endpoint_t *
gbp_endpoint_get (index_t gbpei)
{
  return (pool_elt_at_index (gbp_endpoint_pool, gbpei));
}

static_always_inline void
gbp_endpoint_mk_key_mac (const u8 * mac,
			 u32 bd_index, clib_bihash_kv_16_8_t * key)
{
  key->key[0] = ethernet_mac_address_u64 (mac);
  key->key[1] = bd_index;
}

static_always_inline gbp_endpoint_t *
gbp_endpoint_find_mac (const u8 * mac, u32 bd_index)
{
  clib_bihash_kv_16_8_t key, value;
  int rv;

  gbp_endpoint_mk_key_mac (mac, bd_index, &key);

  rv = clib_bihash_search_16_8 (&gbp_ep_db.ged_by_mac_bd, &key, &value);

  if (0 != rv)
    return NULL;

  return (gbp_endpoint_get (value.value));
}

static_always_inline void
gbp_endpoint_mk_key_ip (const ip46_address_t * ip,
			u32 fib_index, clib_bihash_kv_24_8_t * key)
{
  key->key[0] = ip->as_u64[0];
  key->key[1] = ip->as_u64[1];
  key->key[2] = fib_index;
}

static_always_inline void
gbp_endpoint_mk_key_ip4 (const ip4_address_t * ip,
			 u32 fib_index, clib_bihash_kv_24_8_t * key)
{
  const ip46_address_t a = {
    .ip4 = *ip,
  };
  gbp_endpoint_mk_key_ip (&a, fib_index, key);
}

static_always_inline gbp_endpoint_t *
gbp_endpoint_find_ip4 (const ip4_address_t * ip, u32 fib_index)
{
  clib_bihash_kv_24_8_t key, value;
  int rv;

  gbp_endpoint_mk_key_ip4 (ip, fib_index, &key);

  rv = clib_bihash_search_24_8 (&gbp_ep_db.ged_by_ip_rd, &key, &value);

  if (0 != rv)
    return NULL;

  return (gbp_endpoint_get (value.value));
}

static_always_inline void
gbp_endpoint_mk_key_ip6 (const ip6_address_t * ip,
			 u32 fib_index, clib_bihash_kv_24_8_t * key)
{
  key->key[0] = ip->as_u64[0];
  key->key[1] = ip->as_u64[1];
  key->key[2] = fib_index;
}

static_always_inline gbp_endpoint_t *
gbp_endpoint_find_ip6 (const ip6_address_t * ip, u32 fib_index)
{
  clib_bihash_kv_24_8_t key, value;
  int rv;

  gbp_endpoint_mk_key_ip6 (ip, fib_index, &key);

  rv = clib_bihash_search_24_8 (&gbp_ep_db.ged_by_ip_rd, &key, &value);

  if (0 != rv)
    return NULL;

  return (gbp_endpoint_get (value.value));
}

static_always_inline gbp_endpoint_t *
gbp_endpoint_find_itf (u32 sw_if_index)
{
  index_t gei;

  gei = gbp_ep_db.ged_by_sw_if_index[sw_if_index];

  if (INDEX_INVALID != gei)
    return (gbp_endpoint_get (gei));

  return (NULL);
}


#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
