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
typedef enum gbp_endpoint_flags_t_
{
  GBP_ENDPOINT_FLAG_NONE = 0,
  GBP_ENDPOINT_FLAG_BOUNCE = (1 << 0),
  GBP_ENDPOINT_FLAG_DYNAMIC = (1 << 1),
} gbp_endpoint_flags_t;

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
  u32 ge_sw_if_index;

  /**
   * A vector of ip addresses that below to the endpoint
   */
  ip46_address_t *ge_ips;

  /**
   * MAC address of the endpoint
   */
  mac_address_t ge_mac;

  /**
   * The endpoint's designated EPG
   */
  epg_id_t ge_epg_id;

  /**
   * Endpoint flags
   */
  gbp_endpoint_flags_t ge_flags;
} gbp_endpoint_t;

extern u8 *format_gbp_endpoint (u8 * s, va_list * args);

/**
 * Interface to source EPG DB - a per-interface vector
 */
typedef struct gbp_ep_by_itf_db_t_
{
  index_t *gte_vec;
} gbp_ep_by_itf_db_t;

typedef struct gbp_ep_by_ip_itf_db_t_
{
  clib_bihash_24_8_t gte_table;
} gbp_ep_by_ip_itf_db_t;

typedef struct gbp_ep_by_mac_itf_db_t_
{
  clib_bihash_16_8_t gte_table;
} gbp_ep_by_mac_itf_db_t;

extern int gbp_endpoint_update (u32 sw_if_index,
				const ip46_address_t * ip,
				const mac_address_t * mac,
				epg_id_t epg_id, u32 * handle);
extern void gbp_endpoint_delete (u32 handle);

typedef walk_rc_t (*gbp_endpoint_cb_t) (gbp_endpoint_t * gbpe, void *ctx);
extern void gbp_endpoint_walk (gbp_endpoint_cb_t cb, void *ctx);


/**
 * DP functions and databases
 */
extern gbp_ep_by_itf_db_t gbp_ep_by_itf_db;
extern gbp_ep_by_mac_itf_db_t gbp_ep_by_mac_itf_db;
extern gbp_ep_by_ip_itf_db_t gbp_ep_by_ip_itf_db;
extern gbp_endpoint_t *gbp_endpoint_pool;

/**
 * Get the endpoint from a port/interface
 */
always_inline gbp_endpoint_t *
gbp_endpoint_get (index_t gbpei)
{
  return (pool_elt_at_index (gbp_endpoint_pool, gbpei));
}

always_inline gbp_endpoint_t *
gbp_endpoint_get_itf (u32 sw_if_index)
{
  return (gbp_endpoint_get (gbp_ep_by_itf_db.gte_vec[sw_if_index]));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
