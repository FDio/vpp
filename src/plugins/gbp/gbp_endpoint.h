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

/**
 * The key for an Endpoint
 */
typedef struct gbp_endpoint_key_t_
{
  /**
   * The interface on which the EP is connected
   */
  u32 gek_sw_if_index;

  /**
   * The IP[46] address of the endpoint
   */
  ip46_address_t gek_ip;
} gbp_endpoint_key_t;

/**
 * A Group Based Policy Endpoint.
 * This is typcially a VM on the local compute node for which policy must be
 * locally applied
 */
typedef struct gbp_endpoint_t_
{
  /**
   * The endpoint's interface and IP address
   */
  gbp_endpoint_key_t *ge_key;

  /**
   * The endpoint's designated EPG
   */
  epg_id_t ge_epg_id;
} gbp_endpoint_t;

/**
 * Result of a interface to EPG mapping.
 * multiple Endpoints can occur on the same interface, so this
 * mapping needs to be reference counted.
 */
typedef struct gbp_itf_t_
{
  epg_id_t gi_epg;
  u32 gi_ref_count;
} gbp_itf_t;

/**
 * Interface to source EPG DB - a per-interface vector
 */
typedef struct gbp_itf_to_epg_db_t_
{
  gbp_itf_t *gte_vec;
} gbp_itf_to_epg_db_t;

extern int gbp_endpoint_update (u32 sw_if_index,
				const ip46_address_t * ip, epg_id_t epg_id);
extern void gbp_endpoint_delete (u32 sw_if_index, const ip46_address_t * ip);

typedef int (*gbp_endpoint_cb_t) (gbp_endpoint_t * gbpe, void *ctx);
extern void gbp_endpoint_walk (gbp_endpoint_cb_t cb, void *ctx);

/**
 * Port to EPG mapping management
 */
extern void gbp_itf_epg_update (u32 sw_if_index, epg_id_t src_epg,
				u8 do_policy);
extern void gbp_itf_epg_delete (u32 sw_if_index);

/**
 * DP functions and databases
 */
extern gbp_itf_to_epg_db_t gbp_itf_to_epg_db;

/**
 * Get the source EPG for a port/interface
 */
always_inline u32
gbp_port_to_epg (u32 sw_if_index)
{
  return (gbp_itf_to_epg_db.gte_vec[sw_if_index].gi_epg);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
