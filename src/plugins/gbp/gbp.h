/*
 * Copyright (c) 2013 Cisco and/or its affiliates.
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
 * Group Base Policy (GBP) defines:
 *  - endpoints: typically a VM or container that is connected to the
 *               virtual switch/router (i.e. to VPP)
 *  - endpoint-group: (EPG) a collection of endpoints
 *  - policy: rules determining which traffic can pass between EPGs a.k.a
 *            a 'contract'
 *
 * Here, policy is implemented via an ACL.
 * EPG classification for transit packets is determined by:
 *  - source EPG: from the packet's input interface
 *  - destination EPG: from the packet's destination IP address.
 *
 */

#ifndef included_vnet_gbp_h
#define included_vnet_gbp_h

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

typedef u32 epg_id_t;
#define EPG_INVALID (~0)

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

extern void gbp_endpoint_update (u32 sw_if_index,
				 const ip46_address_t * ip, epg_id_t epg_id);
extern void gbp_endpoint_delete (u32 sw_if_index, const ip46_address_t * ip);

typedef int (*gbp_endpoint_cb_t) (gbp_endpoint_t * gbpe, void *ctx);
extern void gbp_endpoint_walk (gbp_endpoint_cb_t bgpe, void *ctx);


/**
 * The key for an Contract
 */
typedef struct gbp_contract_key_t_
{
  union
  {
    struct
    {
      /**
       * source and destination EPGs for which the ACL applies
       */
      epg_id_t gck_src;
      epg_id_t gck_dst;
    };
    u64 as_u64;
  };
} gbp_contract_key_t;

/**
 * A Group Based Policy Contract.
 *  Determines the ACL that applies to traffic pass between two endpoint groups
 */
typedef struct gbp_contract_t_
{
  /**
   * source and destination EPGs
   */
  gbp_contract_key_t gc_key;

  /**
   * The ACL to apply for packets from the source to the destination EPG
   */
  u32 gc_acl_index;;
} gbp_contract_t;


extern void gbp_contract_update (epg_id_t src_epg,
				 epg_id_t dst_epg, u32 acl_index);
extern void gbp_contract_delete (epg_id_t src_epg, epg_id_t dst_epg);

typedef int (*gbp_contract_cb_t) (gbp_contract_t * gbpe, void *ctx);
extern void gbp_contract_walk (gbp_contract_cb_t bgpe, void *ctx);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
