/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 * @file
 * @brief Segment Routing MPLS data structures definitions
 *
 */

#ifndef included_vnet_srmpls_h
#define included_vnet_srmpls_h

#include <vnet/vnet.h>
#include <vnet/mpls/packet.h>
#include <vnet/fib/mpls_fib.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/lookup.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/replicate_dpo.h>

#include <stdlib.h>
#include <string.h>

/* SR policy types */
#define SR_POLICY_TYPE_DEFAULT 0
#define SR_POLICY_TYPE_SPRAY 1

#define SR_SEGMENT_LIST_WEIGHT_DEFAULT 1

#define SR_STEER_IPV4 4
#define SR_STEER_IPV6 6

/**
 * @brief SR Segment List (SID list)
 */
typedef struct
{
  /**
    * SIDs (key)
    */
  mpls_label_t *segments;

  /**
    * SID list weight (wECMP / UCMP)
    */
  u32 weight;

  /**
    * DPOs for the SID list
    */
  dpo_id_t sl_eos_dpo;
  dpo_id_t sl_neos_dpo;
  dpo_id_t sl_v4_dpo;
  dpo_id_t sl_v6_dpo;

  /**
   * The FIB node graph linkage
   */
  fib_node_t node;

  /**
    * The FIB entry index for the first hop. We track this so we
    * don't need an extra lookup for it in the data plane
    */
  fib_node_index_t first_hop_fe_index;

  /**
    * This SID list' sibling index in the children of the FIB entry
    */
  u32 sibling_index;

  /**
    * The DPO contributed by the first-hop FIB entry.
    */
  dpo_id_t first_hop_dpo;

} mpls_sr_sl_t;

typedef struct
{
  u32 *segments_lists;		/**< Pool of SID lists indexes */

  mpls_label_t bsid;		/**< BindingSID (key) */

  u8 type;					/**< Type (default is 0) */
  /* SR Policy specific DPO                                       */
  /* IF Type = DEFAULT Then Load Balancer DPO among SID lists     */
  /* IF Type = SPRAY then Spray DPO with all SID lists            */

  u32 fib_table;				/**< FIB table */

  dpo_id_t bsid_eos_dpo;		/**< DPO for the SID list */
  dpo_id_t bsid_neos_dpo;		/**< DPO for the SID list */
  dpo_id_t bsid_v4_dpo;			/**< DPO for the SID list */
  dpo_id_t bsid_v6_dpo;			/**< DPO for the SID list */

} mpls_sr_policy_t;

/**
 * @brief Steering db key
 *
 * L3 is IPv4/IPv6 + mask
 */
typedef struct
{
  ip46_address_t prefix;	/**< IP address of the prefix */
  u32 mask_width;			/**< Mask width of the prefix */
  u32 fib_table;			/**< VRF of the prefix */
  u8 traffic_type;			/**< Traffic type (IPv4, IPv6, L2) */
  u8 padding[3];
} sr_mpls_steering_key_t;

typedef struct
{
  sr_mpls_steering_key_t classify;		/**< Traffic classification */
  u32 sr_policy;						/**< SR Policy index */
} mpls_sr_steering_policy_t;

/**
 * @brief Segment Routing main datastructure
 */
typedef struct
{
  /**
    * SR SID lists
    */
  mpls_sr_sl_t *sid_lists;

  /**
    * SR MPLS policies
    */
  mpls_sr_policy_t *sr_policies;

  /**
    * Hash table mapping BindingSID to SR MPLS policy
    */
  mhash_t sr_policies_index_hash;

  /**
    * MPLS lookup DPO
    */
  dpo_id_t mpls_lookup_dpo;

  /**
    * Pool of SR steer policies instances
    */
  mpls_sr_steering_policy_t *steer_policies;

  /**
    * Hash table mapping steering rules to SR steer instance
    */
  mhash_t sr_steer_policies_hash;

  /**
    * Auxiliar FIB table indexes
    */
  u32 fib_table_ip6;
  u32 fib_table_ip4;

  /**
    * convenience
    */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} mpls_sr_main_t;

extern mpls_sr_main_t sr_mpls_main;

extern int
sr_mpls_policy_add (mpls_label_t bsid, mpls_label_t * segments,
		    u8 behavior, u32 fib_table, u32 weight);

extern int
sr_mpls_policy_mod (mpls_label_t bsid, u32 index, u32 fib_table,
		    u8 operation, mpls_label_t * segments, u32 sl_index,
		    u32 weight);

extern int sr_mpls_policy_del (mpls_label_t bsid, u32 index);

#endif /* included_vnet_sr_mpls_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
