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

/**
 * @brief SR Segment List (SID list)
 */
typedef struct
{
  mpls_label_t *segments;   /**< SIDs (key) */

  u32 weight;               /**< SID list weight (wECMP / UCMP) */

  dpo_id_t sl_eos_dpo;    /**< DPO for the SID list */
  dpo_id_t sl_neos_dpo;    /**< DPO for the SID list */
  dpo_id_t sl_v4_dpo;    /**< DPO for the SID list */
  dpo_id_t sl_v6_dpo;    /**< DPO for the SID list */

} mpls_sr_sl_t;

typedef struct 
{
  u32 *segments_lists;    /**< Pool of SID lists indexes */

  mpls_label_t bsid;      /**< BindingSID (key) */

  u8 type;                /**< Type (default is 0) */
  /* SR Policy specific DPO                                       */
  /* IF Type = DEFAULT Then Load Balancer DPO among SID lists     */
  /* IF Type = SPRAY then Spray DPO with all SID lists            */

  u32 fib_table;          /**< FIB table */

  dpo_id_t bsid_eos_dpo;    /**< DPO for the SID list */
  dpo_id_t bsid_neos_dpo;    /**< DPO for the SID list */
  dpo_id_t bsid_v4_dpo;    /**< DPO for the SID list */
  dpo_id_t bsid_v6_dpo;    /**< DPO for the SID list */

} mpls_sr_policy_t;

/**
 * @brief Segment Routing main datastructure
 */
typedef struct
{
  /* SR SID lists */
  mpls_sr_sl_t *sid_lists;

  /* SR MPLS policies */
  mpls_sr_policy_t *sr_policies;

  /* Hash table mapping BindingSID to SR MPLS policy */
  mhash_t sr_policies_index_hash;

  /* MPLS lookup DPO */
  dpo_id_t mpls_lookup_dpo;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} mpls_sr_main_t;

mpls_sr_main_t sr_mpls_main;

int
sr_mpls_policy_add (mpls_label_t bsid, mpls_label_t * segments,
         u8 behavior, u32 fib_table, u32 weight);

int
sr_mpls_policy_mod (mpls_label_t bsid, u32 index, u32 fib_table,
         u8 operation, mpls_label_t * segments, u32 sl_index, u32 weight);

int
sr_mpls_policy_del (mpls_label_t bsid, u32 index);

#endif /* included_vnet_sr_mpls_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
