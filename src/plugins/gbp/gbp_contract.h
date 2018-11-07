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

#ifndef __GBP_CONTRACT_H__
#define __GBP_CONTRACT_H__

#include <plugins/gbp/gbp_types.h>

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
    u32 as_u32;
  };
} gbp_contract_key_t;

typedef struct gbp_next_hop_t_
{
  ip46_address_t gnh_ip;
  mac_address_t gnh_mac;
} gbp_next_hop_t;

typedef enum gbp_hash_mode_t_
{
  GBP_HASH_MODE_SRC_IP,
  GBP_HASH_MODE_DST_IP,
} gbp_hash_mode_t;

typedef struct gbp_next_hop_set_t_
{
  gbp_hash_mode_t gnhs_hash_mode;
  gbp_next_hop_t *gnhs_nhs;
} gbp_next_hop_set_t;

typedef enum gbp_rule_result_t_
{
  CBP_RULE_PERMIT,
  CBP_RULE_DENY,
  CBP_RULE_REDIRECT,
} gbp_rule_result_t;

typedef struct gbp_rule_t_
{
  gbp_rule_result_t gu_result;
  gbp_next_hop_set_t gu_nh_set;
} gbp_rule_t;

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

  u32 gc_acl_index;
  u32 gc_lc_index;

  /**
   * The ACL to apply for packets from the source to the destination EPG
   */
  gbp_rule_t *gc_rules;
} gbp_contract_t;

/**
 * EPG src,dst pair to ACL mapping table, aka contract DB
 */
typedef struct gbp_contract_db_t_
{
  /**
   * We can form a u64 key from the pair, so use a simple hash table
   */
  uword *gc_hash;
} gbp_contract_db_t;

extern int gbp_contract_update (epg_id_t src_epg,
				epg_id_t dst_epg,
				u32 acl_index, gbp_rule_t * rultes);
extern int gbp_contract_delete (epg_id_t src_epg, epg_id_t dst_epg);

typedef int (*gbp_contract_cb_t) (gbp_contract_t * gbpe, void *ctx);
extern void gbp_contract_walk (gbp_contract_cb_t bgpe, void *ctx);

extern u8 *format_gbp_contract (u8 * s, va_list * args);

/**
 * DP functions and databases
 */
extern gbp_contract_db_t gbp_contract_db;

always_inline index_t
gbp_contract_find (gbp_contract_key_t * key)
{
  uword *p;

  p = hash_get (gbp_contract_db.gc_hash, key->as_u32);

  if (NULL != p)
    return (p[0]);

  return (INDEX_INVALID);
}

extern gbp_contract_t *gbp_contract_pool;

always_inline gbp_contract_t *
gbp_contract_get (index_t gci)
{
  return (pool_elt_at_index (gbp_contract_pool, gci));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
