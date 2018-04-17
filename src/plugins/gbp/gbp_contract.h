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
    u64 as_u64;
  };
} gbp_contract_key_t;

/**
 * The value for an Contract
 */
typedef struct gbp_contract_value_t_
{
  union
  {
    struct
    {
      /**
       * lookup context and acl index
       */
      u32 gc_lc_index;
      u32 gc_acl_index;
    };
    u64 as_u64;
  };
} gbp_contract_value_t;

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
  gbp_contract_value_t gc_value;
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

extern void gbp_contract_update (epg_id_t src_epg,
				 epg_id_t dst_epg, u32 acl_index);
extern void gbp_contract_delete (epg_id_t src_epg, epg_id_t dst_epg);

typedef int (*gbp_contract_cb_t) (gbp_contract_t * gbpe, void *ctx);
extern void gbp_contract_walk (gbp_contract_cb_t bgpe, void *ctx);


/**
 * DP functions and databases
 */
extern gbp_contract_db_t gbp_contract_db;

always_inline u64
gbp_acl_lookup (gbp_contract_key_t * key)
{
  uword *p;

  p = hash_get (gbp_contract_db.gc_hash, key->as_u64);

  if (NULL != p)
    return (p[0]);

  return (~0);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
