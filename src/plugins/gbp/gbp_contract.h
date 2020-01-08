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

#include <plugins/gbp/gbp.h>
#include <plugins/gbp/gbp_types.h>

#include <vnet/match/match_set.h>
#include <vnet/match/match_engine.h>

#define foreach_gbp_contract_error                         \
  _(ALLOW_NO_SCLASS,    "allow-no-sclass")                 \
  _(ALLOW_INTRA,        "allow-intra-sclass")              \
  _(ALLOW_A_BIT,        "allow-a-bit-set")                 \
  _(ALLOW_SCLASS_1,     "allow-sclass-1")                  \
  _(ALLOW_CONTRACT,     "allow-contract")                  \
  _(DROP_CONTRACT,      "drop-contract")                   \
  _(DROP_ETHER_TYPE,    "drop-ether-type")                 \
  _(DROP_NO_CONTRACT,   "drop-no-contract")                \
  _(DROP_NO_DCLASS,     "drop-no-dclass")                  \
  _(DROP_NO_RULE,       "drop-no-rule")

typedef enum
{
#define _(sym,str) GBP_CONTRACT_ERROR_##sym,
  foreach_gbp_contract_error
#undef _
    GBP_CONTRACT_N_ERROR,
#define GBP_CONTRACT_N_ERROR GBP_CONTRACT_N_ERROR
} gbp_contract_error_t;

extern char *gbp_contract_error_strings[GBP_CONTRACT_N_ERROR];

/**
 * The key for an Contract
 */
typedef struct gbp_contract_key_t_
{
  union
  {
    struct
    {
      gbp_scope_t gck_scope;
      /**
       * source and destination EPGs for which the ACL applies
       */
      sclass_t gck_src;
      sclass_t gck_dst;
    };
    u64 as_u64;
  };
} gbp_contract_key_t;

typedef struct gbp_next_hop_t_
{
  fib_node_t gnh_node;
  ip46_address_t gnh_ip;
  mac_address_t gnh_mac;
  index_t gnh_gu;
  index_t gnh_bd;
  index_t gnh_rd;
  u32 gnh_ge;
  u32 gnh_sibling;
  index_t gnh_ai[FIB_PROTOCOL_IP_MAX];
} gbp_next_hop_t;

#define foreach_gbp_hash_mode	\
  _(SRC_IP, "src-ip")		\
  _(DST_IP, "dst-ip")		\
  _(SYMMETRIC, "symmetric")

typedef enum gbp_hash_mode_t_
{
#define _(v,s) GBP_HASH_MODE_##v,
  foreach_gbp_hash_mode
#undef _
} gbp_hash_mode_t;

#define foreach_gbp_rule_action   \
  _(PERMIT,   "permit")           \
  _(DENY,     "deny")             \
  _(REDIRECT, "redirect")

typedef enum gbp_rule_action_t_
{
#define _(v,s) GBP_RULE_##v,
  foreach_gbp_rule_action
#undef _
} gbp_rule_action_t;

#define foreach_gbp_policy_node   \
  _(L2, "L2")                     \
  _(IP4, "ip4")                   \
  _(IP6, "ip6")

typedef enum gbp_policy_node_t_
{
#define _(v,s) GBP_POLICY_NODE_##v,
  foreach_gbp_policy_node
#undef _
} gbp_policy_node_t;
#define GBP_POLICY_N_NODES (GBP_POLICY_NODE_IP6+1)

#define FOR_EACH_GBP_POLICY_NODE(pnode)         \
  for (pnode = GBP_POLICY_NODE_L2; pnode < GBP_POLICY_N_NODES; pnode++)

typedef struct gbp_rule_t_
{
  match_rule_t gu_match;
  gbp_rule_action_t gu_action;
  gbp_hash_mode_t gu_hash_mode;
  index_t *gu_nhs;

  /**
   * DPO of the load-balance object used to redirect
   */
  dpo_id_t gu_dpo[GBP_POLICY_N_NODES][FIB_PROTOCOL_IP_MAX];
} gbp_rule_t;

/**
 * A Group Based Policy Contract.
 *  Determines the match-set that applies to traffic pass between two endpoint groups
 */
typedef struct gbp_contract_t_
{
  /**
   * source and destination EPGs
   */
  gbp_contract_key_t gc_key;

  match_list_t gc_ml;
  match_handle_t gc_hdl;
  match_set_app_t gc_app[GBP_POLICY_N_NODES];
  index_t gc_set;

  /**
   * The actions to apply for packets from the source to the destination EPG
   */
  index_t *gc_rules;

  /**
   * An ethertype whitelist
   */
  u16 *gc_allowed_ethertypes;
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

extern int gbp_contract_update (gbp_scope_t scope,
				sclass_t sclass,
				sclass_t dclass,
				index_t * rules,
				u16 * allowed_ethertypes, u32 * stats_index);
extern int gbp_contract_delete (gbp_scope_t scope, sclass_t sclass,
				sclass_t dclass);

extern index_t gbp_rule_alloc (gbp_rule_action_t action,
			       gbp_hash_mode_t hash_mode,
			       const match_rule_t * match, index_t * nhs);
extern void gbp_rule_free (index_t gui);
extern index_t gbp_next_hop_alloc (const ip46_address_t * ip,
				   index_t grd,
				   const mac_address_t * mac, index_t gbd);

typedef int (*gbp_contract_cb_t) (gbp_contract_t * gbpe, void *ctx);
extern void gbp_contract_walk (gbp_contract_cb_t bgpe, void *ctx);

extern u8 *format_gbp_rule_action (u8 * s, va_list * args);
extern u8 *format_gbp_contract (u8 * s, va_list * args);

/**
 * DP functions and databases
 */
extern gbp_contract_db_t gbp_contract_db;

always_inline index_t
gbp_contract_find (gbp_contract_key_t * key)
{
  uword *p;

  p = hash_get (gbp_contract_db.gc_hash, key->as_u64);

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

extern gbp_rule_t *gbp_rule_pool;

always_inline gbp_rule_t *
gbp_rule_get (index_t gui)
{
  return (pool_elt_at_index (gbp_rule_pool, gui));
}

extern vlib_combined_counter_main_t gbp_contract_permit_counters;
extern vlib_combined_counter_main_t gbp_contract_drop_counters;

typedef enum
{
  GBP_CONTRACT_APPLY_L2,
  GBP_CONTRACT_APPLY_IP4,
  GBP_CONTRACT_APPLY_IP6,
} gbp_contract_apply_type_t;

static_always_inline gbp_rule_action_t
gbp_contract_apply (vlib_main_t * vm, gbp_policy_node_t pnode,
		    gbp_contract_key_t * key, vlib_buffer_t * b,
		    gbp_rule_t ** rule, u32 * intra, u32 * sclass1,
		    u32 * acl_match, u32 * rule_match,
		    gbp_contract_error_t * err)
{
  const gbp_contract_t *contract;
  match_set_result_t result;
  index_t contract_index;
  u16 etype;

  *rule = 0;

  if (key->gck_src == key->gck_dst)
    {
      /* intra-epg allowed */
      (*intra)++;
      *err = GBP_CONTRACT_ERROR_ALLOW_INTRA;
      return GBP_RULE_PERMIT;
    }

  if (1 == key->gck_src || 1 == key->gck_dst)
    {
      /* sclass 1 allowed */
      (*sclass1)++;
      *err = GBP_CONTRACT_ERROR_ALLOW_SCLASS_1;
      return GBP_RULE_PERMIT;
    }

  /* look for contract */
  contract_index = gbp_contract_find (key);
  if (INDEX_INVALID == contract_index)
    {
      *err = GBP_CONTRACT_ERROR_DROP_NO_CONTRACT;
      return GBP_RULE_DENY;
    }

  contract = gbp_contract_get (contract_index);

  *err = GBP_CONTRACT_ERROR_DROP_CONTRACT;

  if (GBP_POLICY_NODE_L2 == pnode)
    {
      /* check ethertype */
      etype = ((u16 *) (vlib_buffer_get_current (b) +
			vnet_buffer (b)->l2.l2_len))[-1];

      if (~0 == vec_search (contract->gc_allowed_ethertypes, etype))
	{
	  *err = GBP_CONTRACT_ERROR_DROP_ETHER_TYPE;
	  goto contract_deny;
	}
    }

  /* check ACL */
  contract->gc_app[pnode].msa_match
    (vm, b, &contract->gc_app[pnode], 0, &result);

  if (MATCH_RESULT_MISS != result.msr_pos.msp_rule_index)
    goto contract_deny;

  if (PREDICT_FALSE
      (result.msr_pos.msp_rule_index >= vec_len (contract->gc_rules)))
    {
      *err = GBP_CONTRACT_ERROR_DROP_NO_RULE;
      goto contract_deny;
    }

  *rule = gbp_rule_get (contract->gc_rules[result.msr_pos.msp_rule_index]);
  switch ((*rule)->gu_action)
    {
    case GBP_RULE_PERMIT:
    case GBP_RULE_REDIRECT:
      *err = GBP_CONTRACT_ERROR_ALLOW_CONTRACT;
      vlib_increment_combined_counter (&gbp_contract_permit_counters,
				       vm->thread_index, contract_index, 1,
				       vlib_buffer_length_in_chain (vm, b));
      return (*rule)->gu_action;
    case GBP_RULE_DENY:
      break;
    }

contract_deny:
  vlib_increment_combined_counter (&gbp_contract_drop_counters,
				   vm->thread_index, contract_index, 1,
				   vlib_buffer_length_in_chain (vm, b));
  return GBP_RULE_DENY;
}

#endif /* __GBP_CONTRACT_H__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
