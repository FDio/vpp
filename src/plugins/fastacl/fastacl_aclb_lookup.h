/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 FastNetMon (fastnetmon.com)
 */

#ifndef __included_fastacl_aclb_lookup_h__
#define __included_fastacl_aclb_lookup_h__

#include <fastacl/fastacl_aclb.h>

static_always_inline int
fastacl_aclb_accept (fastacl_aclb_check_ctx_t *c, u32 ace_index)
{
  if (c->exact && !c->fsm->aclb.ace_recheck[ace_index])
    return 1;
  return fastacl_aclb_check (c, ace_index);
}

static_always_inline u32
fastacl_aclb_hash_match (acl_main_t *am, fa_5tuple_t *match, int is_ip6,
			 fastacl_aclb_check_ctx_t *c)
{
  u32 lc_index = match->pkt.lc_index;
  applied_hash_ace_entry_t *aces = *vec_elt_at_index (am->hash_entry_vec_by_lc_index, lc_index);
  hash_applied_mask_info_t *minfos =
    *vec_elt_at_index (am->hash_applied_mask_info_vec_by_lc_index, lc_index);
  clib_bihash_kv_48_8_t kv, result;
  fa_5tuple_t *kv_key = (fa_5tuple_t *) kv.key;
  hash_acl_lookup_value_t *result_val = (hash_acl_lookup_value_t *) &result.value;
  u32 best = ~0 - 1;

  for (int o = 0; o < vec_len (minfos); o++)
    {
      hash_applied_mask_info_t *minfo = &minfos[o];
      ace_mask_type_entry_t *mte;
      collision_match_rule_t *crs;
      fa_packet_info_t pkt;
      u64 *pmatch = (u64 *) match, *pmask, *pkey = (u64 *) kv.key;

      if (minfo->first_rule_index > best)
	break;
      mte = vec_elt_at_index (am->ace_mask_type_pool, minfo->mask_type_index);
      pmask = (u64 *) &mte->mask;
      for (int w = 0; w < 6; w++)
	pkey[w] = pmatch[w] & pmask[w];
      pkt = kv_key->pkt;
      pkt.mask_type_index_lsb = minfo->mask_type_index;
      kv_key->pkt.as_u64 = pkt.as_u64;
      if (clib_bihash_search_inline_2_48_8 (&am->acl_lookup_hash, &kv, &result))
	continue;
      crs = vec_elt_at_index (aces, result_val->applied_entry_index)->colliding_rules;
      for (int i = 0; i < vec_len (crs); i++)
	if (crs[i].applied_entry_index < best &&
	    single_rule_match_5tuple (&crs[i].rule, is_ip6, match) &&
	    fastacl_aclb_accept (c, aces[crs[i].applied_entry_index].ace_index))
	  best = crs[i].applied_entry_index;
    }
  return best < vec_len (aces) ? aces[best].ace_index : ~0;
}

static_always_inline u32
fastacl_aclb_linear_match (acl_main_t *am, u32 acl_index, fa_5tuple_t *match, int is_ip6,
			   fastacl_aclb_check_ctx_t *c)
{
  acl_rule_t *rules;

  if (pool_is_free_index (am->acls, acl_index))
    return ~0;
  rules = am->acls[acl_index].rules;
  for (u32 i = 0; i < vec_len (rules); i++)
    if (single_rule_match_5tuple (&rules[i], is_ip6, match) && fastacl_aclb_accept (c, i))
      return i;
  return ~0;
}

static_always_inline u32
fastacl_aclb_match (fastacl_aclb_t *ab, fa_5tuple_t *match, int is_ip6, fastacl_aclb_check_ctx_t *c)
{
  acl_main_t *am = ab->methods.p_acl_main;

  match->pkt.lc_index = ab->lc_index;
  if (PREDICT_TRUE (am->use_hash_acl_matching))
    return fastacl_aclb_hash_match (am, match, is_ip6, c);
  return fastacl_aclb_linear_match (am, ab->acl_index, match, is_ip6, c);
}

#endif /* __included_fastacl_aclb_lookup_h__ */
