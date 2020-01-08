/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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


#include <vnet/match/match_engine.h>
#include <vnet/match/match_set_dp.h>
#include <vnet/match/engines/classifier/match_classifier.h>
#include <vnet/match/engines/classifier/match_classifier_mask_n_tuple_dp.h>

#include <vnet/ethernet/arp_packet.h>
#include <vnet/ip/ip.h>

match_classifier_engine_t *match_classifier_engine_pool;
match_classifier_session_t *match_classifier_session_pool;
match_classifier_clash_t *match_classifier_clash_pool;
match_classifier_clash_head_t *match_classifier_clash_head_pool;
match_classifier_list_t *match_classifier_list_pool;
match_classifier_rule_t *match_classifier_rule_pool;

static match_classifier_mask_vft_t match_classifier_vfts[MATCH_N_TYPES];

typedef struct match_classifier_ctx_t_
{
  match_set_pos_t mcc_pos;
  match_classifier_engine_t *mcc_engine;
  match_classifier_list_t *mcc_list;
} match_classifier_ctx_t;

static match_classifier_mask_vft_t *
match_classifier_vft_get (match_type_t mtype)
{
  return (&match_classifier_vfts[mtype]);
}

void
match_classifier_mask_register (match_type_t mtype,
				const match_classifier_mask_vft_t * vft)
{
  match_classifier_vfts[mtype] = *vft;
}

static u8 *
format_match_classifier_mask_class (u8 * s, va_list * args)
{
  match_classifier_mask_class_t *mcmc;
  const match_classifier_mask_vft_t *mcv;
  index_t mcmci = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);

  mcmc = pool_elt_at_index (match_classifier_mask_class_pool, mcmci);
  mcv = match_classifier_vft_get (mcmc->mcmc_type);

  s = format (s, "%U[%d] class: locks:%d table:%d best:[%U]",
	      format_white_space, indent,
	      mcmci,
	      mcmc->mcmc_locks,
	      mcmc->mcmc_table, format_match_set_pos, &mcmc->mcmc_best);

  s = format (s, "\n%U", mcv->mcv_format_key, &mcmc->mcmc_key, indent + 2);
  s = format (s, "\n%U  %U", format_white_space, indent, format_hex_bytes,
	      mcmc->mcmc_data, vec_len (mcmc->mcmc_data));

  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_vnet_classify_table, &vnet_classify_main, 0,
	      mcmc->mcmc_table);

  return (s);
}

static u8 *
format_match_classifier_session (u8 * s, va_list * args)
{
  match_classifier_session_t *mcs;
  index_t mcsi = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);

  mcs = pool_elt_at_index (match_classifier_session_pool, mcsi);

  s = format (s, "%U[%d] session:", format_white_space, indent, mcsi);
  s = format (s, "\n%Umask:%d pos:[%U} result:[%U]",
	      format_white_space, indent + 2,
	      mcs->mcs_mask,
	      format_match_set_pos, &mcs->mcs_pos,
	      format_match_result, mcs->mcs_result);
  s = format (s, "\n%U  %U",
	      format_white_space, indent + 2,
	      format_hex_bytes, mcs->mcs_data, vec_len (mcs->mcs_data));
  return (s);
}

static u8 *
format_match_classifier_rule (u8 * s, va_list * args)
{
  match_classifier_rule_t *mcr;
  index_t mcri = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);
  index_t *mcsi;

  mcr = pool_elt_at_index (match_classifier_rule_pool, mcri);

  s = format (s, "%U[%d] rule:",
	      format_white_space, indent,
	      mcri, format_match_rule, &mcr->mcr_rule, indent + 2);

  vec_foreach (mcsi, mcr->mcr_sessions)
    s =
    format (s, "\n%U", format_match_classifier_session, *mcsi, indent + 4);

  return (s);
}

static u8 *
format_match_classifier_list (u8 * s, va_list * args)
{
  match_classifier_list_t *mcl;
  index_t mcli = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);
  index_t *mcri;

  mcl = pool_elt_at_index (match_classifier_list_pool, mcli);

  s = format (s, "%U[%d] list:", format_white_space, indent, mcli);

  vec_foreach (mcri, mcl->mcl_rules)
    s = format (s, "\n%U", format_match_classifier_rule, *mcri, indent + 2);

  return (s);
}

void
match_classifier_mask_class_unlock (index_t * mcmci)
{
  match_classifier_mask_class_t *mcmc;

  mcmc = pool_elt_at_index (match_classifier_mask_class_pool, *mcmci);
  mcmc->mcmc_locks--;

  if (0 == mcmc->mcmc_locks)
    {
      match_classifier_engine_t *mce;

      mce =
	pool_elt_at_index (match_classifier_engine_pool, mcmc->mcmc_engine);

      hash_unset (mce->mce_masks, &mcmc->mcmc_key);

      vnet_classify_delete_table_index (&vnet_classify_main, mcmc->mcmc_table,
					0);

      vec_free (mcmc->mcmc_data);
      pool_put (match_classifier_mask_class_pool, mcmc);
    }

  *mcmci = INDEX_INVALID;
}

index_t
match_classifier_mask_class_add_or_lock (match_type_t mtype,
					 match_classifier_engine_t * mce,
					 const
					 match_classifier_mask_class_key_t *
					 mcmck, const match_set_pos_t * msp)
{
  match_classifier_mask_class_t *mcmc;
  index_t mcmci;
  uword *p;

  p = hash_get (mce->mce_masks, mcmck);

  if (p)
    {
      mcmci = p[0];
      mcmc = pool_elt_at_index (match_classifier_mask_class_pool, mcmci);
    }
  else
    {
      match_classifier_mask_vft_t *mcv;

      mcv = match_classifier_vft_get (mtype);

      pool_get_zero (match_classifier_mask_class_pool, mcmc);

      mcmci = mcmc - match_classifier_mask_class_pool;
      mcmc->mcmc_key = *mcmck;
      mcmc->mcmc_engine = (mce - match_classifier_engine_pool);
      mcmc->mcmc_best = MATCH_SET_POS_MISS;
      mcmc->mcmc_type = mtype;

      /* we'll delay the creation of the table until we know how many
       * sessions it needs */
      mcmc->mcmc_table = ~0;

      mcmc->mcmc_data = mcv->mcv_mk_class_data (&mcmc->mcmc_key);
      mcmc->mcmc_data = match_classifier_pad (mcmc->mcmc_data);

      hash_set (mce->mce_masks, &mcmc->mcmc_key, mcmci);
    }

  mcmc->mcmc_locks++;

  /* less => earlier => better */
  if (match_set_pos_is_better (msp, &mcmc->mcmc_best))
    match_set_pos_copy (msp, &mcmc->mcmc_best);

  return (mcmci);
}

static walk_rc_t
match_classifier_mk_walk_rules (const match_rule_t * mr, void *data)
{
  match_classifier_rule_t *mcr;
  match_classifier_mask_vft_t *mcv;
  match_classifier_ctx_t *ctx;

  ctx = data;
  mcv = match_classifier_vft_get (ctx->mcc_engine->mce_type);

  pool_get_zero (match_classifier_rule_pool, mcr);

  vec_add1 (ctx->mcc_list->mcl_rules, mcr - match_classifier_rule_pool);

  mcr->mcr_rule = *mr;

  ctx->mcc_pos.msp_rule_index = mr->mr_index;

  mcv->mcv_mk_sessions (mcr, &ctx->mcc_pos, ctx->mcc_engine);

  return (WALK_CONTINUE);
}

static walk_rc_t
match_classifier_mk_walk_entries (const match_set_entry_t * mse,
				  u32 index, void *data)
{
  match_classifier_list_t *mcl;

  pool_get_zero (match_classifier_list_pool, mcl);

  /* *INDENT-OFF* */
  match_classifier_ctx_t ctx = {
    .mcc_engine = data,
    .mcc_pos = {
      .msp_list_index = index,
      .msp_rule_index = ~0,
    },
    .mcc_list = mcl,
  };
  /* *INDENT-ON* */

  mcl->mcl_set_entry = mse - match_set_entry_pool;
  vec_add1 (ctx.mcc_engine->mce_lists, mcl - match_classifier_list_pool);

  ASSERT (vec_len (ctx.mcc_engine->mce_lists) - 1 == index);

  match_set_entry_walk_rules (mse, match_classifier_mk_walk_rules, &ctx);

  return (WALK_CONTINUE);
}

static int
match_classifier_mask_sort (void *s1, void *s2)
{
  const match_classifier_mask_class_t *mcmc1, *mcmc2;
  index_t *i1 = s1, *i2 = s2;
  int res;

  mcmc1 = pool_elt_at_index (match_classifier_mask_class_pool, *i1);
  mcmc2 = pool_elt_at_index (match_classifier_mask_class_pool, *i2);

  res = mcmc1->mcmc_best.msp_list_index - mcmc2->mcmc_best.msp_list_index;

  if (0 == res)
    res = mcmc1->mcmc_best.msp_rule_index - mcmc2->mcmc_best.msp_rule_index;

  return (res);
}

static int
match_classifier_clash_sort (void *v1, void *v2)
{
  match_classifier_clash_t *mcc1, *mcc2;
  index_t *mcci1 = v1, *mcci2 = v2;

  mcc1 = pool_elt_at_index (match_classifier_clash_pool, *mcci1);
  mcc2 = pool_elt_at_index (match_classifier_clash_pool, *mcci2);

  return (match_set_pos_is_better (&mcc1->mcc_pos, &mcc2->mcc_pos));
}

static void
match_classifier_session_add (index_t mcsi)
{
  match_classifier_mask_class_t *mcmc;
  match_classifier_session_t *mcs;
  vnet_classify_entry_t *vce;

  mcs = pool_elt_at_index (match_classifier_session_pool, mcsi);
  mcmc = pool_elt_at_index (match_classifier_mask_class_pool, mcs->mcs_mask);

  vce = match_classifier_find_session (mcmc->mcmc_table, mcs->mcs_data);

  if (INDEX_INVALID != mcs->mcs_clash)
    {
      match_classifier_clash_head_t *mcch;
      match_classifier_clash_t *mcc;

      mcc = pool_elt_at_index (match_classifier_clash_pool, mcs->mcs_clash);

      /*
       * Colliding rules. The rule has a port range that we cannot represent as
       * an exact mask. So we need to create a list of rules that will be
       * linearly search in the DP.
       */
      if (!vce)
	{
	  /* first session */
	  pool_get (match_classifier_clash_head_pool, mcch);

	  vec_add1 (mcch->mcch_clashes, mcs->mcs_clash);

	  match_classifier_session_vnet_add (mcmc->mcmc_table, mcs->mcs_data,
					     ~0,
					     mcch -
					     match_classifier_clash_head_pool);
	}
      else
	{
	  /*
	   * insert the clash, sorted by best first, into the list of clashes
	   */
	  mcch = pool_elt_at_index (match_classifier_clash_head_pool,
				    vce->next_index);

	  vec_add1 (mcch->mcch_clashes, mcs->mcs_clash);
	  vec_sort_with_function (mcch->mcch_clashes,
				  match_classifier_clash_sort);
	}

      mcc->mcc_head = (mcch - match_classifier_clash_head_pool);
    }
  else
    {
      match_classifier_session_vnet_add (mcmc->mcmc_table, mcs->mcs_data,
					 mcsi, ~0);
    }
}

static void
match_classifier_rule_add_sessions (index_t mcri)
{
  match_classifier_rule_t *mcr;
  index_t *mcsi;

  mcr = pool_elt_at_index (match_classifier_rule_pool, mcri);

  vec_foreach (mcsi, mcr->mcr_sessions) match_classifier_session_add (*mcsi);
}

static void
match_classifier_list_add_sessions (index_t mcli)
{
  match_classifier_list_t *mcl;
  index_t *mcri;

  mcl = pool_elt_at_index (match_classifier_list_pool, mcli);

  vec_foreach (mcri, mcl->mcl_rules)
    match_classifier_rule_add_sessions (*mcri);
}

static void
match_classifier_clash_head_unlock (index_t mcchi, index_t mcci)
{
  match_classifier_clash_head_t *mcch;
  u32 pos;

  mcch = pool_elt_at_index (match_classifier_clash_head_pool, mcchi);

  pos = vec_search (mcch->mcch_clashes, mcci);

  ASSERT (~0 != pos);

  /* delete preserving the oder */
  vec_delete (mcch->mcch_clashes, 1, pos);

  if (0 == vec_len (mcch->mcch_clashes))
    pool_put (match_classifier_clash_head_pool, mcch);
}

static void
match_classifier_clash_destroy (index_t mcci)
{
  match_classifier_clash_t *mcc;

  mcc = pool_elt_at_index (match_classifier_clash_pool, mcci);

  match_classifier_clash_head_unlock (mcc->mcc_head, mcci);

  pool_put (match_classifier_clash_pool, mcc);
}

static void
match_classifier_session_destroy (index_t mcsi)
{
  match_classifier_session_t *mcs;

  mcs = pool_elt_at_index (match_classifier_session_pool, mcsi);

  match_classifier_mask_class_unlock (&mcs->mcs_mask);

  vec_free (mcs->mcs_data);

  if (INDEX_INVALID != mcs->mcs_clash)
    match_classifier_clash_destroy (mcs->mcs_clash);

  pool_put (match_classifier_session_pool, mcs);
}

static void
match_classifier_rule_destroy (index_t mcri)
{
  match_classifier_rule_t *mcr;
  index_t *mcsi;

  mcr = pool_elt_at_index (match_classifier_rule_pool, mcri);

  vec_foreach (mcsi, mcr->mcr_sessions)
    match_classifier_session_destroy (*mcsi);

  vec_free (mcr->mcr_sessions);

  pool_put (match_classifier_rule_pool, mcr);
}

static void
match_classifier_list_destroy (index_t mcli)
{
  match_classifier_list_t *mcl;
  index_t *mcri;

  mcl = pool_elt_at_index (match_classifier_list_pool, mcli);

  vec_foreach (mcri, mcl->mcl_rules) match_classifier_rule_destroy (*mcri);

  vec_free (mcl->mcl_rules);

  pool_put (match_classifier_list_pool, mcl);
}

/**
 * Use the classifier sets to render the masek src IP and MAC match
 */
static void
match_classifier_apply_i (match_set_t * ms, match_classifier_engine_t * mce)
{
  /*
   * Translate ech rule in each entry into the correspnding masks and sessions
   */
  match_set_walk_entries (ms, match_classifier_mk_walk_entries, mce);

  if (hash_elts (mce->mce_masks) == 0)
    {
      /* someone applied an empty list */
      return;
    }

  /*
   * now we have the DB of all the masks and the number of sessions that use them
   * we can create the classifier tables
   */
  match_classifier_mask_class_key_t *mcmck;
  index_t mcmci, *mcmcip, *masks = NULL;

  /* *INDENT-OFF* */
  hash_foreach(mcmck, mcmci, mce->mce_masks,
  ({
    vec_add1(masks, mcmci);
  }));
  /* *INDENT-ON* */

  /* sort the vector.
   * the set of classifier sets created will be in a chain, a miss in the
   * (n)th  set results in a lookup in the (n+1)th.
   * So we want to sort the tables using the best rule that they contain. So once
   * we have a match, if we encounter a table whose best match is worse thant that,
   * then there are no better rules to match, and we're done
   */
  vec_sort_with_function (masks, match_classifier_mask_sort);

  /* The classifier tables are created in the reverse order to that which they are searched */
  u32 next_table_index = ~0;

  vec_foreach_backwards (mcmcip, masks)
  {
    match_classifier_mask_class_t *mcmc;

    mcmc = pool_elt_at_index (match_classifier_mask_class_pool, *mcmcip);

    next_table_index =
      mcmc->mcmc_table =
      match_classifier_table_vnet_add (mcmc->mcmc_data,
				       mcmc->mcmc_locks,
				       next_table_index,
				       mcmc->mcmc_best.msp_as_u64);
    ASSERT (mcmc->mcmc_table != INDEX_INVALID);
  }

  /*
   * Save the first table to search in the engine so we can get it in the DP
   */
  match_classifier_mask_class_t *mcmc;

  mcmc = pool_elt_at_index (match_classifier_mask_class_pool, masks[0]);

  mce->mce_table_index = mcmc->mcmc_table;

  vec_free (masks);

  /* for each entry/rule add its session to the appropriate classifier table */
  index_t *mcli;

  vec_foreach (mcli, mce->mce_lists)
    match_classifier_list_add_sessions (*mcli);
}

void
match_classifier_apply (match_set_t * ms,
			match_semantic_t msem,
			match_set_tag_flags_t flags, match_set_app_t * msa)
{
  const match_classifier_mask_vft_t *mcv;
  match_classifier_engine_t *mce;

  pool_get (match_classifier_engine_pool, mce);

  mce->mce_table_index = ~0;
  mce->mce_semantic = msem;
  mce->mce_type = ms->ms_type;
  mce->mce_tag_flags = flags;

  match_classifier_apply_i (ms, mce);

  msa->msa_index = mce - match_classifier_engine_pool;

  mcv = match_classifier_vft_get (ms->ms_type);
  msa->msa_match = (ETHERNET_TYPE_IP6 == ms->ms_eth_type ?
		    mcv->mcv_match[AF_IP6][msem] :
		    mcv->mcv_match[AF_IP4][msem]);
}

static void
match_classifier_teardown (match_classifier_engine_t * mce)
{
  index_t *mcli;

  vec_foreach (mcli, mce->mce_lists) match_classifier_list_destroy (*mcli);
  vec_free (mce->mce_lists);

  hash_free (mce->mce_masks);
}

void
match_classifier_unapply (match_set_t * ms, const match_set_app_t * msa)
{
  match_classifier_engine_t *mce;

  mce = pool_elt_at_index (match_classifier_engine_pool, msa->msa_index);

  match_classifier_teardown (mce);

  pool_put (match_classifier_engine_pool, mce);
}

void
match_classifier_update (match_set_t * ms, const match_set_app_t * msa)
{
  /* nothing clever here. destroy all state and start again */
  match_classifier_engine_t *mce;

  mce = pool_elt_at_index (match_classifier_engine_pool, msa->msa_index);

  match_classifier_teardown (mce);
  match_classifier_apply_i (ms, mce);
}

u8 *
format_match_classifier_engine (u8 * s, va_list * args)
{
  match_classifier_engine_t *mce;
  match_classifier_mask_class_key_t *mcmck;
  index_t mcmci, *mcli, mb;
  u32 indent;

  mb = va_arg (*args, index_t);
  indent = va_arg (*args, u32);

  mce = pool_elt_at_index (match_classifier_engine_pool, mb);

  s = format (s, "%Umatch-classifier: table:%d",
	      format_white_space, indent, mce->mce_table_index);

  /* *INDENT-OFF* */
  hash_foreach (mcmck, mcmci, mce->mce_masks,
  ({
    s = format (s, "\n%U",
                format_match_classifier_mask_class, mcmci, indent + 2);
  }));
  /* *INDENT-ON* */

  vec_foreach (mcli, mce->mce_lists)
    s = format (s, "\n%U", format_match_classifier_list, *mcli, indent + 2);

  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
