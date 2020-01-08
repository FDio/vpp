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

#include <vnet/match/engines/linear/match_linear_dp.h>

match_engine_linear_t *match_engine_linear_pool;
match_engine_linear_per_thread_t *match_engine_linear_per_thread;

/* *INDENT-OFF* */
static match_match_t match_linear_arp_fns[MATCH_N_TYPES][MATCH_BOTH] = {
  [MATCH_TYPE_MASK_IP_MAC] = {
    [MATCH_SRC] = match_engine_linear_match_mask_ip_mac_src_arp,
    [MATCH_DST] = match_engine_linear_match_mask_ip_mac_dst_arp,
  },
};

static match_match_t match_linear_ip4_fns[MATCH_N_TYPES][MATCH_BOTH + 1] = {
  [MATCH_TYPE_MASK_IP_MAC] = {
    [MATCH_SRC] = match_engine_linear_match_mask_ip_mac_src_ip4,
    [MATCH_DST] = match_engine_linear_match_mask_ip_mac_dst_ip4,
  },
  [MATCH_TYPE_MASK_N_TUPLE] = {
    [MATCH_SRC] = match_engine_linear_match_mask_n_tuple_ip4,
    [MATCH_DST] = match_engine_linear_match_mask_n_tuple_ip4,
    [MATCH_BOTH] = match_engine_linear_match_mask_n_tuple_ip4,
  },
  [MATCH_TYPE_MASK_IP] = {
    [MATCH_SRC] = match_engine_linear_match_mask_ip_src_ip4,
    [MATCH_DST] = match_engine_linear_match_mask_ip_dst_ip4,
  },
  [MATCH_TYPE_EXACT_IP] = {
    [MATCH_SRC] = match_engine_linear_match_exact_ip_src_ip4,
    [MATCH_DST] = match_engine_linear_match_exact_ip_dst_ip4,
  },
  [MATCH_TYPE_EXACT_IP_L4] = {
    [MATCH_SRC] = match_engine_linear_match_exact_ip_l4_src_ip4,
    [MATCH_DST] = match_engine_linear_match_exact_ip_l4_dst_ip4,
  },
  [MATCH_TYPE_SETS] = {
    [MATCH_SRC] = match_engine_linear_match_sets,
    [MATCH_DST] = match_engine_linear_match_sets,
    [MATCH_BOTH] = match_engine_linear_match_sets,
  },
};

static match_match_t match_linear_ip6_fns[MATCH_N_TYPES][MATCH_BOTH + 1] = {
  [MATCH_TYPE_MASK_IP_MAC] = {
    [MATCH_SRC] = match_engine_linear_match_mask_ip_mac_src_ip6,
    [MATCH_DST] = match_engine_linear_match_mask_ip_mac_dst_ip6,
  },
  [MATCH_TYPE_MASK_N_TUPLE] = {
    [MATCH_SRC] = match_engine_linear_match_mask_n_tuple_ip6,
    [MATCH_DST] = match_engine_linear_match_mask_n_tuple_ip6,
    [MATCH_BOTH] = match_engine_linear_match_mask_n_tuple_ip6,
  },
  [MATCH_TYPE_MASK_IP] = {
    [MATCH_SRC] = match_engine_linear_match_mask_ip_src_ip6,
    [MATCH_DST] = match_engine_linear_match_mask_ip_dst_ip6,
  },
  [MATCH_TYPE_EXACT_IP] = {
    [MATCH_SRC] = match_engine_linear_match_exact_ip_src_ip6,
    [MATCH_DST] = match_engine_linear_match_exact_ip_dst_ip6,
  },
  [MATCH_TYPE_EXACT_IP_L4] = {
    [MATCH_SRC] = match_engine_linear_match_exact_ip_l4_src_ip6,
    [MATCH_DST] = match_engine_linear_match_exact_ip_l4_dst_ip6,
  },
  [MATCH_TYPE_SETS] = {
    [MATCH_SRC] = match_engine_linear_match_sets,
    [MATCH_DST] = match_engine_linear_match_sets,
    [MATCH_BOTH] = match_engine_linear_match_sets,
  },
};
/* *INDENT-ON* */

/**
 * Since we apply set recursively the linear engine pool is likely to realloc
 */
typedef struct match_linear_ctx_t_
{
  index_t meli;
} match_linear_ctx_t;

static walk_rc_t
match_linear_build_set_rules (const match_rule_t * mr, void *data)
{
  match_engine_linear_set_t *mel_set;
  match_linear_ctx_t *ctx = data;
  match_engine_linear_t *mel;
  match_orientation_t mo;

  mel = pool_elt_at_index (match_engine_linear_pool, ctx->meli);
  vec_add2 (mel->mel_sets, mel_set, 1);

  mel_set->mels_res = mr->mr_result;

  FOR_EACH_MATCH_ORIENTATION (mo)
  {
    mel_set->mels_set[mo] = mr->mr_sets.mss_set[mo];

    if (INDEX_INVALID != mel_set->mels_set[mo])
      {
	match_set_lock (mel_set->mels_set[mo]);
	match_set_apply (mel_set->mels_set[mo],
			 MATCH_SEMANTIC_ANY,
			 mel->mel_flags, &mel_set->mels_app[mo]);
      }
  }

  return (WALK_CONTINUE);
}

static walk_rc_t
match_linear_build_set_entry (const match_set_entry_t * mse,
			      u32 index, void *data)
{
  match_set_entry_walk_rules (mse, match_linear_build_set_rules, data);

  return (WALK_CONTINUE);
}

static walk_rc_t
match_linear_build_rule (const match_rule_t * mr, void *ctx)
{
  match_engine_linear_t *mel = ctx;

  match_list_push_back (&mel->mel_list, mr);

  return (WALK_CONTINUE);
}

static walk_rc_t
match_linear_build_entry (const match_set_entry_t * mse, u32 index, void *ctx)
{
  match_set_entry_walk_rules (mse, match_linear_build_rule, ctx);

  return (WALK_CONTINUE);
}

static void
match_linear_apply_i (match_engine_linear_t * mel, match_set_t * ms)
{
  if (MATCH_TYPE_SETS == ms->ms_type)
    {
      /* Apply each of the sets for the rules.
       * do so with ANY semantics, since what we want to know is if
       * anything in the set matches
       */
      match_orientation_t mo;

      if (match_set_size (ms))
	{
	  /* initiate the per-thread data for the DP */
	  match_engine_linear_per_thread_t *ptd;

	  vec_foreach (ptd, match_engine_linear_per_thread)
	  {
	    FOR_EACH_MATCH_ORIENTATION (mo)
	    {
	      vec_validate_init_empty (ptd->melptd_res[mo],
				       match_set_size (ms) - 1,
				       MATCH_RESULT_MISS);
	      vec_validate_init_empty (ptd->melptd_match[mo],
				       match_set_size (ms) - 1, false);
	      clib_bitmap_validate (ptd->melptd_match[mo],
				    match_set_size (ms) - 1);
	    }
	  }

	  match_linear_ctx_t ctx = {
	    .meli = mel - match_engine_linear_pool,
	  };

	  /* copy the rules into private data with the set-application */
	  match_set_walk_entries (ms, match_linear_build_set_entry, &ctx);
	}
    }
  else
    {
      /*
       * flatten the set's many entries with lists into a single long list
       * which is more efficient to walk
       */
      match_list_init (&mel->mel_list, NULL, match_set_size (ms));
      match_set_walk_entries (ms, match_linear_build_entry, mel);
    }
}

static void
match_linear_apply (match_set_t * ms,
		    match_semantic_t msem,
		    match_set_tag_flags_t flags, match_set_app_t * msa)
{
  match_engine_linear_t *mel;
  index_t meli;

  pool_get_zero (match_engine_linear_pool, mel);

  meli = mel - match_engine_linear_pool;
  mel->mel_set = match_set_get_index (ms);
  mel->mel_flags = flags;
  match_list_init (&mel->mel_list, NULL, 0);

  switch (ms->ms_eth_type)
    {
    case ETHERNET_TYPE_IP4:
      msa->msa_match = match_linear_ip4_fns[ms->ms_type][ms->ms_orientation];
      break;
    case ETHERNET_TYPE_IP6:
      msa->msa_match = match_linear_ip6_fns[ms->ms_type][ms->ms_orientation];
      break;
    case ETHERNET_TYPE_ARP:
      msa->msa_match = match_linear_arp_fns[ms->ms_type][ms->ms_orientation];
      break;
    default:
      break;
    }

  match_linear_apply_i (mel, ms);
  ASSERT (msa->msa_match);

  msa->msa_index = meli;
}

static void
match_linear_teardown (match_engine_linear_t * mel, match_set_t * ms)
{
  match_engine_linear_set_t *mel_set;
  match_orientation_t mo;

  /*
   * delete all the applications of the sets (in the rules)
   */
  FOR_EACH_MATCH_ORIENTATION (mo)
  {
    vec_foreach (mel_set, mel->mel_sets)
    {
      if (match_set_app_is_valid (&mel_set->mels_app[mo]))
	{
	  match_set_unapply (mel_set->mels_set[mo], &mel_set->mels_app[mo]);
	  match_set_unlock (&mel_set->mels_set[mo]);
	}
    }
  }

  match_list_free (&mel->mel_list);
}

static void
match_linear_unapply (match_set_t * ms, const match_set_app_t * msa)
{
  match_engine_linear_t *mel;

  mel = pool_elt_at_index (match_engine_linear_pool, msa->msa_index);

  match_linear_teardown (mel, ms);

  pool_put_index (match_engine_linear_pool, msa->msa_index);
}

/**
 * Treat all list updates the same - destroy and rebuild everything
 * a bit clunky - we can do better, but we are only dealing with samll
 * list sizes with this list engines, so it's not imperative.
 *
 */
static void
match_linear_list_update (match_set_t * ms,
			  index_t msei, const match_set_app_t * msa)
{
  match_engine_linear_t *mel;

  mel = pool_elt_at_index (match_engine_linear_pool, msa->msa_index);

  match_linear_teardown (mel, ms);
  match_linear_apply_i (mel, ms);
}

static u8 *
format_match_linear (u8 * s, va_list * args)
{
  index_t meli = va_arg (*args, index_t);

  /* match_engine_linear_t *mel; */

  /* mel = pool_elt_at_index (match_engine_linear_pool, meli); */

  s = format (s, "[%d] linear", meli);

  return (s);
}

static clib_error_t *
match_linear_init (vlib_main_t * vm)
{
  /**
   * The linear engine is good when the list size is small,
   * but terrible when long.
   */
  match_engine_priority_t mep, *meps = NULL;

  mep.len = 32;
  mep.prio = 20;
  vec_add1 (meps, mep);

  mep.len = 64;
  mep.prio = 100;
  vec_add1 (meps, mep);

  mep.len = 256;
  mep.prio = 500;
  vec_add1 (meps, mep);

  /*
   * The linear matcher can do all match types and semantics
   */
#define _(a,b)                                                          \
  const static match_engine_vft_t ml_vft_##a = {                        \
    .mev_apply = match_linear_apply,                                    \
    .mev_unapply = match_linear_unapply,                                \
    .mev_format = format_match_linear,                                  \
    .mev_list_actions = {                                               \
      [MATCH_ENGINE_LIST_ADD] = match_linear_list_update,               \
      [MATCH_ENGINE_LIST_REPLACE] = match_linear_list_update,           \
      [MATCH_ENGINE_LIST_DELETE] = match_linear_list_update,            \
    },                                                                  \
  };                                                                    \
  match_engine_register ("linear", MATCH_TYPE_##a,                      \
                         MATCH_SEMANTIC_ANY, &ml_vft_##a, meps);        \
  match_engine_register ("linear", MATCH_TYPE_##a,                      \
                         MATCH_SEMANTIC_FIRST, &ml_vft_##a, meps);
  foreach_match_type
#undef _
    vec_free (meps);

  vlib_thread_main_t *tm = vlib_get_thread_main ();

  vec_validate (match_engine_linear_per_thread, tm->n_vlib_mains);

  return (NULL);
}

VLIB_INIT_FUNCTION (match_linear_init) =
{
.runs_after = VLIB_INITS ("match_init"),};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
