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

#include <vnet/match/engines/hash/match_hash_dp.h>

match_engine_hash_t *match_engine_hash_pool;

/* *INDENT-OFF* */
static match_match_t match_hash_ip4_fns[MATCH_N_TYPES][MATCH_BOTH + 1] = {

  [MATCH_TYPE_EXACT_IP] = {
    [MATCH_SRC] = match_engine_hash_match_exact_ip_src_ip4,
    [MATCH_DST] = match_engine_hash_match_exact_ip_dst_ip4,
  },
  [MATCH_TYPE_EXACT_IP_L4] = {
    [MATCH_SRC] = match_engine_hash_match_exact_ip_l4_src_ip4,
    [MATCH_DST] = match_engine_hash_match_exact_ip_l4_dst_ip4,
  },
};

static match_match_t match_hash_ip6_fns[MATCH_N_TYPES][MATCH_BOTH + 1] = {
  [MATCH_TYPE_EXACT_IP] = {
    [MATCH_SRC] = match_engine_hash_match_exact_ip_src_ip6,
    [MATCH_DST] = match_engine_hash_match_exact_ip_dst_ip6,
  },
  [MATCH_TYPE_EXACT_IP_L4] = {
    [MATCH_SRC] = match_engine_hash_match_exact_ip_l4_src_ip6,
    [MATCH_DST] = match_engine_hash_match_exact_ip_l4_dst_ip6,
  },
};
/* *INDENT-ON* */

static void
match_hash_build_l4_key (const match_exact_ip_l4_t * exact_ip_l4,
			 match_exact_l4_key_t * key)
{
  key->mek_proto = exact_ip_l4->meil_proto;

  switch (key->mek_proto)
    {
    case IP_PROTOCOL_TCP:
    case IP_PROTOCOL_UDP:
      key->mek_port = exact_ip_l4->meil_l4.ml_port;
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
      key->mek_icmp.meki_type = exact_ip_l4->meil_l4.ml_icmp.mi_type;
      key->mek_icmp.meki_code = exact_ip_l4->meil_l4.ml_icmp.mi_code;
      break;
    default:
      break;
    }
}

static walk_rc_t
match_hash_build_rule (const match_rule_t * mr, void *ctx)
{
  match_engine_hash_t *meh = ctx;

  switch (mr->mr_type)
    {
    case MATCH_TYPE_EXACT_IP:
      if (AF_IP4 == ip_addr_version (&mr->mr_exact_ip))
	hash_set (meh->meh_hash, ip_addr_v4 (&mr->mr_exact_ip).as_u32, 1);
      else
	hash_set_mem_alloc (&meh->meh_hash, &ip_addr_v6 (&mr->mr_exact_ip),
			    1);
      break;
    case MATCH_TYPE_EXACT_IP_L4:
      if (AF_IP4 == ip_addr_version (&mr->mr_exact_ip_l4.meil_ip))
	{
	  match_exact_ip4_l4_key_t key;

	  clib_memset (&key, 0, sizeof (key));

	  key.me4k_ip = ip_addr_v4 (&mr->mr_exact_ip_l4.meil_ip);

	  match_hash_build_l4_key (&mr->mr_exact_ip_l4, &key.me4k_l4);
	}
      else
	{
	  match_exact_ip6_l4_key_t key;

	  clib_memset (&key, 0, sizeof (key));

	  key.me6k_ip = ip_addr_v6 (&mr->mr_exact_ip_l4.meil_ip);

	  match_hash_build_l4_key (&mr->mr_exact_ip_l4, &key.me6k_l4);
	}
      break;
    case MATCH_TYPE_MASK_IP_MAC:
    case MATCH_TYPE_MASK_IP:
    case MATCH_TYPE_MASK_N_TUPLE:
    case MATCH_TYPE_SETS:
      break;
    }

  return (WALK_CONTINUE);
}

static walk_rc_t
match_hash_build_entry (const match_set_entry_t * mse, u32 index, void *ctx)
{
  match_set_entry_walk_rules (mse, match_hash_build_rule, ctx);

  return (WALK_CONTINUE);
}

static void
match_hash_apply_i (match_engine_hash_t * meh, match_set_t * ms)
{
  match_set_walk_entries (ms, match_hash_build_entry, meh);
}

static void
match_hash_apply (match_set_t * ms,
		  match_semantic_t msem,
		  match_set_tag_flags_t flags, match_set_app_t * msa)
{
  match_engine_hash_t *meh;
  index_t mehi;

  pool_get_zero (match_engine_hash_pool, meh);

  mehi = meh - match_engine_hash_pool;

  switch (ms->ms_eth_type)
    {
    case ETHERNET_TYPE_IP4:
      msa->msa_match = match_hash_ip4_fns[ms->ms_type][ms->ms_orientation];

      /* both exact-ip and exact-ip+L4 fit in a u64 key */
      meh->meh_hash = hash_create (0, sizeof (match_result_t));
      break;
    case ETHERNET_TYPE_IP6:
      msa->msa_match = match_hash_ip6_fns[ms->ms_type][ms->ms_orientation];

      if (ms->ms_type == MATCH_TYPE_EXACT_IP)
	meh->meh_hash =
	  hash_create_mem (0, sizeof (ip6_address_t),
			   sizeof (match_result_t));
      else if (ms->ms_type == MATCH_TYPE_EXACT_IP_L4)
	meh->meh_hash =
	  hash_create_mem (0, sizeof (match_exact_ip6_l4_key_t),
			   sizeof (match_result_t));
      else
	ASSERT (0);
      break;
    default:
      break;
    }

  match_hash_apply_i (meh, ms);
  ASSERT (msa->msa_match);

  msa->msa_index = mehi;
}

static void
match_hash_teardown (match_engine_hash_t * meh, match_set_t * ms)
{
  hash_free (meh->meh_hash);
}

static void
match_hash_unapply (match_set_t * ms, const match_set_app_t * msa)
{
  match_engine_hash_t *meh;

  meh = pool_elt_at_index (match_engine_hash_pool, msa->msa_index);

  match_hash_teardown (meh, ms);

  pool_put_index (match_engine_hash_pool, msa->msa_index);
}

/**
 * Treat all list updates the same - destroy and rebuild everything
 * a bit clunky - we can do better, but we are only dealing with samll
 * list sizes with this list engines, so it's not imperative.
 *
 */
static void
match_hash_list_update (match_set_t * ms,
			index_t msei, const match_set_app_t * msa)
{
  match_engine_hash_t *meh;

  meh = pool_elt_at_index (match_engine_hash_pool, msa->msa_index);

  match_hash_teardown (meh, ms);
  match_hash_apply_i (meh, ms);
}

static u8 *
format_match_hash (u8 * s, va_list * args)
{
  index_t mehi = va_arg (*args, index_t);

  /* match_engine_hash_t *meh; */

  /* meh = pool_elt_at_index (match_engine_hash_pool, mehi); */

  s = format (s, "[%d] hash", mehi);

  return (s);
}

static clib_error_t *
match_hash_init (vlib_main_t * vm)
{
  /**
   * The hash engine is always excellent for ANY sematics, exact matching
   */
  match_engine_priority_t mep, *meps = NULL;

  mep.len = 0;
  mep.prio = 2;
  vec_add1 (meps, mep);

  /*
   * The hash matcher can only do exact match with ANY semantics
   */
#define _(a,b)                                                          \
  const static match_engine_vft_t ml_vft_##a = {                        \
    .mev_apply = match_hash_apply,                                      \
    .mev_unapply = match_hash_unapply,                                  \
    .mev_format = format_match_hash,                                    \
    .mev_list_actions = {                                               \
      [MATCH_ENGINE_LIST_ADD] = match_hash_list_update,                 \
      [MATCH_ENGINE_LIST_REPLACE] = match_hash_list_update,             \
      [MATCH_ENGINE_LIST_DELETE] = match_hash_list_update,              \
    },                                                                  \
  };                                                                    \
  match_engine_register ("hash", MATCH_TYPE_##a,                        \
                         MATCH_SEMANTIC_ANY, &ml_vft_##a, meps);
  foreach_match_hash_type
#undef _
    vec_free (meps);
  return (NULL);
}

VLIB_INIT_FUNCTION (match_hash_init) =
{
.runs_after = VLIB_INITS ("match_init"),};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
