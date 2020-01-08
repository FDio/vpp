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

#include <match-turbo/match_turbo.h>
#include <match-turbo/match_turbo_dp.h>

#include <vnet/match/match_set.h>
#include <vnet/match/match_engine.h>

#include <vnet/ip/ip.h>

match_turbo_app_t *match_turbo_app_pool;
match_turbo_per_thread_data_t *match_turbo_per_thread_data;

/**
 * A data maintained for each match-list/entry in the match-set
 */
typedef struct match_turbo_list_t_
{
  index_t *mtl_rules;
} match_turbo_list_t;

static match_turbo_list_t *match_turbo_list_pool;

typedef struct match_turbo_ctx_t_
{
  match_turbo_app_t *mtc_app;
  match_turbo_list_t *mtc_list;
} match_turbo_ctx_t;

static void
match_turbo_lkup_set (match_turbo_lkup_t * mtl,
		      u16 bucket, index_t i, u8 value)
{
  mtl->mtl_lkup[bucket] = clib_bitmap_set (mtl->mtl_lkup[bucket], i, value);
}

static void
match_turbo_lkup_set_any (match_turbo_lkup_t * mtl, index_t i, u8 value)
{
  mtl->mtl_any = clib_bitmap_set (mtl->mtl_any, i, value);
}

static void
match_turbo_lkup_destroy (match_turbo_lkup_t * mtl)
{
  u32 bucket;

  clib_bitmap_free (mtl->mtl_any);

  for (bucket = 0; bucket < ARRAY_LEN (mtl->mtl_lkup); bucket++)
    clib_bitmap_free (mtl->mtl_lkup[bucket]);
}

static void
match_turbo_destroy_ip4 (match_turbo_table_ip4_t * mtti4)
{
  match_turbo_lkup_destroy (&mtti4->mtti4_lkup[0]);
  match_turbo_lkup_destroy (&mtti4->mtti4_lkup[1]);
}

static void
match_turbo_destroy_ip6 (match_turbo_table_ip6_t * mtti6)
{
  match_turbo_lkup_destroy (&mtti6->mtti6_lkup[0]);
  match_turbo_lkup_destroy (&mtti6->mtti6_lkup[1]);
  match_turbo_lkup_destroy (&mtti6->mtti6_lkup[2]);
  match_turbo_lkup_destroy (&mtti6->mtti6_lkup[3]);
  match_turbo_lkup_destroy (&mtti6->mtti6_lkup[4]);
  match_turbo_lkup_destroy (&mtti6->mtti6_lkup[5]);
  match_turbo_lkup_destroy (&mtti6->mtti6_lkup[6]);
  match_turbo_lkup_destroy (&mtti6->mtti6_lkup[7]);
}

static void
match_turbo_set_port (match_turbo_lkup_t * mtl,
		      const match_port_range_t * mpr, u32 bit, u8 value)
{
  if (match_port_range_is_any (mpr))
    {
      match_turbo_lkup_set_any (mtl, bit, value);
    }
  else
    {
      int j;
      /* but the bucket to popualte should be in network order */
      for (j = mpr->mpr_begin; j <= mpr->mpr_end; j++)
	match_turbo_lkup_set (mtl, clib_host_to_net_u16 (j), bit, value);
    }
}

static void
match_turbo_set_icmp_type (match_turbo_lkup_t * mtl,
			   const match_icmp_type_range_t * mitr,
			   u32 bit, u8 value)
{
  if (match_icmp_type_range_is_any (mitr))
    match_turbo_lkup_set_any (mtl, bit, value);
  else
    {
      u8 j;
      for (j = mitr->mitr_begin; j <= mitr->mitr_end; j++)
	match_turbo_lkup_set (mtl, j, bit, value);
    }
}

static void
match_turbo_set_icmp_code (match_turbo_lkup_t * mtl,
			   const match_icmp_code_range_t * micr,
			   u32 bit, u8 value)
{
  if (match_icmp_code_range_is_any (micr))
    match_turbo_lkup_set_any (mtl, bit, value);
  else
    {
      u8 j;
      for (j = micr->micr_begin; j <= micr->micr_end; j++)
	match_turbo_lkup_set (mtl, j, bit, value);
    }
}

static void
match_turbo_set_tcp (match_turbo_lkup_t * mtl,
		     const match_tcp_flags_t * mtf, u32 bit, u8 value)
{
  if (0 == mtf->mtf_mask)
    {
      match_turbo_lkup_set_any (mtl, bit, value);
    }
  else
    {
      int j;
      /* but the bucket to popualte should be in network order */
      for (j = 0; j <= 0xff; j++)
	match_turbo_lkup_set (mtl, (j & ~mtf->mtf_mask) | mtf->mtf_flags,
			      bit, value);
    }
}

static void
match_turbo_set_ip4 (match_turbo_table_ip4_t * mtti4,
		     const match_ip_prefix_t * mip, u32 bit, u8 value)
{
  /* the lookup key is an ip address in network byte order */
  ip4_address_t ip_begin, ip_end;
  i16 j, i;

  ip_begin = ip_addr_v4 (&ip_prefix_addr (&mip->mip_ip));
  ip_end.as_u32 = (ip_begin.as_u32 |
		   ~ip4_main.fib_masks[ip_prefix_len (&mip->mip_ip)]);

  // for each block of 16 bits starting with the least significant
  for (i = 1; i >= 0; i--)
    {
      if (i * 16 >= ip_prefix_len (&mip->mip_ip))
	/* the prefix is not long enough to cover this block */
	match_turbo_lkup_set_any (&mtti4->mtti4_lkup[i], bit, value);
      else
	{
	  /* in order for the loop to iterate on sensible values we need to bytes
	   * swap, but the bucket to popualte should be in network order */
	  for (j = clib_net_to_host_u16 (ip_begin.as_u16[i]);
	       j <= clib_net_to_host_u16 (ip_end.as_u16[i]); j++)
	    match_turbo_lkup_set (&mtti4->mtti4_lkup[i],
				  clib_host_to_net_u16 (j), bit, value);
	}
    }
}

static void
match_turbo_set_ip6 (match_turbo_table_ip6_t * mtti6,
		     const match_ip_prefix_t * mip, u32 bit, u8 value)
{
  /* the lookup key is an ip address in network byte order */
  ip6_address_t ip_begin, ip_end;
  u16 j, i;

  ip_begin = ip_addr_v6 (&ip_prefix_addr (&mip->mip_ip));
  ip_end.as_u64[0] = (ip_begin.as_u64[0] |
		      ~ip6_main.
		      fib_masks[ip_prefix_len (&mip->mip_ip)].as_u64[0]);
  ip_end.as_u64[1] =
    (ip_begin.as_u64[1] | ~ip6_main.
     fib_masks[ip_prefix_len (&mip->mip_ip)].as_u64[1]);

  // for each block of 16 bits starting with the most significant
  for (i = 0; i < 8; i++)
    {
      if (ip_prefix_len (&mip->mip_ip) <= (i * 16))
	/* the prefix is not long enough to cover this block */
	match_turbo_lkup_set_any (&mtti6->mtti6_lkup[i], bit, value);
      else
	{
	  /* in order for the loop to iterate on sensible values we need to byte
	   * swap, but the bucket to popualte should be in network order */
	  for (j = clib_net_to_host_u16 (ip_begin.as_u16[i]);
	       j <= clib_net_to_host_u16 (ip_end.as_u16[i]); j++)
	    match_turbo_lkup_set (&mtti6->mtti6_lkup[i],
				  clib_host_to_net_u16 (j), bit, value);
	}
    }
}

static void
match_turbo_set (match_turbo_table_t * mtt,
		 const match_mask_n_tuple_t * mnt, u32 bit, u8 value)
{
  mtt->mtt_af = ip_prefix_version (&mnt->mnt_src_ip.mip_ip);

  switch (mtt->mtt_af)
    {
    case AF_IP4:
      match_turbo_set_ip4 (&mtt->mtt_src_ip4, &mnt->mnt_src_ip, bit, value);
      match_turbo_set_ip4 (&mtt->mtt_dst_ip4, &mnt->mnt_dst_ip, bit, value);
      break;
    case AF_IP6:
      match_turbo_set_ip6 (&mtt->mtt_src_ip6, &mnt->mnt_src_ip, bit, value);
      match_turbo_set_ip6 (&mtt->mtt_dst_ip6, &mnt->mnt_dst_ip, bit, value);
      break;
    }

  switch (mnt->mnt_ip_proto)
    {
    case 0:
      match_turbo_lkup_set_any (&mtt->mtt_proto, bit, value);
      break;
    case IP_PROTOCOL_TCP:
      match_turbo_set_tcp (&mtt->mtt_tcp, &mnt->mnt_tcp, bit, value);
      /* FALL THROUGH */
    case IP_PROTOCOL_UDP:
      match_turbo_set_port (&mtt->mtt_src_port, &mnt->mnt_src_port, bit,
			    value);
      match_turbo_set_port (&mtt->mtt_dst_port, &mnt->mnt_dst_port, bit,
			    value);
      match_turbo_lkup_set (&mtt->mtt_proto, mnt->mnt_ip_proto, bit, value);
      break;
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
      match_turbo_set_icmp_type (&mtt->mtt_icmp_type, &mnt->mnt_icmp_type,
				 bit, value);
      match_turbo_set_icmp_code (&mtt->mtt_icmp_code, &mnt->mnt_icmp_code,
				 bit, value);
      match_turbo_lkup_set (&mtt->mtt_proto, mnt->mnt_ip_proto, bit, value);
      break;
    default:
      break;
    }
}

static walk_rc_t
match_turbo_mk_walk_rules (const match_rule_t * mr, void *data)
{
  match_turbo_rule_t *mtr;
  match_turbo_ctx_t *ctx = data;

  ASSERT (mr->mr_type == MATCH_TYPE_MASK_N_TUPLE);

  pool_get_zero (ctx->mtc_app->mta_rule_pool, mtr);

  vec_add1 (ctx->mtc_list->mtl_rules, mtr - ctx->mtc_app->mta_rule_pool);

  mtr->mtr_rule = mr->mr_mask_n_tuple;
  mtr->mtr_res = mr->mr_result;

  match_turbo_set (&ctx->mtc_app->mta_table, &mtr->mtr_rule,
		   mtr - ctx->mtc_app->mta_rule_pool, 1);

  return (WALK_CONTINUE);
}

static void
match_turbo_rule_destroy (index_t mtri, match_turbo_app_t * mta)
{
  match_turbo_rule_t *mtr;

  mtr = pool_elt_at_index (mta->mta_rule_pool, mtri);

  match_turbo_set (&mta->mta_table, &mtr->mtr_rule,
		   mtr - mta->mta_rule_pool, 0);

  pool_put (mta->mta_rule_pool, mtr);
}

static void
match_turbo_list_destroy (index_t mtli, match_turbo_app_t * mta)
{
  match_turbo_list_t *mtl;
  index_t *mtri;

  mtl = pool_elt_at_index (match_turbo_list_pool, mtli);

  vec_foreach (mtri, mtl->mtl_rules) match_turbo_rule_destroy (*mtri, mta);

  vec_free (mtl->mtl_rules);

  pool_put (match_turbo_list_pool, mtl);
}

static void
match_turbo_table_destroy (match_turbo_table_t * mtt)
{
  switch (mtt->mtt_af)
    {
    case AF_IP4:
      match_turbo_destroy_ip4 (&mtt->mtt_src_ip4);
      match_turbo_destroy_ip4 (&mtt->mtt_dst_ip4);
      break;
    case AF_IP6:
      match_turbo_destroy_ip6 (&mtt->mtt_src_ip6);
      match_turbo_destroy_ip6 (&mtt->mtt_dst_ip6);
      break;
    }
}

static walk_rc_t
match_turbo_mk_walk_entries (const match_set_entry_t * mse,
			     u32 index, void *data)
{
  match_turbo_list_t *mtl;

  pool_get_zero (match_turbo_list_pool, mtl);

  /* *INDENT-OFF* */
  match_turbo_ctx_t ctx = {
    .mtc_app = data,
    .mtc_list = mtl,
  };
  /* *INDENT-ON* */

  vec_add1 (ctx.mtc_app->mta_lists, mtl - match_turbo_list_pool);

  ASSERT (vec_len (ctx.mtc_app->mta_lists) - 1 == index);

  match_set_entry_walk_rules (mse, match_turbo_mk_walk_rules, &ctx);

  return (WALK_CONTINUE);
}

/**
 * Use the turbo sets to render the masek src IP and MAC match
 */
static void
match_turbo_apply_mask_n_tuple_i (match_set_t * ms, match_turbo_app_t * mta)
{
  /*
   * Translate ech rule in each entry into the correspnding masks and sessions
   */
  match_set_walk_entries (ms, match_turbo_mk_walk_entries, mta);
}

static void
match_turbo_apply_mask_n_tuple (match_set_t * ms,
				match_semantic_t msem,
				match_set_tag_flags_t flags,
				match_set_app_t * msa)
{
  match_turbo_app_t *mta;

  pool_get (match_turbo_app_pool, mta);

  mta->mta_semantic = msem;

  match_turbo_apply_mask_n_tuple_i (ms, mta);

  msa->msa_index = mta - match_turbo_app_pool;
  msa->msa_match = (AF_IP6 == mta->mta_table.mtt_af ?
		    match_turbo_match_mask_n_tuple_ip6 :
		    match_turbo_match_mask_n_tuple_ip4);
}

static void
match_turbo_teardown (match_turbo_app_t * mta)
{
  index_t *mtli;

  vec_foreach (mtli, mta->mta_lists) match_turbo_list_destroy (*mtli, mta);
  vec_free (mta->mta_lists);

  match_turbo_table_destroy (&mta->mta_table);

  pool_free (mta->mta_rule_pool);
}

static void
match_turbo_unapply_mask_n_tuple (match_set_t * ms,
				  const match_set_app_t * msa)
{
  match_turbo_app_t *mta;

  mta = pool_elt_at_index (match_turbo_app_pool, msa->msa_index);

  match_turbo_teardown (mta);

  pool_put (match_turbo_app_pool, mta);
}

static void
match_turbo_list_action_mask_n_tuple (match_set_t * ms,
				      index_t msei,
				      const match_set_app_t * msa)
{
  /* nothing clever here. destroy all state and start again */
  match_turbo_app_t *mta;

  mta = pool_elt_at_index (match_turbo_app_pool, msa->msa_index);

  match_turbo_teardown (mta);
  match_turbo_apply_mask_n_tuple_i (ms, mta);
}

static u8 *
format_match_turbo_lkup (u8 * s, va_list * args)
{
  match_turbo_lkup_t *mtl;
  u32 indent, bucket;

  mtl = va_arg (*args, match_turbo_lkup_t *);
  indent = va_arg (*args, u32);

  s = format (s, "%U[any]: %U",
	      format_white_space, indent, format_bitmap_hex, mtl->mtl_any);

  for (bucket = 0; bucket < MATCH_TURBO_STRIDE_N_BUCKETS; bucket++)
    if (mtl->mtl_lkup[bucket])
      s = format (s, "\n%U[0x%x]: %U",
		  format_white_space, indent, clib_host_to_net_u16 (bucket),
		  format_bitmap_hex, mtl->mtl_lkup[bucket]);

  return (s);
}

static u8 *
format_match_turbo_table_ip4 (u8 * s, va_list * args)
{
  match_turbo_table_ip4_t *mtti4;
  u32 indent;

  mtti4 = va_arg (*args, match_turbo_table_ip4_t *);
  indent = va_arg (*args, u32);

  s = format (s, "%Uip4 /16:", format_white_space, indent);
  s = format (s, "\n%U", format_match_turbo_lkup,
	      &mtti4->mtti4_lkup[0], indent + 2);
  s = format (s, "\n%Uip4 /32:", format_white_space, indent);
  s = format (s, "\n%U", format_match_turbo_lkup,
	      &mtti4->mtti4_lkup[1], indent + 2);

  return (s);
}

static u8 *
format_match_turbo_table_ip6 (u8 * s, va_list * args)
{
  match_turbo_table_ip6_t *mtti6;
  u32 ii, indent;

  mtti6 = va_arg (*args, match_turbo_table_ip6_t *);
  indent = va_arg (*args, u32);

  for (ii = 0; ii < 8; ii++)
    {
      s = format (s, "\n%U /%d:", format_white_space, indent, ii * 16);
      s = format (s, "\n%U", format_match_turbo_lkup, &mtti6->mtti6_lkup[ii],
		  indent + 2);
    }
  return (s);
}

static u8 *
format_match_turbo_table (u8 * s, va_list * args)
{
  match_turbo_table_t *mtt;
  u32 indent;

  mtt = va_arg (*args, match_turbo_table_t *);
  indent = va_arg (*args, u32);

  s = format (s, "%Utable:", format_white_space, indent);

  switch (mtt->mtt_af)
    {
    case AF_IP4:
      s = format (s, "\n%U%U src:", format_white_space, indent + 2,
		  format_ip_address_family, mtt->mtt_af);
      s = format (s, "\n%U", format_match_turbo_table_ip4,
		  &mtt->mtt_src_ip4, indent + 4);
      s = format (s, "\n%U%U dst:", format_white_space, indent + 2,
		  format_ip_address_family, mtt->mtt_af);
      s = format (s, "\n%U", format_match_turbo_table_ip4,
		  &mtt->mtt_dst_ip4, indent + 4);
      break;
    case AF_IP6:
      s = format (s, "\n%U%U src:", format_white_space, indent + 2,
		  format_ip_address_family, mtt->mtt_af);
      s = format (s, "\n%U", format_match_turbo_table_ip6,
		  &mtt->mtt_src_ip6, indent + 4);
      s = format (s, "\n%U%U dst:", format_white_space, indent + 2,
		  format_ip_address_family, mtt->mtt_af);
      s = format (s, "\n%U", format_match_turbo_table_ip6,
		  &mtt->mtt_dst_ip6, indent + 4);
      break;
    }

  s = format (s, "\n%Uproto:", format_white_space, indent + 2);
  s =
    format (s, "\n%U", format_match_turbo_lkup, &mtt->mtt_proto, indent + 4);

  s = format (s, "\n%Usrc-ports:", format_white_space, indent + 2);
  s = format (s, "\n%U", format_match_turbo_lkup, &mtt->mtt_src_port,
	      indent + 4);
  s = format (s, "\n%Udst-ports:", format_white_space, indent + 2);
  s = format (s, "\n%U", format_match_turbo_lkup, &mtt->mtt_dst_port,
	      indent + 4);

  return (s);
}

static u8 *
format_match_turbo_rule (u8 * s, va_list * args)
{
  match_turbo_rule_t *mtr;
  match_turbo_app_t *mta;
  index_t mtri;
  u32 indent;

  mta = va_arg (*args, match_turbo_app_t *);
  mtri = va_arg (*args, index_t);
  indent = va_arg (*args, u32);

  mtr = pool_elt_at_index (mta->mta_rule_pool, mtri);

  s = format (s, "%U[%d]", format_white_space, indent, mtri);
  s =
    format (s, " %U", format_match_mask_n_tuple, &mtr->mtr_rule, indent + 2);
  s =
    format (s, "\n%U => %U", format_white_space, indent,
	    format_match_result, mtr->mtr_res, indent + 2);

  return (s);
}

static u8 *
format_match_turbo_list (u8 * s, va_list * args)
{
  match_turbo_list_t *mtl;
  match_turbo_app_t *mta;
  index_t mtli, *mtri;
  u32 indent;

  mta = va_arg (*args, match_turbo_app_t *);
  mtli = va_arg (*args, index_t);
  indent = va_arg (*args, u32);

  mtl = pool_elt_at_index (match_turbo_list_pool, mtli);

  s = format (s, "%U[%d]", format_white_space, indent, mtli);
  vec_foreach (mtri, mtl->mtl_rules)
    s = format (s, "\n%U", format_match_turbo_rule, mta, *mtri, indent + 2);

  return (s);
}

static u8 *
format_match_turbo_app (u8 * s, va_list * args)
{
  match_turbo_app_t *mta;
  index_t mb, *mtli;
  u32 indent;

  mb = va_arg (*args, index_t);
  indent = va_arg (*args, u32);

  mta = pool_elt_at_index (match_turbo_app_pool, mb);

  s = format (s, "%U[%d]: match-turbo:", format_white_space, indent, mb);

  vec_foreach (mtli, mta->mta_lists)
    s = format (s, "\n%U", format_match_turbo_list, mta, *mtli, indent + 2);

  s =
    format (s, "\n%U", format_match_turbo_table, &mta->mta_table, indent + 2);

  return (s);
}

const static match_engine_vft_t mc_vft_first = {
  .mev_apply = match_turbo_apply_mask_n_tuple,
  .mev_unapply = match_turbo_unapply_mask_n_tuple,
  .mev_format = format_match_turbo_app,
  .mev_list_actions = {
		       [MATCH_ENGINE_LIST_ADD] =
		       match_turbo_list_action_mask_n_tuple,
		       [MATCH_ENGINE_LIST_REPLACE] =
		       match_turbo_list_action_mask_n_tuple,
		       [MATCH_ENGINE_LIST_DELETE] =
		       match_turbo_list_action_mask_n_tuple,
		       },
};

static clib_error_t *
match_turbo_mask_n_tuple_init (vlib_main_t * vm)
{
  /**
   * The effectiviness of the tuple search algorithm is a function of the number
   * of classes not the number of rules. However, without parsing the rule set
   * before choosing an engine we don't know this. So we'll approxiamte a priority
   * based on the number of rules
   * At a low number of rules, this scheme is rather poor (.r.t. the linear search),
   * so we start poor and get better. the unmbers here are all relatvie to other
   * engines.
   */
  match_turbo_per_thread_data_t *mpd;
  match_engine_priority_t mep, *meps = NULL;
  vlib_thread_main_t *tm = vlib_get_thread_main ();

  mep.len = 32;
  mep.prio = 25;
  vec_add1 (meps, mep);

  mep.len = 256;
  mep.prio = 30;
  vec_add1 (meps, mep);

  mep.len = 1024;
  mep.prio = 80;
  vec_add1 (meps, mep);

  match_engine_register ("turbo", MATCH_TYPE_MASK_N_TUPLE,
			 MATCH_SEMANTIC_FIRST, &mc_vft_first, meps);

  vec_free (meps);

  vec_validate_aligned (match_turbo_per_thread_data,
			tm->n_vlib_mains - 1, CLIB_CACHE_LINE_BYTES);

  vec_foreach (mpd, match_turbo_per_thread_data)
    // worst-case number of bitmaps collected
    vec_validate (mpd->mpd_bitmaps, 14);

  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (match_turbo_mask_n_tuple_init) =
{
  .runs_after = VLIB_INITS ("match_init"),
};
/* *INDENT-ON* */

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Turbo Matching",
};
/* *INDENT-ON* */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
