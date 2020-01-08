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
#include <vnet/match/engines/classifier/match_classifier.h>
#include <vnet/match/engines/classifier/match_classifier_mask_n_tuple_dp.h>

#include <vnet/ethernet/arp_packet.h>
#include <vnet/ip/ip.h>

static u32 MATCH_CLASSIFIER_MASK_N_TUPLE_RANGE_MAX = 0xfff;

static u8 *
format_match_classifier_mask_class_key_flags (u8 * s, va_list * args)
{
  /* int promo of  match_classifier_mask_class_key_flags_t */
  match_classifier_mask_class_key_flags_t mflags = va_arg (*args, int);

  if (0)
    ;
#define _(a,b,c)                                                        \
  else if (mflags & MASK_CLASS_KEY_FLAG_##a)                            \
    s = format (s, "%s", c);
  foreach_mask_class_key_flags
#undef _
    return (s);
}

static u8 *
format_match_classifier_mask_class_key_mask_n_tuple (u8 * s, va_list * args)
{
  match_classifier_mask_class_key_mask_n_tuple_t *mcmck =
    va_arg (*args, match_classifier_mask_class_key_mask_n_tuple_t *);
  u32 indent = va_arg (*args, u32);

  s = format (s, "%Uaf:%U ip:[%d, %d] %U tcp:%d",
	      format_white_space, indent,
	      format_ip_address_family, mcmck->mcmck_af,
	      mcmck->mcmck_ip[VLIB_RX],
	      mcmck->mcmck_ip[VLIB_TX],
	      format_match_classifier_mask_class_key_flags,
	      mcmck->mcmck_flags, mcmck->mcmck_tcp_mask);

  return (s);
}

static void
match_classifier_match_class_from_icmp_rule (const match_mask_n_tuple_t * mnt,
					     match_classifier_mask_class_key_flags_t
					     flags,
					     match_classifier_mask_class_key_mask_n_tuple_t
					     * mcmck)
{
  mcmck->mcmck_af = ip_prefix_version (&mnt->mnt_src_ip.mip_ip);
  mcmck->mcmck_ip[VLIB_RX] = ip_prefix_len (&mnt->mnt_src_ip.mip_ip);
  mcmck->mcmck_ip[VLIB_TX] = ip_prefix_len (&mnt->mnt_dst_ip.mip_ip);

  mcmck->mcmck_flags |= (MASK_CLASS_KEY_FLAG_MATCH_PROTO |
			 MASK_CLASS_KEY_FLAG_MATCH_EXACT | flags);
}

static void
match_classifier_match_class_from_any_rule (const match_mask_n_tuple_t * mnt,
					    match_classifier_mask_class_key_mask_n_tuple_t
					    * mcmck)
{
  mcmck->mcmck_af = ip_prefix_version (&mnt->mnt_src_ip.mip_ip);
  mcmck->mcmck_ip[VLIB_RX] = ip_prefix_len (&mnt->mnt_src_ip.mip_ip);
  mcmck->mcmck_ip[VLIB_TX] = ip_prefix_len (&mnt->mnt_dst_ip.mip_ip);
}

static void
match_classifier_match_class_from_l4_rule (const match_mask_n_tuple_t * mnt,
					   match_classifier_mask_class_key_flags_t
					   flags,
					   match_classifier_mask_class_key_mask_n_tuple_t
					   * mcmck)
{
  mcmck->mcmck_af = ip_prefix_version (&mnt->mnt_src_ip.mip_ip);
  mcmck->mcmck_ip[VLIB_RX] = ip_prefix_len (&mnt->mnt_src_ip.mip_ip);
  mcmck->mcmck_ip[VLIB_TX] = ip_prefix_len (&mnt->mnt_dst_ip.mip_ip);
  mcmck->mcmck_tcp_mask = mnt->mnt_tcp.mtf_mask;

  mcmck->mcmck_flags |= (MASK_CLASS_KEY_FLAG_MATCH_PROTO | flags);
}

static u8 *
match_classifier_mask_class_mk_data_mask_n_tuple (const
						  match_classifier_mask_class_key_t
						  * k)
{
  const match_classifier_mask_class_key_mask_n_tuple_t *mcmck =
    &k->mcmck_mask_n_tuple;
  u8 *s;

  s = match_classifier_build_ip_mask (NULL,
				      mcmck->mcmck_af,
				      mcmck->mcmck_ip[VLIB_RX],
				      mcmck->mcmck_ip[VLIB_TX],
				      (mcmck->mcmck_flags &
				       MASK_CLASS_KEY_FLAG_MATCH_PROTO));

  if ((mcmck->mcmck_flags & MASK_CLASS_KEY_FLAG_MATCH_SRC_PORT) ||
      (mcmck->mcmck_flags & MASK_CLASS_KEY_FLAG_MATCH_DST_PORT) ||
      mcmck->mcmck_tcp_mask)
    s = match_classifier_build_l4_mask
      (s,
       (mcmck->mcmck_flags & MASK_CLASS_KEY_FLAG_MATCH_SRC_PORT),
       (mcmck->mcmck_flags & MASK_CLASS_KEY_FLAG_MATCH_DST_PORT),
       mcmck->mcmck_tcp_mask);
  else if ((mcmck->mcmck_flags & MASK_CLASS_KEY_FLAG_MATCH_ICMP_TYPE) ||
	   (mcmck->mcmck_flags & MASK_CLASS_KEY_FLAG_MATCH_ICMP_CODE))
    s = match_classifier_build_icmp_mask
      (s,
       (mcmck->mcmck_flags & MASK_CLASS_KEY_FLAG_MATCH_ICMP_TYPE),
       (mcmck->mcmck_flags & MASK_CLASS_KEY_FLAG_MATCH_ICMP_CODE));

  return (s);
}

static index_t
match_classifier_mk_icmp_session (const match_mask_n_tuple_t * mnt,
				  match_classifier_mask_class_key_flags_t
				  flags, u8 itype, u8 icode,
				  const match_set_pos_t * pos,
				  match_result_t result,
				  match_classifier_engine_t * app)
{
  match_classifier_mask_class_key_t mcmck;
  match_classifier_session_t *mcs;

  clib_memset (&mcmck, 0, sizeof (mcmck));
  pool_get_aligned_zero (match_classifier_session_pool, mcs,
			 MATCH_CLASSIFIER_SESSION_ALGIN);

  mcs->mcs_pos = *pos;
  mcs->mcs_result = result;
  mcs->mcs_clash = INDEX_INVALID;

  match_classifier_match_class_from_icmp_rule (mnt, flags,
					       &mcmck.mcmck_mask_n_tuple);

  /* find the mask-class we will use */
  mcs->mcs_mask =
    match_classifier_mask_class_add_or_lock (MATCH_TYPE_MASK_N_TUPLE, app,
					     &mcmck, &mcs->mcs_pos);

  mcs->mcs_data = match_classifier_build_ip_hdr (mcs->mcs_data,
						 &mnt->mnt_src_ip.mip_ip,
						 &mnt->mnt_dst_ip.mip_ip,
						 mnt->mnt_ip_proto);
  mcs->mcs_data =
    match_classifier_build_icmp_hdr (mcs->mcs_data, itype, icode);
  mcs->mcs_data = match_classifier_pad (mcs->mcs_data);

  return (mcs - match_classifier_session_pool);
}

static index_t
match_classifier_mk_any_session (const match_mask_n_tuple_t * mnt,
				 const match_set_pos_t * pos,
				 match_result_t result,
				 match_classifier_engine_t * app)
{
  match_classifier_mask_class_key_t mcmck;
  match_classifier_session_t *mcs;

  clib_memset (&mcmck, 0, sizeof (mcmck));
  pool_get_aligned_zero (match_classifier_session_pool, mcs,
			 MATCH_CLASSIFIER_SESSION_ALGIN);

  mcs->mcs_pos = *pos;
  mcs->mcs_result = result;
  mcs->mcs_clash = INDEX_INVALID;

  match_classifier_match_class_from_any_rule (mnt, &mcmck.mcmck_mask_n_tuple);

  /* find the mask-class we will use */
  mcs->mcs_mask =
    match_classifier_mask_class_add_or_lock (MATCH_TYPE_MASK_N_TUPLE, app,
					     &mcmck, &mcs->mcs_pos);

  mcs->mcs_data = match_classifier_build_ip_hdr (mcs->mcs_data,
						 &mnt->mnt_src_ip.mip_ip,
						 &mnt->mnt_dst_ip.mip_ip,
						 mnt->mnt_ip_proto);
  mcs->mcs_data = match_classifier_pad (mcs->mcs_data);

  return (mcs - match_classifier_session_pool);
}

static void
match_classifier_mk_icmp_sessions (match_classifier_rule_t * mcr,
				   const match_set_pos_t * pos,
				   match_classifier_engine_t * mce)
{
  const match_icmp_code_range_t *micr;
  const match_icmp_type_range_t *mitr;
  const match_mask_n_tuple_t *mnt;
  icmp4_type_t itype;
  icmp4_code_t icode;
  index_t mcsi;

  mnt = &mcr->mcr_rule.mr_mask_n_tuple;
  mitr = &mnt->mnt_icmp_type;
  micr = &mnt->mnt_icmp_code;

  if (match_icmp_code_range_is_any (micr) &&
      match_icmp_type_range_is_any (mitr))
    {
      /* an 'any' - 'any' icmp range rule */
      mcsi = match_classifier_mk_icmp_session (mnt,
					       MASK_CLASS_KEY_FLAG_MATCH_PROTO,
					       ICMP_INVALID, ICMP_INVALID,
					       pos, mcr->mcr_rule.mr_result,
					       mce);
      vec_add1 (mcr->mcr_sessions, mcsi);
    }
  else if (match_icmp_code_range_is_any (micr))
    {
      for (itype = mitr->mitr_begin; itype <= mitr->mitr_end; itype++)
	{
	  mcsi = match_classifier_mk_icmp_session
	    (mnt,
	     (MASK_CLASS_KEY_FLAG_MATCH_PROTO |
	      MASK_CLASS_KEY_FLAG_MATCH_ICMP_TYPE),
	     itype, ICMP_INVALID, pos, mcr->mcr_rule.mr_result, mce);
	  vec_add1 (mcr->mcr_sessions, mcsi);
	}
    }
  else
    {
      for (itype = mitr->mitr_begin; itype <= mitr->mitr_end; itype++)
	for (icode = micr->micr_begin; icode <= micr->micr_end; icode++)
	  {
	    mcsi = match_classifier_mk_icmp_session
	      (mnt,
	       (MASK_CLASS_KEY_FLAG_MATCH_PROTO |
		MASK_CLASS_KEY_FLAG_MATCH_ICMP_TYPE |
		MASK_CLASS_KEY_FLAG_MATCH_ICMP_CODE),
	       itype, icode, pos, mcr->mcr_rule.mr_result, mce);
	    vec_add1 (mcr->mcr_sessions, mcsi);
	  }
    }
}

static index_t
match_classifier_mk_l4_session (const match_mask_n_tuple_t * mnt,
				match_classifier_mask_class_key_flags_t flags,
				u16 s_port,
				u16 d_port,
				const match_set_pos_t * pos,
				match_result_t result,
				match_classifier_engine_t * mce)
{
  match_classifier_mask_class_key_t mcmck;
  match_classifier_session_t *mcs;

  clib_memset (&mcmck, 0, sizeof (mcmck));

  pool_get_aligned_zero (match_classifier_session_pool, mcs,
			 MATCH_CLASSIFIER_SESSION_ALGIN);

  mcs->mcs_pos = *pos;
  mcs->mcs_result = result;
  mcs->mcs_clash = INDEX_INVALID;

  match_classifier_match_class_from_l4_rule (mnt, flags,
					     &mcmck.mcmck_mask_n_tuple);

  /* find the mask-class we will use */
  mcs->mcs_mask =
    match_classifier_mask_class_add_or_lock (MATCH_TYPE_MASK_N_TUPLE, mce,
					     &mcmck, &mcs->mcs_pos);

  mcs->mcs_data = match_classifier_build_ip_hdr (mcs->mcs_data,
						 &mnt->mnt_src_ip.mip_ip,
						 &mnt->mnt_dst_ip.mip_ip,
						 mnt->mnt_ip_proto);
  mcs->mcs_data = match_classifier_build_l4_hdr (mcs->mcs_data,
						 s_port, d_port,
						 &mnt->mnt_tcp);
  mcs->mcs_data = match_classifier_pad (mcs->mcs_data);

  if (!(mcmck.mcmck_mask_n_tuple.mcmck_flags &
	MASK_CLASS_KEY_FLAG_MATCH_EXACT))
    {
      /* we need to add a clash session */
      match_classifier_clash_t *mcc;

      pool_get_zero (match_classifier_clash_pool, mcc);
      mcc->mcc_rule = *mnt;
      mcc->mcc_result = mcs->mcs_result;

      mcs->mcs_clash = (mcc - match_classifier_clash_pool);
    }

  return (mcs - match_classifier_session_pool);
}

static void
match_classifier_mk_l4_range_sessions (match_classifier_rule_t * mcr,
				       match_classifier_mask_class_key_flags_t
				       flags,
				       const match_port_range_t * s_mpr,
				       const match_port_range_t * d_mpr,
				       const match_set_pos_t * pos,
				       match_classifier_engine_t * mce)
{
  u16 s_port, d_port;

  FOR_EACH_MATCH_PORT_RANGE (s_mpr, s_port)
    FOR_EACH_MATCH_PORT_RANGE (d_mpr, d_port)
    vec_add1 (mcr->mcr_sessions,
	      match_classifier_mk_l4_session (&mcr->mcr_rule.mr_mask_n_tuple,
					      flags, s_port, d_port,
					      pos, mcr->mcr_rule.mr_result,
					      mce));
}

static void
match_classifier_mk_any_sessions (match_classifier_rule_t * mcr,
				  const match_set_pos_t * pos,
				  match_classifier_engine_t * mce)
{
  vec_add1 (mcr->mcr_sessions,
	    match_classifier_mk_any_session (&mcr->mcr_rule.mr_mask_n_tuple,
					     pos, mcr->mcr_rule.mr_result,
					     mce));
}

static void
match_classifier_mk_l4_sessions (match_classifier_rule_t * mcr,
				 const match_set_pos_t * pos,
				 match_classifier_engine_t * mce)
{
  const match_port_range_t *d_mpr, *s_mpr;
  const match_mask_n_tuple_t *mnt;
  index_t mcsi;

  mnt = &mcr->mcr_rule.mr_mask_n_tuple;

  s_mpr = &mnt->mnt_src_port;
  d_mpr = &mnt->mnt_dst_port;

  if (match_port_range_is_any (s_mpr) && match_port_range_is_any (s_mpr))
    {
      /* an 'any' - 'any' port range rule */
      mcsi = match_classifier_mk_l4_session (mnt,
					     (MASK_CLASS_KEY_FLAG_MATCH_PROTO
					      |
					      MASK_CLASS_KEY_FLAG_MATCH_EXACT),
					     0, 0, pos,
					     mcr->mcr_rule.mr_result, mce);
      vec_add1 (mcr->mcr_sessions, mcsi);
    }
  else if (match_port_range_is_one (s_mpr))
    {
      if (match_port_range_size (d_mpr) <
	  MATCH_CLASSIFIER_MASK_N_TUPLE_RANGE_MAX)
	{
	  /* There's only one src port, the dst port range is within the
	   * limit. Add individual exact match sessions for each port */
	  match_classifier_mk_l4_range_sessions
	    (mcr,
	     (MASK_CLASS_KEY_FLAG_MATCH_PROTO |
	      MASK_CLASS_KEY_FLAG_MATCH_SRC_PORT |
	      MASK_CLASS_KEY_FLAG_MATCH_DST_PORT |
	      MASK_CLASS_KEY_FLAG_MATCH_EXACT), s_mpr, d_mpr, pos, mce);
	}
      else
	{
	  /* There's only one src port, the dst port range larger than the
	   * limit. Add one session to exact match the dst and clash on the
	   * source */
	  mcsi = match_classifier_mk_l4_session (mnt,
						 (MASK_CLASS_KEY_FLAG_MATCH_PROTO
						  |
						  MASK_CLASS_KEY_FLAG_MATCH_SRC_PORT),
						 s_mpr->mpr_begin, 0, pos,
						 mcr->mcr_rule.mr_result,
						 mce);
	  vec_add1 (mcr->mcr_sessions, mcsi);
	}
    }
  else if (match_port_range_is_one (d_mpr))
    {
      if (match_port_range_size (s_mpr) <
	  MATCH_CLASSIFIER_MASK_N_TUPLE_RANGE_MAX)
	{
	  /* There's only one dst port, the src port range is within the
	   * limit. Add individual exactmatch sessions for each port */
	  match_classifier_mk_l4_range_sessions
	    (mcr,
	     (MASK_CLASS_KEY_FLAG_MATCH_PROTO |
	      MASK_CLASS_KEY_FLAG_MATCH_SRC_PORT |
	      MASK_CLASS_KEY_FLAG_MATCH_DST_PORT |
	      MASK_CLASS_KEY_FLAG_MATCH_EXACT), s_mpr, d_mpr, pos, mce);
	}
      else
	{
	  /* There's only one dst port, the src port range larger than the
	   * limit. Add one session to exact match the dst and clash on the
	   * source */
	  mcsi = match_classifier_mk_l4_session (mnt,
						 (MASK_CLASS_KEY_FLAG_MATCH_PROTO
						  |
						  MASK_CLASS_KEY_FLAG_MATCH_DST_PORT),
						 0, d_mpr->mpr_begin, pos,
						 mcr->mcr_rule.mr_result,
						 mce);
	  vec_add1 (mcr->mcr_sessions, mcsi);
	}
    }
  else
    {
      /* two ranges
       *  this could lead to a session explosion */
      if (match_port_range_size (s_mpr) * match_port_range_size (d_mpr) <
	  MATCH_CLASSIFIER_MASK_N_TUPLE_RANGE_MAX)
	{
	  /* less than our self imposed limit */
	  match_classifier_mk_l4_range_sessions
	    (mcr,
	     (MASK_CLASS_KEY_FLAG_MATCH_PROTO |
	      MASK_CLASS_KEY_FLAG_MATCH_SRC_PORT |
	      MASK_CLASS_KEY_FLAG_MATCH_DST_PORT |
	      MASK_CLASS_KEY_FLAG_MATCH_EXACT), s_mpr, d_mpr, pos, mce);
	}
      else
	{
	  /* this is more sessions than we're prepared to burn for one rule -
	   * reluctantly we add a range based (and hence colliding) rule */
	  mcsi = match_classifier_mk_l4_session (mnt,
						 MASK_CLASS_KEY_FLAG_MATCH_PROTO,
						 0, 0, pos,
						 mcr->mcr_rule.mr_result,
						 mce);
	  vec_add1 (mcr->mcr_sessions, mcsi);
	}
    }
}

static void
match_classifier_mk_sessions_mask_n_tuple (match_classifier_rule_t * mcr,
					   const match_set_pos_t * pos,
					   match_classifier_engine_t * mce)
{
  switch (mcr->mcr_rule.mr_mask_n_tuple.mnt_ip_proto)
    {
    case IP_PROTOCOL_TCP:
    case IP_PROTOCOL_UDP:
      return (match_classifier_mk_l4_sessions (mcr, pos, mce));
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
      return (match_classifier_mk_icmp_sessions (mcr, pos, mce));
    case 0:
      return (match_classifier_mk_any_sessions (mcr, pos, mce));
    default:
      break;
    }
}

const static match_classifier_mask_vft_t mcv_mask_n_tuple = {
  .mcv_mk_sessions = match_classifier_mk_sessions_mask_n_tuple,
  .mcv_mk_class_data = match_classifier_mask_class_mk_data_mask_n_tuple,
  .mcv_format_key = format_match_classifier_mask_class_key_mask_n_tuple,
  .mcv_match = {
		[AF_IP4] = {
			    match_classifier_engine_match_mask_n_tuple_ip4,
			    match_classifier_engine_match_mask_n_tuple_ip4,
			    },
		[AF_IP6] = {
			    match_classifier_engine_match_mask_n_tuple_ip6,
			    match_classifier_engine_match_mask_n_tuple_ip6,
			    },
		},
};

const static match_engine_vft_t mc_vft_first = {
  .mev_apply = match_classifier_apply,
  .mev_update = match_classifier_update,
  .mev_unapply = match_classifier_unapply,
  .mev_format = format_match_classifier_engine,
};

static clib_error_t *
match_classifier_mask_n_tuple_init (vlib_main_t * vm)
{
  match_classifier_mask_register (MATCH_TYPE_MASK_N_TUPLE, &mcv_mask_n_tuple);
  /**
   * The effectiviness of the tuple search algorithm is a function of the number
   * of classes not the number of rules. However, without parsing the rule set
   * before choosing an engine we don't know this. So we'll approxiamte a priority
   * based on the number of rules
   * At a low number of rules, this scheme is rather poor (w.r.t. the linear search),
   * so we start poor and get better. the unmbers here are all relatvie to other
   * engines.
   */
  match_engine_priority_t mep, *meps = NULL;

  mep.len = 32;
  mep.prio = 200;
  vec_add1 (meps, mep);

  mep.len = 64;
  mep.prio = 50;
  vec_add1 (meps, mep);

  match_engine_register ("classifier", MATCH_TYPE_MASK_N_TUPLE,
			 MATCH_SEMANTIC_FIRST, &mc_vft_first, meps);

  vec_free (meps);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (match_classifier_mask_n_tuple_init) =
{
  .runs_after = VLIB_INITS ("match_init"),
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
