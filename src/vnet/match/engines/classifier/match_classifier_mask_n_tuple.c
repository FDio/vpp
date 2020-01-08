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
#include <vnet/match/engines/classifier/match_classifier_mask_n_tuple.h>
#include <vnet/match/engines/classifier/match_classifier_mask_n_tuple_dp.h>

#include <vnet/ethernet/arp_packet.h>
#include <vnet/ip/ip.h>

match_engine_classifier_app_t *match_engine_classifier_app_pool;
match_classifier_session_t *match_classifier_session_pool;
match_classifier_clash_t *match_classifier_clash_pool;
match_classifier_clash_head_t *match_classifier_clash_head_pool;

#define ICMP_INVALID 0xff
#define PORT_MASK 0xff

static u32 MATCH_CLASSIFIER_MASK_N_TUPLE_RANGE_MAX = 0xfff;

/**
 * A mask 'class' requires its own vnet-classifier table
 */
typedef struct match_classifier_mask_class_key_t_
{
  union
  {
    u64 mcmck_as_u64;
    struct
    {
      ip_address_family_t mcmck_af;
      /* the src and dst IP mask lengths */
      u8 mcmck_ip[VLIB_N_DIR];
      /* The IP protocol */
      ip_protocol_t mcmck_ip_proto;

      /* depending on the ip-proto type - l4 */
      union
      {
	struct
	{
	  /* prefix lengths for src and dest port ranges */
	  u8 mcmck_port[VLIB_N_DIR];
	  u8 mcmck_tcp_mask;
	  u8 mcmck_exact;
	};
	/* we either build a set of exact matches for the icmp types and codes
	 * or any any */
	struct
	{
	  u8 mcmck_icmp_type;
	  u8 mcmck_icmp_code;
	};
      };
    };
  };
} __clib_packed match_classifier_mask_class_key_t;


STATIC_ASSERT (sizeof (match_classifier_mask_class_key_t) <= sizeof (u64),
	       "match-class bigger than u64 - switch to hash_get_mem");

typedef enum match_classifier_mask_class_flags_t_
{
  /* This mask class can produce collisions */
  MATCH_CLASSIFIER_MASK_CLASS_FLAG_CAN_COLLIDE = (1 << 0),
} match_classifier_mask_class_flags_t;

/**
 * the key and data associated with each unique mask
 */
typedef struct match_classifier_mask_class_t_
{
  match_classifier_mask_class_key_t mcmc_key;

  /* Mask data given to the vnet-classifier */
  u8 *mcmc_data;

  /* number of sessions using this mask */
  u32 mcmc_locks;
  u32 mcmc_table;

  /* engine application whose hash this object is in */
  index_t mcmc_app;

  /* The best rule using this mask - used to sort the tables */
  match_set_pos_t mcmc_best;
} match_classifier_mask_class_t;

static match_classifier_mask_class_t *match_classifier_mask_class_pool;

/**
 * A data maintained for each match-rule in the match-list
 */
typedef struct match_classifier_rule_t_
{
  match_mask_n_tuple_t mcr_rule;

  /* The vector of sessions that this rule generates */
  index_t *mcr_sessions;
} match_classifier_rule_t;

static match_classifier_rule_t *match_classifier_rule_pool;

/**
 * A data maintained for each match-list/entry in the match-set
 */
typedef struct match_classifier_list_t_
{
  index_t *mcl_rules;
} match_classifier_list_t;

static match_classifier_list_t *match_classifier_list_pool;

typedef struct match_classifier_ctx_t_
{
  match_set_result_t mcc_result;
  match_engine_classifier_app_t *mcc_app;
  match_classifier_list_t *mcc_list;
} match_classifier_ctx_t;

static u8 *
format_match_classifier_mask_class_key (u8 * s, va_list * args)
{
  match_classifier_mask_class_key_t *mcmck =
    va_arg (*args, match_classifier_mask_class_key_t *);
  u32 indent = va_arg (*args, u32);

  s = format (s, "%Uaf:%U ip:[%d, %d] %U",
	      format_white_space, indent,
	      format_ip_address_family, mcmck->mcmck_af,
	      mcmck->mcmck_ip[VLIB_RX],
	      mcmck->mcmck_ip[VLIB_TX],
	      format_ip_protocol, mcmck->mcmck_ip_proto);

  switch (mcmck->mcmck_ip_proto)
    {
    case IP_PROTOCOL_TCP:
    case IP_PROTOCOL_UDP:
      s = format (s, " ports:[0x%x, 0x%x] tcp:%x",
		  mcmck->mcmck_port[VLIB_RX],
		  mcmck->mcmck_port[VLIB_TX], mcmck->mcmck_tcp_mask);
      break;
    default:
      break;
    }

  return (s);
}

static u8 *
format_match_classifier_mask_class (u8 * s, va_list * args)
{
  match_classifier_mask_class_t *mcmc;
  index_t mcmci = va_arg (*args, index_t);
  u32 indent = va_arg (*args, u32);

  mcmc = pool_elt_at_index (match_classifier_mask_class_pool, mcmci);

  s = format (s, "%U[%d] class: locks:%d table:%d best:[%U]",
	      format_white_space, indent,
	      mcmci,
	      mcmc->mcmc_locks,
	      mcmc->mcmc_table, format_match_set_pos, &mcmc->mcmc_best);

  s =
    format (s, "\n%U", format_match_classifier_mask_class_key,
	    &mcmc->mcmc_key, indent + 2), s =
    format (s, "\n%U  %U", format_white_space, indent, format_hex_bytes,
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
  s = format (s, "\n%Umask:%d result:[%U]",
	      format_white_space, indent + 2,
	      mcs->mcs_mask, format_match_set_result, &mcs->mcs_result);
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
	      mcri, format_match_mask_n_tuple, mcr->mcr_rule, indent + 2);

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

static u8 *
match_classifier_build_ip4_mask (const match_classifier_mask_class_key_t *
				 mcmck)
{
  ip4_header_t *ip4;
  u8 *s = NULL;

  vec_validate (s, sizeof (*ip4) - 1);
  ip4 = (ip4_header_t *) s;

  ip4_preflen_to_mask (mcmck->mcmck_ip[VLIB_RX], &ip4->src_address);
  ip4_preflen_to_mask (mcmck->mcmck_ip[VLIB_TX], &ip4->dst_address);

  if (mcmck->mcmck_ip_proto)
    ip4->protocol = 0xff;

  return (s);
}

static u8 *
match_classifier_build_ip6_mask (const match_classifier_mask_class_key_t *
				 mcmck)
{
  ip6_header_t *ip6;
  u8 *s = NULL;

  vec_validate (s, sizeof (*ip6) - 1);
  ip6 = (ip6_header_t *) s;

  ip6_preflen_to_mask (mcmck->mcmck_ip[VLIB_RX], &ip6->src_address);
  ip6_preflen_to_mask (mcmck->mcmck_ip[VLIB_TX], &ip6->dst_address);

  if (mcmck->mcmck_ip_proto)
    ip6->protocol = 0xff;

  return (s);
}

static u8 *
match_classifier_build_ip_mask (const match_classifier_mask_class_key_t *
				mcmck)
{
  switch (mcmck->mcmck_af)
    {
    case AF_IP4:
      return (match_classifier_build_ip4_mask (mcmck));
    case AF_IP6:
      return (match_classifier_build_ip6_mask (mcmck));
    }

  ASSERT (0);
  return (NULL);
}

static u8 *
match_classifier_build_ip4_hdr (const match_mask_n_tuple_t * mnt)
{
  ip4_header_t *ip4;
  u8 *s = NULL;

  vec_validate (s, sizeof (*ip4) - 1);
  ip4 = (ip4_header_t *) s;

  ip4->src_address = ip_addr_v4 (&ip_prefix_addr (&mnt->mnt_src_ip.mip_ip));
  ip4->dst_address = ip_addr_v4 (&ip_prefix_addr (&mnt->mnt_dst_ip.mip_ip));

  ip4->protocol = mnt->mnt_ip_proto;

  return (s);
}

static u8 *
match_classifier_build_ip6_hdr (const match_mask_n_tuple_t * mnt)
{
  ip6_header_t *ip6;
  u8 *s = NULL;

  vec_validate (s, sizeof (*ip6) - 1);
  ip6 = (ip6_header_t *) s;

  ip6->src_address = ip_addr_v6 (&ip_prefix_addr (&mnt->mnt_src_ip.mip_ip));
  ip6->dst_address = ip_addr_v6 (&ip_prefix_addr (&mnt->mnt_dst_ip.mip_ip));

  ip6->protocol = mnt->mnt_ip_proto;

  return (s);
}

static u8 *
match_classifier_build_ip_hdr (const match_mask_n_tuple_t * mnt)
{
  switch (ip_prefix_version (&mnt->mnt_src_ip.mip_ip))
    {
    case AF_IP4:
      return (match_classifier_build_ip4_hdr (mnt));
    case AF_IP6:
      return (match_classifier_build_ip6_hdr (mnt));
    }

  ASSERT (0);
  return (NULL);
}

static u8 *
match_classifier_build_icmp_hdr (u8 * s, u8 itype, u8 icode)
{
  icmp46_header_t *icmp;
  u8 *n;

  // append an icmp header
  vec_add2 (s, n, sizeof (*icmp));
  icmp = (icmp46_header_t *) n;

  if (ICMP_INVALID != itype)
    icmp->type = itype;
  if (ICMP_INVALID != icode)
    icmp->code = icode;

  return (s);
}

static u8 *
match_classifier_build_icmp_mask (u8 * s,
				  const match_classifier_mask_class_key_t *
				  mcmck)
{
  icmp46_header_t *icmp;
  u8 *n;

  // append an icmp header
  vec_add2 (s, n, sizeof (*icmp));
  icmp = (icmp46_header_t *) n;

  if (mcmck->mcmck_icmp_type)
    icmp->type = 0xff;
  if (mcmck->mcmck_icmp_code)
    icmp->code = 0xff;

  return (s);
}

static u8 *
match_classifier_build_l4_hdr (u8 * s, const match_mask_n_tuple_t * mnt,
			       u16 s_port, u16 d_port)
{
  tcp_header_t *tcp;
  u8 *n;

  // append an tcp header
  vec_add2 (s, n, sizeof (*tcp));
  tcp = (tcp_header_t *) n;

  tcp->src_port = clib_host_to_net_u16 (s_port);
  tcp->dst_port = clib_host_to_net_u16 (d_port);
  tcp->flags = mnt->mnt_tcp.mtf_flags;

  return (s);
}

static u8 *
match_classifier_build_l4_mask (u8 * s,
				const match_classifier_mask_class_key_t *
				mcmck)
{
  tcp_header_t *tcp;
  u8 *n;

  // append an tcp header
  vec_add2 (s, n, sizeof (*tcp));
  tcp = (tcp_header_t *) n;

  tcp->src_port = mcmck->mcmck_port[VLIB_RX];
  tcp->dst_port = mcmck->mcmck_port[VLIB_RX];
  tcp->flags = mcmck->mcmck_tcp_mask;

  return (s);
}

static void
match_classifier_match_class_from_icmp_rule (const match_mask_n_tuple_t * mnt,
					     match_classifier_mask_class_key_t
					     * mcmck,
					     u8 itype, bool t_exact,
					     u8 icode, bool c_exact)
{
  clib_memset (mcmck, 0, sizeof (*mcmck));

  mcmck->mcmck_af = ip_prefix_version (&mnt->mnt_src_ip.mip_ip);
  mcmck->mcmck_ip[VLIB_RX] = ip_prefix_len (&mnt->mnt_src_ip.mip_ip);
  mcmck->mcmck_ip[VLIB_TX] = ip_prefix_len (&mnt->mnt_dst_ip.mip_ip);

  mcmck->mcmck_ip_proto = mnt->mnt_ip_proto;

  mcmck->mcmck_icmp_type = t_exact;
  mcmck->mcmck_icmp_code = c_exact;
}

static void
match_classifier_match_class_from_any_rule (const match_mask_n_tuple_t * mnt,
					    match_classifier_mask_class_key_t
					    * mcmck)
{
  clib_memset (mcmck, 0, sizeof (*mcmck));

  mcmck->mcmck_af = ip_prefix_version (&mnt->mnt_src_ip.mip_ip);
  mcmck->mcmck_ip[VLIB_RX] = ip_prefix_len (&mnt->mnt_src_ip.mip_ip);
  mcmck->mcmck_ip[VLIB_TX] = ip_prefix_len (&mnt->mnt_dst_ip.mip_ip);

  mcmck->mcmck_ip_proto = 0;
}

static void
match_classifier_match_class_from_l4_rule (const match_mask_n_tuple_t * mnt,
					   u16 s_port,
					   bool s_exact,
					   u16 d_port,
					   bool d_exact,
					   match_classifier_mask_class_key_t *
					   mcmck)
{
  clib_memset (mcmck, 0, sizeof (*mcmck));

  mcmck->mcmck_af = ip_prefix_version (&mnt->mnt_src_ip.mip_ip);
  mcmck->mcmck_ip[VLIB_RX] = ip_prefix_len (&mnt->mnt_src_ip.mip_ip);
  mcmck->mcmck_ip[VLIB_TX] = ip_prefix_len (&mnt->mnt_dst_ip.mip_ip);

  mcmck->mcmck_ip_proto = mnt->mnt_ip_proto;

  if (s_port)
    mcmck->mcmck_port[VLIB_RX] = PORT_MASK;
  if (d_port)
    mcmck->mcmck_port[VLIB_TX] = PORT_MASK;
  mcmck->mcmck_exact = s_exact & d_exact;

  mcmck->mcmck_tcp_mask = mnt->mnt_tcp.mtf_mask;
}

static u8 *
match_classifier_pad_to_classifier_vector_size (u8 * s)
{
  u32 len;

  len =
    match_classifier_round_up_to_classifier_vector_size (vec_len (s)) *
    VNET_CLASSIFY_VECTOR_SIZE;

  vec_validate (s, len - 1);

  return (s);
}

static void
match_classifier_mask_class_unlock (index_t * mcmci)
{
  match_classifier_mask_class_t *mcmc;

  mcmc = pool_elt_at_index (match_classifier_mask_class_pool, *mcmci);
  mcmc->mcmc_locks--;

  if (0 == mcmc->mcmc_locks)
    {
      match_engine_classifier_app_t *meca;

      meca =
	pool_elt_at_index (match_engine_classifier_app_pool, mcmc->mcmc_app);

      hash_unset (meca->meca_masks, mcmc->mcmc_key.mcmck_as_u64);

      vnet_classify_delete_table_index (&vnet_classify_main, mcmc->mcmc_table,
					0);

      pool_put (match_classifier_mask_class_pool, mcmc);
    }

  *mcmci = INDEX_INVALID;
}

static index_t
match_classifier_mask_class_add_or_lock (match_engine_classifier_app_t * app,
					 const
					 match_classifier_mask_class_key_t *
					 mcmck)
{
  match_classifier_mask_class_t *mcmc;
  index_t mcmci;
  uword *p;

  p = hash_get (app->meca_masks, mcmck->mcmck_as_u64);

  if (p)
    {
      mcmci = p[0];
      mcmc = pool_elt_at_index (match_classifier_mask_class_pool, mcmci);
    }
  else
    {
      pool_get_zero (match_classifier_mask_class_pool, mcmc);

      mcmci = mcmc - match_classifier_mask_class_pool;
      mcmc->mcmc_key = *mcmck;
      mcmc->mcmc_app = (app - match_engine_classifier_app_pool);
      mcmc->mcmc_best = MATCH_SET_POS_MISS;

      /* we'll delay the creation of the table until we know how many
       * sessions it needs */
      mcmc->mcmc_table = ~0;

      mcmc->mcmc_data = match_classifier_build_ip_mask (&mcmc->mcmc_key);

      switch (mcmc->mcmc_key.mcmck_ip_proto)
	{
	case IP_PROTOCOL_TCP:
	case IP_PROTOCOL_UDP:
	  mcmc->mcmc_data = match_classifier_build_l4_mask (mcmc->mcmc_data,
							    &mcmc->mcmc_key);
	  break;
	case IP_PROTOCOL_ICMP:
	case IP_PROTOCOL_ICMP6:
	  mcmc->mcmc_data = match_classifier_build_icmp_mask (mcmc->mcmc_data,
							      &mcmc->mcmc_key);
	  break;
	default:
	  break;
	}

      mcmc->mcmc_data =
	match_classifier_pad_to_classifier_vector_size (mcmc->mcmc_data);

      hash_set (app->meca_masks, mcmck->mcmck_as_u64, mcmci);

      app->meca_af = mcmck->mcmck_af;
    }

  mcmc->mcmc_locks++;

  return (mcmci);
}

static u32
match_classifier_mask_class_mk_table (match_classifier_mask_class_t * mcmc,
				      u32 next_table_index, vnet_link_t linkt)
{
  return (match_classifier_mk_table (mcmc->mcmc_data,
				     vec_len (mcmc->mcmc_data),
				     mcmc->mcmc_locks,
				     next_table_index,
				     (VNET_LINK_ETHERNET == linkt ?
				      CLASSIFY_FLAG_USE_L2_LEN :
				      CLASSIFY_FLAG_NONE),
				     0, mcmc->mcmc_best.msp_as_u64));
}

static void
match_classifier_mask_class_update_best (index_t mcmci,
					 const match_set_result_t * msr)
{
  match_classifier_mask_class_t *mcmc;

  mcmc = pool_elt_at_index (match_classifier_mask_class_pool, mcmci);

  /* less => earlier => better */
  if (match_set_pos_is_better (&msr->msr_pos, &mcmc->mcmc_best))
    match_set_pos_copy (&msr->msr_pos, &mcmc->mcmc_best);
}

static index_t
match_classifier_mk_icmp_session (const match_mask_n_tuple_t * mnt,
				  u8 itype,
				  bool t_exact,
				  u8 icode,
				  bool c_exact,
				  const match_set_result_t * result,
				  match_engine_classifier_app_t * app)
{
  match_classifier_mask_class_key_t mcmck;
  match_classifier_session_t *mcs;

  pool_get_aligned_zero (match_classifier_session_pool, mcs,
			 MATCH_CLASSIFIER_SESSION_ALGIN);

  mcs->mcs_result = *result;
  mcs->mcs_clash = INDEX_INVALID;

  match_classifier_match_class_from_icmp_rule (mnt, &mcmck,
					       itype, t_exact,
					       icode, c_exact);

  /* find the mask-class we will use */
  mcs->mcs_mask = match_classifier_mask_class_add_or_lock (app, &mcmck);

  match_classifier_mask_class_update_best (mcs->mcs_mask, &mcs->mcs_result);

  mcs->mcs_data = match_classifier_build_ip_hdr (mnt);
  mcs->mcs_data =
    match_classifier_build_icmp_hdr (mcs->mcs_data, itype, icode);
  mcs->mcs_data =
    match_classifier_pad_to_classifier_vector_size (mcs->mcs_data);

  return (mcs - match_classifier_session_pool);
}

static index_t
match_classifier_mk_any_session (const match_mask_n_tuple_t * mnt,
				 const match_set_result_t * result,
				 match_engine_classifier_app_t * app)
{
  match_classifier_mask_class_key_t mcmck;
  match_classifier_session_t *mcs;

  pool_get_aligned_zero (match_classifier_session_pool, mcs,
			 MATCH_CLASSIFIER_SESSION_ALGIN);

  mcs->mcs_result = *result;
  mcs->mcs_clash = INDEX_INVALID;

  match_classifier_match_class_from_any_rule (mnt, &mcmck);

  /* find the mask-class we will use */
  mcs->mcs_mask = match_classifier_mask_class_add_or_lock (app, &mcmck);

  match_classifier_mask_class_update_best (mcs->mcs_mask, &mcs->mcs_result);

  mcs->mcs_data = match_classifier_build_ip_hdr (mnt);
  mcs->mcs_data =
    match_classifier_pad_to_classifier_vector_size (mcs->mcs_data);

  return (mcs - match_classifier_session_pool);
}

static void
match_classifier_mk_icmp_sessions (match_classifier_rule_t * mcr,
				   const match_set_result_t * result,
				   match_engine_classifier_app_t * app)
{
  const match_icmp_code_range_t *micr;
  const match_icmp_type_range_t *mitr;
  icmp4_type_t itype;
  icmp4_code_t icode;

  mitr = &mcr->mcr_rule.mnt_icmp_type;
  micr = &mcr->mcr_rule.mnt_icmp_code;

  if (match_icmp_code_range_is_any (micr) &&
      match_icmp_type_range_is_any (mitr))
    {
      /* an 'any' - 'any' icmp range rule */
      vec_add1 (mcr->mcr_sessions,
		match_classifier_mk_icmp_session (&mcr->mcr_rule,
						  ICMP_INVALID, false,
						  ICMP_INVALID, false,
						  result, app));
    }
  else if (match_icmp_code_range_is_any (micr))
    {
      for (itype = mitr->mitr_begin; itype <= mitr->mitr_end; itype++)
	vec_add1 (mcr->mcr_sessions,
		  match_classifier_mk_icmp_session (&mcr->mcr_rule,
						    itype, true,
						    ICMP_INVALID, false,
						    result, app));
    }
  else
    {
      for (itype = mitr->mitr_begin; itype <= mitr->mitr_end; itype++)
	for (icode = micr->micr_begin; icode <= micr->micr_end; icode++)
	  vec_add1 (mcr->mcr_sessions,
		    match_classifier_mk_icmp_session (&mcr->mcr_rule,
						      itype, true,
						      icode, true,
						      result, app));
    }
}

static index_t
match_classifier_mk_l4_session (const match_mask_n_tuple_t * mnt,
				u16 s_port,
				bool s_exact,
				u16 d_port,
				bool d_exact,
				const match_set_result_t * result,
				match_engine_classifier_app_t * app)
{
  match_classifier_mask_class_key_t mcmck;
  match_classifier_session_t *mcs;

  pool_get_aligned_zero (match_classifier_session_pool, mcs,
			 MATCH_CLASSIFIER_SESSION_ALGIN);

  mcs->mcs_result = *result;
  mcs->mcs_clash = INDEX_INVALID;

  match_classifier_match_class_from_l4_rule (mnt, s_port, s_exact,
					     d_port, d_exact, &mcmck);

  /* find the mask-class we will use */
  mcs->mcs_mask = match_classifier_mask_class_add_or_lock (app, &mcmck);

  mcs->mcs_data = match_classifier_build_ip_hdr (mnt);
  mcs->mcs_data = match_classifier_build_l4_hdr (mcs->mcs_data, mnt,
						 s_port, d_port);
  mcs->mcs_data =
    match_classifier_pad_to_classifier_vector_size (mcs->mcs_data);
  match_classifier_mask_class_update_best (mcs->mcs_mask, &mcs->mcs_result);

  if (!(s_exact && d_exact))
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
				       const match_port_range_t * s_mpr,
				       bool s_exact,
				       const match_port_range_t * d_mpr,
				       bool d_exact,
				       const match_set_result_t * result,
				       match_engine_classifier_app_t * app)
{
  u16 s_port, d_port;

  FOR_EACH_MATCH_PORT_RANGE (s_mpr, s_port)
    FOR_EACH_MATCH_PORT_RANGE (d_mpr, d_port)
    vec_add1 (mcr->mcr_sessions,
	      match_classifier_mk_l4_session (&mcr->mcr_rule,
					      s_port, s_exact,
					      d_port, d_exact, result, app));
}

static void
match_classifier_mk_any_sessions (match_classifier_rule_t * mcr,
				  const match_set_result_t * result,
				  match_engine_classifier_app_t * app)
{
  vec_add1 (mcr->mcr_sessions,
	    match_classifier_mk_any_session (&mcr->mcr_rule, result, app));
}

static void
match_classifier_mk_l4_sessions (match_classifier_rule_t * mcr,
				 const match_set_result_t * result,
				 match_engine_classifier_app_t * app)
{
  const match_port_range_t *d_mpr, *s_mpr;

  s_mpr = &mcr->mcr_rule.mnt_src_port;
  d_mpr = &mcr->mcr_rule.mnt_dst_port;

  if (match_port_range_is_any (s_mpr) && match_port_range_is_any (s_mpr))
    {
      /* an 'any' - 'any' port range rule */
      vec_add1 (mcr->mcr_sessions,
		match_classifier_mk_l4_session (&mcr->mcr_rule,
						0, true, 0, true,
						result, app));
    }
  else if (match_port_range_is_one (s_mpr))
    {
      if (match_port_range_size (d_mpr) <
	  MATCH_CLASSIFIER_MASK_N_TUPLE_RANGE_MAX)
	{
	  /* There's only one src port, the dst port range is within the
	   * limit. Add individual exactmatch sessions for each port */
	  match_classifier_mk_l4_range_sessions (mcr, s_mpr, true,
						 d_mpr, true, result, app);
	}
      else
	{
	  /* There's only one src port, the dst port range larger than the
	   * limit. Add one session to exact match the dst and clash on the
	   * source */
	  vec_add1 (mcr->mcr_sessions,
		    match_classifier_mk_l4_session (&mcr->mcr_rule,
						    s_mpr->mpr_begin, true,
						    0, false, result, app));
	}
    }
  else if (match_port_range_is_one (d_mpr))
    {
      if (match_port_range_size (s_mpr) <
	  MATCH_CLASSIFIER_MASK_N_TUPLE_RANGE_MAX)
	{
	  /* There's only one dst port, the src port range is within the
	   * limit. Add individual exactmatch sessions for each port */
	  match_classifier_mk_l4_range_sessions (mcr, s_mpr, true,
						 d_mpr, true, result, app);
	}
      else
	{
	  /* There's only one dst port, the src port range larger than the
	   * limit. Add one session to exact match the dst and clash on the
	   * source */
	  vec_add1 (mcr->mcr_sessions,
		    match_classifier_mk_l4_session (&mcr->mcr_rule,
						    0, false,
						    d_mpr->mpr_begin, true,
						    result, app));
	}
    }
  else
    {
      /* two ranges
       *  this could lead to a session explosion */
      if (match_port_range_size (s_mpr) * match_port_range_size (d_mpr) <
	  MATCH_CLASSIFIER_MASK_N_TUPLE_RANGE_MAX)
	{
	  match_classifier_mk_l4_range_sessions (mcr,
						 s_mpr, true,
						 d_mpr, true, result, app);
	}
      else
	{
	  /* this is more sessions than we're prepared to burn for one rule -
	   * reluctantly we add a range based (and hence colliding) rule */
	  vec_add1 (mcr->mcr_sessions,
		    match_classifier_mk_l4_session (&mcr->mcr_rule,
						    0, false,
						    0, false, result, app));
	}
    }
}

static void
match_classifier_mk_sessions (match_classifier_rule_t * mcr,
			      const match_set_result_t * result,
			      match_engine_classifier_app_t * app)
{
  switch (mcr->mcr_rule.mnt_ip_proto)
    {
    case IP_PROTOCOL_TCP:
    case IP_PROTOCOL_UDP:
      return (match_classifier_mk_l4_sessions (mcr, result, app));
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
      return (match_classifier_mk_icmp_sessions (mcr, result, app));
    case 0:
      return (match_classifier_mk_any_sessions (mcr, result, app));
    default:
      break;
    }
}

static walk_rc_t
match_classifier_mk_walk_rules (const match_rule_t * mr, void *data)
{
  match_classifier_rule_t *mcr;
  match_classifier_ctx_t *ctx = data;

  ASSERT (mr->mr_type == MATCH_TYPE_MASK_N_TUPLE);

  pool_get_zero (match_classifier_rule_pool, mcr);

  vec_add1 (ctx->mcc_list->mcl_rules, mcr - match_classifier_rule_pool);

  mcr->mcr_rule = mr->mr_mask_n_tuple;

  ctx->mcc_result.msr_pos.msp_rule_index = mr->mr_index;

  match_classifier_mk_sessions (mcr, &ctx->mcc_result, ctx->mcc_app);

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
    .mcc_app = data,
    .mcc_result = {
      .msr_user_ctx = mse->mse_usr_ctxt,
      .msr_pos = {
        .msp_list_index = index,
        .msp_rule_index = MATCH_RESULT_MISS,
      },
    },
    .mcc_list = mcl,
  };
  /* *INDENT-ON* */

  vec_add1 (ctx.mcc_app->meca_lists, mcl - match_classifier_list_pool);

  ASSERT (vec_len (ctx.mcc_app->meca_lists) - 1 == index);

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

  return (match_set_pos_is_better (&mcc1->mcc_result.msr_pos,
				   &mcc2->mcc_result.msr_pos));
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

	  match_classifier_mk_session (mcmc->mcmc_table, mcs->mcs_data, ~0,
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
      match_classifier_mk_session (mcmc->mcmc_table, mcs->mcs_data, mcsi, ~0);
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
match_classifier_apply_mask_n_tuple_i (match_set_t * ms,
				       match_engine_classifier_app_t * meca)
{
  /*
   * Translate ech rule in each entry into the correspnding masks and sessions
   */
  match_set_walk_entries (ms, match_classifier_mk_walk_entries, meca);

  if (hash_elts (meca->meca_masks) == 0)
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
  hash_foreach(mcmck, mcmci, meca->meca_masks,
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
      match_classifier_mask_class_mk_table (mcmc, next_table_index,
					    meca->meca_linkt);
  }

  /*
   * Save the first table to search in the engine so we can get it in tht DP
   */
  match_classifier_mask_class_t *mcmc;

  mcmc = pool_elt_at_index (match_classifier_mask_class_pool, masks[0]);

  meca->meca_table_index = mcmc->mcmc_table;

  vec_free (masks);

  /* for each entry/rule add its session to the appropriate classifier table */
  index_t *mcli;

  vec_foreach (mcli, meca->meca_lists)
    match_classifier_list_add_sessions (*mcli);
}

static void
match_classifier_apply_mask_n_tuple (match_set_t * ms,
				     match_semantic_t msem,
				     vnet_link_t linkt,
				     match_set_tag_flags_t flags,
				     match_set_app_t * msa)
{
  match_engine_classifier_app_t *meca;

  pool_get (match_engine_classifier_app_pool, meca);

  meca->meca_table_index = ~0;
  meca->meca_linkt = linkt;
  meca->meca_semantic = msem;

  match_classifier_apply_mask_n_tuple_i (ms, meca);

  msa->msa_index = meca - match_engine_classifier_app_pool;
  msa->msa_match = (AF_IP6 == meca->meca_af ?
		    match_engine_classifier_match_mask_n_tuple_ip6 :
		    match_engine_classifier_match_mask_n_tuple_ip4);
}

static void
match_classifier_teardown (match_engine_classifier_app_t * meca)
{
  index_t *mcli;

  vec_foreach (mcli, meca->meca_lists) match_classifier_list_destroy (*mcli);
  vec_free (meca->meca_lists);

  hash_free (meca->meca_masks);
}

static void
match_classifier_unapply_mask_n_tuple (match_set_t * ms,
				       const match_set_app_t * msa)
{
  match_engine_classifier_app_t *meca;

  meca = pool_elt_at_index (match_engine_classifier_app_pool, msa->msa_index);

  match_classifier_teardown (meca);

  pool_put (match_engine_classifier_app_pool, meca);
}

static void
match_classifier_update_mask_n_tuple (match_set_t * ms,
				      const match_set_app_t * msa)
{
  /* nothing clever here. destroy all state and start again */
  match_engine_classifier_app_t *meca;

  meca = pool_elt_at_index (match_engine_classifier_app_pool, msa->msa_index);

  match_classifier_teardown (meca);
  match_classifier_apply_mask_n_tuple_i (ms, meca);
}

static u8 *
format_match_classifier_app (u8 * s, va_list * args)
{
  match_engine_classifier_app_t *meca;
  match_classifier_mask_class_key_t *mcmck;
  index_t mcmci, *mcli, mb;
  u32 indent;

  mb = va_arg (*args, index_t);
  indent = va_arg (*args, u32);

  meca = pool_elt_at_index (match_engine_classifier_app_pool, mb);

  s = format (s, "%Umatch-classifier: table:%d",
	      format_white_space, indent, meca->meca_table_index);

  /* *INDENT-OFF* */
  hash_foreach (mcmck, mcmci, meca->meca_masks,
  ({
    s = format (s, "\n%U",
                format_match_classifier_mask_class, mcmci, indent + 2);
  }));
  /* *INDENT-ON* */

  vec_foreach (mcli, meca->meca_lists)
    s = format (s, "\n%U", format_match_classifier_list, *mcli, indent + 2);

  return (s);
}

const static match_engine_vft_t mc_vft_first = {
  .mev_apply = match_classifier_apply_mask_n_tuple,
  .mev_update = match_classifier_update_mask_n_tuple,
  .mev_unapply = match_classifier_unapply_mask_n_tuple,
  .mev_format = format_match_classifier_app,
};

static clib_error_t *
match_classifier_mask_n_tuple_init (vlib_main_t * vm)
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
