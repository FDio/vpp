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
#include <vnet/match/engines/classifier/match_classifier_mask_ip_mac_dp.h>

#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>

static u8 *
format_match_classifier_mask_class_key_mask_ip_mac (u8 * s, va_list * args)
{
  match_classifier_mask_class_key_mask_ip_mac_t *mcmck =
    va_arg (*args, match_classifier_mask_class_key_mask_ip_mac_t *);
  u32 indent = va_arg (*args, u32);

  s = format (s, "%U [%U] %U ip /%d %U %U",
	      format_white_space, indent,
	      format_mac_address_t, &mcmck->mcmck_mac,
	      format_ethernet_type, mcmck->mcmck_proto,
	      mcmck->mcmck_ip,
	      format_match_orientation, mcmck->mcmck_orientation,
	      format_match_tag_flags, mcmck->mcmck_flag);

  return (s);
}

static u8 *
match_classifier_push_tag_masks (u8 * s, match_set_tag_flags_t flag)
{
  if (flag == MATCH_SET_TAG_FLAG_0_TAG)
    /* no tag to push */
    ;
  else if (flag == MATCH_SET_TAG_FLAG_1_TAG)
    s = match_classifier_build_vlan_mask (s);
  else if (flag == MATCH_SET_TAG_FLAG_2_TAG)
    {
      s = match_classifier_build_vlan_mask (s);
      s = match_classifier_build_vlan_mask (s);
    }

  return (s);
}

static u8 *
match_classifier_mk_class_mask_arp (const
				    match_classifier_mask_class_key_mask_ip_mac_t
				    * mcmck)
{
  u8 *s;

  s = match_classifier_build_mac_mask2 (NULL,
					mcmck->mcmck_orientation,
					&mcmck->mcmck_mac);
  s = match_classifier_push_tag_masks (s, mcmck->mcmck_flag);
  s = match_classifier_build_arp_mask2 (s,
					mcmck->mcmck_orientation,
					&mcmck->mcmck_mac, mcmck->mcmck_ip);

  return (s);
}

static u8 *
match_classifier_mk_class_mask_ip (const
				   match_classifier_mask_class_key_mask_ip_mac_t
				   * mcmck, ip_address_family_t af)
{
  u8 *s;

  s = match_classifier_build_mac_mask2 (NULL,
					mcmck->mcmck_orientation,
					&mcmck->mcmck_mac);
  s = match_classifier_push_tag_masks (s, mcmck->mcmck_flag);
  s = match_classifier_build_ip_mask2 (s, mcmck->mcmck_orientation, af,
				       mcmck->mcmck_ip, false);
  return (s);
}

static u8 *
match_classifier_mask_class_mk_data_mask_ip_mac (const
						 match_classifier_mask_class_key_t
						 * k)
{
  const match_classifier_mask_class_key_mask_ip_mac_t *mcmck =
    &k->mcmck_mask_ip_mac;

  switch (mcmck->mcmck_proto)
    {
    case ETHERNET_TYPE_ARP:
      return (match_classifier_mk_class_mask_arp (mcmck));
    case ETHERNET_TYPE_IP4:
      return (match_classifier_mk_class_mask_ip (mcmck, AF_IP4));
    case ETHERNET_TYPE_IP6:
      return (match_classifier_mk_class_mask_ip (mcmck, AF_IP6));
    default:
      ASSERT (0);
      break;
    }

  ASSERT (0);
  return (NULL);
}

typedef struct match_classifier_ctx_t_
{
  uword *masks;
  match_set_tag_flags_t flags;
  index_t *mask_vec;
} match_classifier_ctx_t;

static void
match_classifier_mk_key_mask_ip_mac (const match_classifier_rule_t * mcr,
				     match_classifier_mask_class_key_mask_ip_mac_t
				     * mcmck, match_set_tag_flags_t tflag)
{
  const match_rule_t *mr = &mcr->mcr_rule;

  mcmck->mcmck_proto = mr->mr_proto;
  mcmck->mcmck_orientation = mr->mr_orientation;
  mcmck->mcmck_flag = tflag;

  switch (mr->mr_type)
    {
    case MATCH_TYPE_MASK_IP_MAC:
      mac_address_copy (&mcmck->mcmck_mac,
			&mr->mr_mask_ip_mac.mmim_mac.mmm_mask);
      mcmck->mcmck_ip = mr->mr_mask_ip_mac.mmim_ip.mip_ip.len;
      break;
    case MATCH_TYPE_MASK_IP:
    case MATCH_TYPE_EXACT_IP_L4:
    case MATCH_TYPE_EXACT_IP:
    case MATCH_TYPE_MASK_N_TUPLE:
    case MATCH_TYPE_SETS:
      ASSERT (!"unsupported");
    }
}

static u8 *
match_classifier_push_l2_hdrs (u8 * s,
			       match_orientation_t mo,
			       const mac_address_t * mac,
			       ethernet_type_t etype,
			       match_set_tag_flags_t flag)
{
  if (flag & MATCH_SET_TAG_FLAG_0_TAG)
    s = match_classifier_build_mac_hdr2 (s, mo, mac, etype);
  if (flag & MATCH_SET_TAG_FLAG_1_TAG)
    {
      s = match_classifier_build_mac_hdr2 (s, mo, mac, ETHERNET_TYPE_VLAN);
      s = match_classifier_build_vlan_hdr (s, etype);
    }
  if (flag & MATCH_SET_TAG_FLAG_2_TAG)
    {
      s = match_classifier_build_mac_hdr2 (s, mo, mac, ETHERNET_TYPE_DOT1AD);
      s = match_classifier_build_vlan_hdr (s, ETHERNET_TYPE_VLAN);
      s = match_classifier_build_vlan_hdr (s, etype);
    }

  return (s);
}

static index_t
match_classifier_mk_arp_session (match_rule_t * mr,
				 const match_classifier_mask_class_key_t * k,
				 const match_set_pos_t * pos,
				 match_classifier_engine_t * mce)
{
  const match_classifier_mask_class_key_mask_ip_mac_t *mcmck;
  match_classifier_session_t *mcs;

  pool_get_aligned_zero (match_classifier_session_pool, mcs,
			 MATCH_CLASSIFIER_SESSION_ALGIN);

  mcs->mcs_pos = *pos;
  mcs->mcs_result = mr->mr_result;
  mcs->mcs_clash = INDEX_INVALID;

  mcmck = &k->mcmck_mask_ip_mac;
  mcs->mcs_mask =
    match_classifier_mask_class_add_or_lock (MATCH_TYPE_MASK_IP_MAC, mce, k,
					     &mcs->mcs_pos);

  mcs->mcs_data = match_classifier_push_l2_hdrs
    (NULL, mcmck->mcmck_orientation,
     &mr->mr_mask_ip_mac.mmim_mac.mmm_mac,
     ETHERNET_TYPE_ARP, mcmck->mcmck_flag);
  mcs->mcs_data = match_classifier_build_arp_hdr2 (mcs->mcs_data,
						   mcmck->mcmck_orientation,
						   &mr->
						   mr_mask_ip_mac.mmim_mac.
						   mmm_mac,
						   &mr->
						   mr_mask_ip_mac.mmim_ip.
						   mip_ip);

  return (mcs - match_classifier_session_pool);
}

static index_t
match_classifier_mk_ip_session (match_rule_t * mr,
				ip_address_family_t af,
				const match_classifier_mask_class_key_t * k,
				const match_set_pos_t * pos,
				match_classifier_engine_t * mce)
{
  const match_classifier_mask_class_key_mask_ip_mac_t *mcmck;
  match_classifier_session_t *mcs;
  ethernet_type_t etype;

  etype = (AF_IP4 == af ? ETHERNET_TYPE_IP4 : ETHERNET_TYPE_IP6);

  pool_get_aligned_zero (match_classifier_session_pool, mcs,
			 MATCH_CLASSIFIER_SESSION_ALGIN);

  mcs->mcs_pos = *pos;
  mcs->mcs_result = mr->mr_result;
  mcs->mcs_clash = INDEX_INVALID;

  mcmck = &k->mcmck_mask_ip_mac;
  mcs->mcs_mask =
    match_classifier_mask_class_add_or_lock (MATCH_TYPE_MASK_IP_MAC, mce, k,
					     &mcs->mcs_pos);

  mcs->mcs_data = match_classifier_push_l2_hdrs
    (NULL, mcmck->mcmck_orientation,
     &mr->mr_mask_ip_mac.mmim_mac.mmm_mac, etype, mcmck->mcmck_flag);
  mcs->mcs_data = match_classifier_build_ip_hdr2 (mcs->mcs_data,
						  mcmck->mcmck_orientation,
						  &mr->mr_mask_ip_mac.
						  mmim_ip.mip_ip, 0);

  return (mcs - match_classifier_session_pool);
}

static void
match_classifier_mk_sessions (match_classifier_rule_t * mcr,
			      const match_classifier_mask_class_key_t * mcmck,
			      const match_set_pos_t * pos,
			      match_classifier_engine_t * mce)
{
  index_t mcsi;

  switch (mcmck->mcmck_mask_ip_mac.mcmck_proto)
    {
    case ETHERNET_TYPE_ARP:
      mcsi =
	match_classifier_mk_arp_session (&mcr->mcr_rule, mcmck, pos, mce);
      break;
    case ETHERNET_TYPE_IP4:
      mcsi =
	match_classifier_mk_ip_session (&mcr->mcr_rule, AF_IP4, mcmck, pos,
					mce);
      break;
    case ETHERNET_TYPE_IP6:
      mcsi =
	match_classifier_mk_ip_session (&mcr->mcr_rule, AF_IP6, mcmck, pos,
					mce);
      break;
    default:
      ASSERT (0);
      goto crap;
      break;
    }

  vec_add1 (mcr->mcr_sessions, mcsi);
crap:
  return;
}

static void
match_classifier_mk_sessions_mask_ip_mac_i (match_classifier_rule_t * mcr,
					    const match_set_pos_t * pos,
					    match_classifier_engine_t * mce,
					    match_set_tag_flags_t tflags)
{
  match_classifier_mask_class_key_t mcmck;

  match_classifier_mk_key_mask_ip_mac (mcr, &mcmck.mcmck_mask_ip_mac, tflags);

  match_classifier_mk_sessions (mcr, &mcmck, pos, mce);
}

static void
match_classifier_mk_sessions_mask_ip_mac (match_classifier_rule_t * mcr,
					  const match_set_pos_t * pos,
					  match_classifier_engine_t * mce)
{
  if (mce->mce_tag_flags & MATCH_SET_TAG_FLAG_2_TAG)
    match_classifier_mk_sessions_mask_ip_mac_i (mcr, pos, mce,
						MATCH_SET_TAG_FLAG_2_TAG);
  if (mce->mce_tag_flags & MATCH_SET_TAG_FLAG_1_TAG)
    match_classifier_mk_sessions_mask_ip_mac_i (mcr, pos, mce,
						MATCH_SET_TAG_FLAG_1_TAG);
  if (mce->mce_tag_flags & MATCH_SET_TAG_FLAG_0_TAG)
    match_classifier_mk_sessions_mask_ip_mac_i (mcr, pos, mce,
						MATCH_SET_TAG_FLAG_0_TAG);
}

static int
match_classifier_sort_mask_ip_mac (const match_classifier_mask_class_key_t *
				   k1,
				   const match_classifier_mask_class_key_t *
				   k2)
{
  const match_classifier_mask_class_key_mask_ip_mac_t *mcmck1, *mcmck2;

  mcmck1 = &k1->mcmck_mask_ip_mac;
  mcmck2 = &k2->mcmck_mask_ip_mac;

  ASSERT (mcmck1->mcmck_proto == mcmck2->mcmck_proto);

  if (mcmck1->mcmck_ip != mcmck2->mcmck_ip)
    return (mcmck1->mcmck_ip - mcmck2->mcmck_ip);
  return (mac_address_n_bits_set (&mcmck1->mcmck_mac) -
	  mac_address_n_bits_set (&mcmck2->mcmck_mac));
}

/* *INDENT-OFF* */
const static match_classifier_mask_vft_t mcv_mask_ip_mac = {
  .mcv_mk_sessions = match_classifier_mk_sessions_mask_ip_mac,
  .mcv_mk_class_data = match_classifier_mask_class_mk_data_mask_ip_mac,
  .mcv_format_key = format_match_classifier_mask_class_key_mask_ip_mac,
  .mcv_sort = match_classifier_sort_mask_ip_mac,
  .mcv_match = {
    [AF_IP4] = {
      [MATCH_SEMANTIC_ANY] =
      match_classifier_engine_match_mask_src_ip_mac_any,
      [MATCH_SEMANTIC_FIRST] =
      match_classifier_engine_match_mask_src_ip_mac_first,
    },
    [AF_IP6] = {
      [MATCH_SEMANTIC_ANY] =
      match_classifier_engine_match_mask_src_ip_mac_any,
      [MATCH_SEMANTIC_FIRST] =
      match_classifier_engine_match_mask_src_ip_mac_first,
    },
  },
};

const static match_engine_vft_t mc_vft = {
  .mev_apply = match_classifier_apply,
  .mev_unapply = match_classifier_unapply,
  .mev_format = format_match_classifier_engine,
  .mev_list_actions = {
    [MATCH_ENGINE_LIST_ADD] = match_classifier_list_add,
    [MATCH_ENGINE_LIST_REPLACE] = match_classifier_list_replace,
    [MATCH_ENGINE_LIST_DELETE] = match_classifier_list_delete,
  },
};
/* *INDENT-ON* */

static clib_error_t *
match_classifier_init (vlib_main_t * vm)
{
  match_classifier_mask_register (MATCH_TYPE_MASK_IP_MAC, &mcv_mask_ip_mac);

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

  match_engine_register ("classifier", MATCH_TYPE_MASK_IP_MAC,
			 MATCH_SEMANTIC_ANY, &mc_vft, meps);
  match_engine_register ("classifier", MATCH_TYPE_MASK_IP_MAC,
			 MATCH_SEMANTIC_FIRST, &mc_vft, meps);

  vec_free (meps);
  return (NULL);
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (match_classifier_init) =
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
