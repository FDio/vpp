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

#ifndef __MATCH_ENGINE_LINEAR_DP_H__
#define __MATCH_ENGINE_LINEAR_DP_H__

#include <vnet/match/match_set.h>
#include <vnet/match/match_types_dp.h>
#include <vnet/match/engines/linear/match_linear.h>

#include <vnet/ethernet/arp_packet.h>

static_always_inline bool
match_engine_linear_mask_ip4_mac (match_orientation_t mo,
				  const ethernet_header_t * eh,
				  const ip4_header_t * ip,
				  const match_rule_t * mr)
{
  if (!match_mac_mask (&mr->mr_mask_ip_mac.mmim_mac,
		       ethernet_header_address (mo, eh)))
    return (false);

  return (match_ip4_prefix (&mr->mr_mask_ip_mac.mmim_ip,
			    ip4_header_address (mo, ip)));
}

static_always_inline bool
match_engine_linear_mask_arp_mac (match_orientation_t mo,
				  const ethernet_header_t * eh,
				  const ethernet_arp_header_t * arp,
				  const match_rule_t * mr)
{
  u8 who = (MATCH_SRC == mo ? ARP_SENDER : ARP_TARGET);

  if (!match_mac_mask (&mr->mr_mask_ip_mac.mmim_mac,
		       ethernet_header_address (mo, eh)))
    return (false);

  if (!match_mac_mask (&mr->mr_mask_ip_mac.mmim_mac,
		       arp->ip4_over_ethernet[who].mac.bytes))
    return (false);

  return (match_ip4_prefix (&mr->mr_mask_ip_mac.mmim_ip,
			    &arp->ip4_over_ethernet[who].ip4));
}

static_always_inline bool
match_engine_linear_mask_ip6_mac (match_orientation_t mo,
				  const ethernet_header_t * eh,
				  const ip6_header_t * ip,
				  const match_rule_t * mr)
{
  if (!match_mac_mask (&mr->mr_mask_ip_mac.mmim_mac,
		       ethernet_header_address (mo, eh)))
    return (false);

  return (match_ip6_prefix (&mr->mr_mask_ip_mac.mmim_ip,
			    ip6_header_address (mo, ip)));
}

static_always_inline bool
match_engine_linear_mask_ip6 (match_orientation_t mo,
			      const ip6_header_t * ip,
			      const match_rule_t * mr)
{
  return (match_ip6_prefix (&mr->mr_mask_ip_mac.mmim_ip,
			    ip6_header_address (mo, ip)));
}

static_always_inline bool
match_engine_linear_mask_ip4 (match_orientation_t mo,
			      const ip4_header_t * ip,
			      const match_rule_t * mr)
{
  return (match_ip4_prefix (&mr->mr_mask_ip_mac.mmim_ip,
			    ip4_header_address (mo, ip)));
}

static_always_inline bool
match_engine_linear_exact_ip6 (match_orientation_t mo,
			       const ip6_header_t * ip,
			       const match_rule_t * mr)
{
  return (ip6_address_is_equal (&mr->mr_exact_ip.ip.ip6,
				ip6_header_address (mo, ip)));
}

static_always_inline bool
match_engine_linear_exact_ip4 (match_orientation_t mo,
			       const ip4_header_t * ip,
			       const match_rule_t * mr)
{
  return (ip4_address_is_equal (&mr->mr_exact_ip.ip.ip4,
				ip4_header_address (mo, ip)));
}

static_always_inline bool
match_engine_linear_match (vlib_main_t * vm,
			   vlib_buffer_t * b,
			   i16 l2_offset,
			   i16 l3_offset,
			   const match_set_app_t * app,
			   f64 now,
			   match_result_t * res,
			   match_type_t mtype,
			   match_orientation_t mo, ethernet_type_t etype)
{
  const match_engine_linear_t *mel0;
  const ethernet_arp_header_t *arp0;
  const match_set_entry_t *mse0;
  const ethernet_header_t *eh0;
  const ip4_header_t *ip40;
  const ip6_header_t *ip60;
  const match_rule_t *mr0;
  const match_set_t *ms0;
  const index_t *msei0;
  bool match0;
  u32 mri0;

  /* get the table to search in */
  mel0 = pool_elt_at_index (match_engine_linear_pool, app->msa_index);
  ms0 = match_set_get (mel0->mel_set);

  eh0 = vlib_buffer_get_current (b) + l2_offset;
  ip40 = vlib_buffer_get_current (b) + l3_offset;
  ip60 = (ip6_header_t *) (ip40);
  arp0 = (ethernet_arp_header_t *) (ip40);
  match0 = false;

  /* walk each entry */
  vec_foreach (msei0, ms0->ms_entries)
  {
    mse0 = match_set_entry_get (*msei0);

    vec_foreach_index (mri0, mse0->mse_list.ml_rules)
    {
      mr0 = &mse0->mse_list.ml_rules[mri0];

      if (mri0 < vec_len (mse0->mse_list.ml_rules) - 2)
	CLIB_PREFETCH (&mse0->mse_list.ml_rules[mri0 + 1],
		       sizeof (match_rule_t), STORE);

      switch (mtype)
	{
	case MATCH_TYPE_MASK_IP_MAC:
	  if (ETHERNET_TYPE_IP4 == etype)
	    match0 = match_engine_linear_mask_ip4_mac (mo, eh0, ip40, mr0);
	  else if (ETHERNET_TYPE_IP6 == etype)
	    match0 = match_engine_linear_mask_ip6_mac (mo, eh0, ip60, mr0);
	  else if (ETHERNET_TYPE_ARP == etype)
	    match0 = match_engine_linear_mask_arp_mac (mo, eh0, arp0, mr0);
	  else
	    match0 = false;
	  break;
	case MATCH_TYPE_MASK_IP:
	  if (ETHERNET_TYPE_IP4 == etype)
	    match0 = match_engine_linear_mask_ip4 (mo, ip40, mr0);
	  else if (ETHERNET_TYPE_IP6 == etype)
	    match0 = match_engine_linear_mask_ip6 (mo, ip60, mr0);
	  else
	    match0 = false;
	  break;
	case MATCH_TYPE_EXACT_IP:
	  if (ETHERNET_TYPE_IP4 == etype)
	    match0 = match_engine_linear_exact_ip4 (mo, ip40, mr0);
	  else if (ETHERNET_TYPE_IP6 == etype)
	    match0 = match_engine_linear_exact_ip6 (mo, ip60, mr0);
	  else
	    match0 = false;
	  break;
	case MATCH_TYPE_EXACT_IP_L4:
	  if (ETHERNET_TYPE_IP4 == etype)
	    match0 = match_exact_ip4_l4 (mo, ip40, &mr0->mr_exact_ip_l4);
	  else if (ETHERNET_TYPE_IP6 == etype)
	    match0 = match_exact_ip6_l4 (mo, ip60, &mr0->mr_exact_ip_l4);
	  else
	    match0 = false;
	  break;
	case MATCH_TYPE_MASK_N_TUPLE:
	  if (ETHERNET_TYPE_IP4 == etype)
	    match0 = match_ip4_mask_n_tuple (ip40, &mr0->mr_mask_n_tuple);
	  else if (ETHERNET_TYPE_IP6 == etype)
	    match0 = match_ip6_mask_n_tuple (ip60, &mr0->mr_mask_n_tuple);
	  else
	    match0 = false;
	  break;
	case MATCH_TYPE_SETS:
	  match0 = false;
	  break;
	}

      if (match0)
	{
	  *res = mr0->mr_result;
	  return (match0);
	}
    }
  }
  return (match0);
}

static_always_inline bool
match_engine_linear_match_sets_rule (vlib_main_t * vm,
				     match_engine_linear_t * mel0,
				     const match_sets_t * mss,
				     u32 count,
				     vlib_buffer_t * b,
				     i16 l2_offset, i16 l3_offset, f64 now)
{
  match_orientation_t mo;

  FOR_EACH_MATCH_ORIENTATION (mo)
  {
    if (match_set_app_is_valid (&mel0->mel_app[mo][count]))
      {
	if (!clib_bitmap_get (mel0->mel_bitmap[mo], mss->mss_set[mo]))
	  {
	    mel0->mel_match[mo][count] =
	      match_match_one (vm, b, l2_offset, l3_offset,
			       &mel0->mel_app[mo][count], now,
			       &mel0->mel_res[mo][count]);
	    clib_bitmap_set (mel0->mel_bitmap[mo], mss->mss_set[mo], 1);
	  }
      }
    else
      mel0->mel_match[mo][count] = true;
  }

  return (mel0->mel_match[MATCH_SRC][count] &&
	  mel0->mel_match[MATCH_DST][count]);
}

static_always_inline bool
match_engine_linear_match_sets (vlib_main_t * vm,
				vlib_buffer_t * b,
				i16 l2_offset,
				i16 l3_offset,
				const match_set_app_t * app,
				f64 now, match_result_t * res)
{
  const match_set_entry_t *mse0;
  match_engine_linear_t *mel0;
  const match_rule_t *mr0;
  const match_set_t *ms0;
  const index_t *msei0;
  u32 mri0, count;
  bool match0;

  /* get the table to search in */
  count = 0;
  mel0 = pool_elt_at_index (match_engine_linear_pool, app->msa_index);
  ms0 = match_set_get (mel0->mel_set);

  clib_bitmap_zero (mel0->mel_bitmap[MATCH_SRC]);
  clib_bitmap_zero (mel0->mel_bitmap[MATCH_DST]);

  /* walk each entry */
  vec_foreach (msei0, ms0->ms_entries)
  {
    mse0 = match_set_entry_get (*msei0);

    vec_foreach_index (mri0, mse0->mse_list.ml_rules)
    {
      mr0 = &mse0->mse_list.ml_rules[mri0];

      if (mri0 < vec_len (mse0->mse_list.ml_rules) - 2)
	CLIB_PREFETCH (&mse0->mse_list.ml_rules[mri0 + 1],
		       sizeof (match_rule_t), STORE);

      match0 = match_engine_linear_match_sets_rule (vm, mel0, &mr0->mr_sets,
						    count++, b, l2_offset,
						    l3_offset, now);

      if (match0)
	{
	  *res = mr0->mr_result;
	  return (match0);
	}
    }
  }

  return (match0);
}

/**
 * Data-plane function to go match
 */
static_always_inline bool
match_engine_linear_match_mask_ip_mac_src_ip4 (vlib_main_t * vm,
					       vlib_buffer_t * buf,
					       i16 l2_offset,
					       i16 l3_offset,
					       const match_set_app_t * app,
					       f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_MASK_IP_MAC, MATCH_SRC, ETHERNET_TYPE_IP4));
}

static_always_inline bool
match_engine_linear_match_mask_ip_mac_src_ip6 (vlib_main_t * vm,
					       vlib_buffer_t * buf,
					       i16 l2_offset,
					       i16 l3_offset,
					       const match_set_app_t * app,
					       f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_MASK_IP_MAC, MATCH_SRC, ETHERNET_TYPE_IP6));
}

static_always_inline bool
match_engine_linear_match_mask_ip_mac_src_arp (vlib_main_t * vm,
					       vlib_buffer_t * buf,
					       i16 l2_offset,
					       i16 l3_offset,
					       const match_set_app_t * app,
					       f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_MASK_IP_MAC, MATCH_SRC, ETHERNET_TYPE_ARP));
}

static_always_inline bool
match_engine_linear_match_mask_ip_mac_dst_arp (vlib_main_t * vm,
					       vlib_buffer_t * buf,
					       i16 l2_offset,
					       i16 l3_offset,
					       const match_set_app_t * app,
					       f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_MASK_IP_MAC, MATCH_DST, ETHERNET_TYPE_ARP));
}

static_always_inline bool
match_engine_linear_match_mask_ip_mac_dst_ip4 (vlib_main_t * vm,
					       vlib_buffer_t * buf,
					       i16 l2_offset,
					       i16 l3_offset,
					       const match_set_app_t * app,
					       f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_MASK_IP_MAC, MATCH_DST, ETHERNET_TYPE_IP4));
}

static_always_inline bool
match_engine_linear_match_mask_ip_mac_dst_ip6 (vlib_main_t * vm,
					       vlib_buffer_t * buf,
					       i16 l2_offset,
					       i16 l3_offset,
					       const match_set_app_t * app,
					       f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_MASK_IP_MAC, MATCH_DST, ETHERNET_TYPE_IP6));
}

static_always_inline bool
match_engine_linear_match_mask_ip_src_ip4 (vlib_main_t * vm,
					   vlib_buffer_t * buf,
					   i16 l2_offset,
					   i16 l3_offset,
					   const match_set_app_t * app,
					   f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res, MATCH_TYPE_MASK_IP,
	   MATCH_SRC, ETHERNET_TYPE_IP4));
}

static_always_inline bool
match_engine_linear_match_mask_ip_src_ip6 (vlib_main_t * vm,
					   vlib_buffer_t * buf,
					   i16 l2_offset,
					   i16 l3_offset,
					   const match_set_app_t * app,
					   f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res, MATCH_TYPE_MASK_IP,
	   MATCH_SRC, ETHERNET_TYPE_IP6));
}

static_always_inline bool
match_engine_linear_match_mask_ip_dst_ip4 (vlib_main_t * vm,
					   vlib_buffer_t * buf,
					   i16 l2_offset,
					   i16 l3_offset,
					   const match_set_app_t * app,
					   f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res, MATCH_TYPE_MASK_IP,
	   MATCH_DST, ETHERNET_TYPE_IP4));
}

static_always_inline bool
match_engine_linear_match_mask_ip_dst_ip6 (vlib_main_t * vm,
					   vlib_buffer_t * buf,
					   i16 l2_offset,
					   i16 l3_offset,
					   const match_set_app_t * app,
					   f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res, MATCH_TYPE_MASK_IP,
	   MATCH_DST, ETHERNET_TYPE_IP6));
}

static_always_inline bool
match_engine_linear_match_exact_ip_src_ip4 (vlib_main_t * vm,
					    vlib_buffer_t * buf,
					    i16 l2_offset,
					    i16 l3_offset,
					    const match_set_app_t * app,
					    f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res, MATCH_TYPE_EXACT_IP,
	   MATCH_SRC, ETHERNET_TYPE_IP4));
}

static_always_inline bool
match_engine_linear_match_exact_ip_src_ip6 (vlib_main_t * vm,
					    vlib_buffer_t * buf,
					    i16 l2_offset,
					    i16 l3_offset,
					    const match_set_app_t * app,
					    f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res, MATCH_TYPE_EXACT_IP,
	   MATCH_SRC, ETHERNET_TYPE_IP6));
}

static_always_inline bool
match_engine_linear_match_exact_ip_dst_ip4 (vlib_main_t * vm,
					    vlib_buffer_t * buf,
					    i16 l2_offset,
					    i16 l3_offset,
					    const match_set_app_t * app,
					    f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res, MATCH_TYPE_EXACT_IP,
	   MATCH_DST, ETHERNET_TYPE_IP4));
}

static_always_inline bool
match_engine_linear_match_exact_ip_dst_ip6 (vlib_main_t * vm,
					    vlib_buffer_t * buf,
					    i16 l2_offset,
					    i16 l3_offset,
					    const match_set_app_t * app,
					    f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res, MATCH_TYPE_EXACT_IP,
	   MATCH_DST, ETHERNET_TYPE_IP6));
}

static_always_inline bool
match_engine_linear_match_exact_ip_l4_src_ip4 (vlib_main_t * vm,
					       vlib_buffer_t * buf,
					       i16 l2_offset,
					       i16 l3_offset,
					       const match_set_app_t * app,
					       f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_EXACT_IP_L4, MATCH_SRC, ETHERNET_TYPE_IP4));
}

static_always_inline bool
match_engine_linear_match_exact_ip_l4_src_ip6 (vlib_main_t * vm,
					       vlib_buffer_t * buf,
					       i16 l2_offset,
					       i16 l3_offset,
					       const match_set_app_t * app,
					       f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_EXACT_IP_L4, MATCH_SRC, ETHERNET_TYPE_IP6));
}

static_always_inline bool
match_engine_linear_match_exact_ip_l4_dst_ip4 (vlib_main_t * vm,
					       vlib_buffer_t * buf,
					       i16 l2_offset,
					       i16 l3_offset,
					       const match_set_app_t * app,
					       f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_EXACT_IP_L4, MATCH_DST, ETHERNET_TYPE_IP4));
}

static_always_inline bool
match_engine_linear_match_exact_ip_l4_dst_ip6 (vlib_main_t * vm,
					       vlib_buffer_t * buf,
					       i16 l2_offset,
					       i16 l3_offset,
					       const match_set_app_t * app,
					       f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_EXACT_IP_L4, MATCH_DST, ETHERNET_TYPE_IP6));
}

static_always_inline bool
match_engine_linear_match_mask_n_tuple_ip4 (vlib_main_t * vm,
					    vlib_buffer_t * buf,
					    i16 l2_offset,
					    i16 l3_offset,
					    const match_set_app_t * app,
					    f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_MASK_N_TUPLE, MATCH_BOTH, ETHERNET_TYPE_IP4));
}

static_always_inline bool
match_engine_linear_match_mask_n_tuple_ip6 (vlib_main_t * vm,
					    vlib_buffer_t * buf,
					    i16 l2_offset,
					    i16 l3_offset,
					    const match_set_app_t * app,
					    f64 now, match_result_t * res)
{
  return (match_engine_linear_match
	  (vm, buf, l2_offset, l3_offset, app, now, res,
	   MATCH_TYPE_MASK_N_TUPLE, MATCH_BOTH, ETHERNET_TYPE_IP6));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
