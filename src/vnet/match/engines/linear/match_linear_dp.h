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

static_always_inline bool
match_engine_linear_mask_src_ip4_mac (const ethernet_header_t * eh,
				      const ip4_header_t * ip,
				      const match_rule_t * mr)
{
  if (AF_IP6 == ip_addr_version (&mr->mr_mask_ip_mac.mmim_ip.mip_ip.addr))
    return (false);

  if (!match_mac_mask (&mr->mr_mask_ip_mac.mmim_mac, eh->src_address))
    return (false);

  return (match_ip4_prefix (&mr->mr_mask_ip_mac.mmim_ip, &ip->src_address));
}

static_always_inline bool
match_engine_linear_mask_src_ip6_mac (const ethernet_header_t * eh,
				      const ip6_header_t * ip,
				      const match_rule_t * mr)
{
  if (AF_IP4 == ip_addr_version (&mr->mr_mask_ip_mac.mmim_ip.mip_ip.addr))
    return (false);

  if (!match_mac_mask (&mr->mr_mask_ip_mac.mmim_mac, eh->src_address))
    return (false);

  return (match_ip6_prefix (&mr->mr_mask_ip_mac.mmim_ip, &ip->src_address));
}

static_always_inline void
match_engine_linear_match (vlib_main_t * vm,
			   vlib_buffer_t * b,
			   const match_set_app_t * app,
			   f64 now,
			   match_set_result_t * res, match_type_t mtype)
{
  const match_engine_linear_t *mel0;
  const match_set_entry_t *mse0;
  const ethernet_header_t *eh0;
  const ip4_header_t *ip40;
  const ip6_header_t *ip60;
  const match_rule_t *mr0;
  const match_set_t *ms0;
  const index_t *msei0;
  u32 mri0;
  bool match0;

  /* get the table to search in */
  mel0 = pool_elt_at_index (match_engine_linear_pool, app->msa_index);
  ms0 = match_set_get (mel0->mel_set);

  eh0 = vlib_buffer_get_current (b);

  if (VNET_LINK_IP4 == mel0->mel_linkt || VNET_LINK_IP6 == mel0->mel_linkt)
    {
      ip40 = vlib_buffer_get_current (b);
      ip60 = vlib_buffer_get_current (b);
    }
  else
    {
      ip40 = (ip4_header_t *) ((u8 *) eh0 + vnet_buffer (b)->l2.l2_len);
      ip60 = (ip6_header_t *) (ip40);
    }
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
	case MATCH_TYPE_MASK_SRC_IP_MAC:
	  match0 = match_engine_linear_mask_src_ip4_mac (eh0, ip40, mr0);
	  match0 |= match_engine_linear_mask_src_ip6_mac (eh0, ip60, mr0);
	  break;
	case MATCH_TYPE_MASK_N_TUPLE:
	  match0 = match_ip4_mask_n_tuple (ip40, &mr0->mr_mask_n_tuple);
	  match0 |= match_ip6_mask_n_tuple (ip60, &mr0->mr_mask_n_tuple);
	}

      if (match0)
	{
	  res->msr_pos.msp_list_index = msei0 - ms0->ms_entries;
	  res->msr_pos.msp_rule_index = mr0->mr_index;
	  res->msr_user_ctx = mse0->mse_usr_ctxt;
	  return;
	}
    }
  }
  *res = MATCH_SET_RESULT_MISS;
}

/**
 * Data-plane function to go match
 */
#define _(a,b)                                                          \
static_always_inline void                                               \
match_engine_linear_match_##a (vlib_main_t * vm,                        \
                               vlib_buffer_t *buf,                      \
                               const match_set_app_t *app,              \
                               f64 now,                                 \
                               match_set_result_t * res)                \
{                                                                       \
  match_engine_linear_match(vm, buf, app, now, res, MATCH_TYPE_##a);    \
}
foreach_match_type
#undef _
#endif
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
