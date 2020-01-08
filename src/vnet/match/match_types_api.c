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

#include <vnet/match/match_types_api.h>
#include <vnet/match/match_set.h>

#include <vnet/ip/ip_types_api.h>
#include <vnet/ethernet/ethernet_types_api.h>

int
match_ip_prefix_decode (const vl_api_prefix_t * in, match_ip_prefix_t * out)
{
  ip_prefix_t ip;
  int rv;

  rv = ip_prefix_decode2 (in, &ip);

  match_ip_prefix_set (out, &ip);

  return (rv);
}

int
match_tcp_flags_decode (const vl_api_match_tcp_flags_t * in,
			match_tcp_flags_t * out)
{
  out->mtf_flags = in->mtf_flags;
  out->mtf_mask = in->mtf_mask;

  return (0);
}

void
match_tcp_flags_encode (const match_tcp_flags_t * in,
			vl_api_match_tcp_flags_t * out)
{
  out->mtf_flags = in->mtf_flags;
  out->mtf_mask = in->mtf_mask;
}

void
match_ip_prefix_encode (const match_ip_prefix_t * in, vl_api_prefix_t * out)
{
  ip_prefix_encode2 (&in->mip_ip, out);
}

int
match_port_range_decode (const vl_api_match_port_range_t * in,
			 match_port_range_t * out)
{
  out->mpr_begin = clib_net_to_host_u16 (in->mpr_begin);
  out->mpr_end = clib_net_to_host_u16 (in->mpr_end);

  if (out->mpr_begin > out->mpr_end)
    return (VNET_API_ERROR_EXCEEDED_NUMBER_OF_RANGES_CAPACITY);
  return (0);
}

void
match_port_range_encode (const match_port_range_t * in,
			 vl_api_match_port_range_t * out)
{
  out->mpr_begin = clib_net_to_host_u16 (in->mpr_begin);
  out->mpr_end = clib_net_to_host_u16 (in->mpr_end);
}

void
match_mac_mask_decode (const vl_api_match_mac_mask_t * in,
		       match_mac_mask_t * out)
{
  mac_address_from_bytes (&out->mmm_mac, in->mmm_mac);
  mac_address_from_bytes (&out->mmm_mask, in->mmm_mask);
}

void
match_mac_mask_encode (const match_mac_mask_t * in,
		       vl_api_match_mac_mask_t * out)
{
  mac_address_to_bytes (&in->mmm_mac, out->mmm_mac);
  mac_address_to_bytes (&in->mmm_mask, out->mmm_mask);
}

void
match_icmp_code_range_decode (const vl_api_match_icmp_code_range_t * in,
			      match_icmp_code_range_t * out)
{
  out->micr_begin = in->micr_begin;
  out->micr_end = in->micr_end;
}

void
match_icmp_type_range_decode (const vl_api_match_icmp_type_range_t * in,
			      match_icmp_type_range_t * out)
{
  out->mitr_begin = in->mitr_begin;
  out->mitr_end = in->mitr_end;
}

void
match_icmp_code_range_encode (const match_icmp_code_range_t * in,
			      vl_api_match_icmp_code_range_t * out)
{
  out->micr_begin = in->micr_begin;
  out->micr_end = in->micr_end;
}

void
match_icmp_type_range_encode (const match_icmp_type_range_t * in,
			      vl_api_match_icmp_type_range_t * out)
{
  out->mitr_begin = in->mitr_begin;
  out->mitr_end = in->mitr_end;
}

int
match_type_decode (vl_api_match_type_t in, match_type_t * out)
{
  switch (in)
    {
#define _(a,b) case MATCH_API_TYPE_##a: \
      *out = MATCH_TYPE_##a;            \
      return (0);
      foreach_match_type
#undef _
    }

  return (VNET_API_ERROR_INVALID_VALUE);
}

vl_api_match_type_t
match_type_encode (match_type_t in)
{
  return ((vl_api_match_type_t) in);
}

int
match_orientation_decode (vl_api_match_orientation_t in,
			  match_orientation_t * out)
{
  switch (in)
    {
    case MATCH_API_SRC:
      *out = MATCH_SRC;
      return (0);
    case MATCH_API_DST:
      *out = MATCH_DST;
      return (0);
    }

  return (VNET_API_ERROR_INVALID_VALUE);
}

vl_api_match_orientation_t
match_orientation_encode (match_orientation_t in)
{
  return ((vl_api_match_orientation_t) in);
}

int
match_rule_mask_ip_mac_decode (const vl_api_match_mask_ip_mac_t * mmim_in,
			       match_rule_t * out)
{
  match_mask_ip_mac_t *mmim_out;
  int rv;

  mmim_out = &out->mr_mask_ip_mac;

  rv = match_ip_prefix_decode (&mmim_in->mmim_ip, &mmim_out->mmim_ip);
  match_mac_mask_decode (&mmim_in->mmim_mac, &mmim_out->mmim_mac);

  return (rv);
}

void
match_rule_mask_ip_mac_encode (const match_rule_t * in,
			       vl_api_match_mask_ip_mac_t * mmim_out)
{
  const match_mask_ip_mac_t *mmim_in = &in->mr_mask_ip_mac;

  match_ip_prefix_encode (&mmim_in->mmim_ip, &mmim_out->mmim_ip);
  match_mac_mask_encode (&mmim_in->mmim_mac, &mmim_out->mmim_mac);
}

int
match_rule_mask_n_tuple_decode (const vl_api_match_mask_n_tuple_t * mnt_in,
				match_rule_t * out)
{
  match_mask_n_tuple_t *mnt_out;
  int rv;

  mnt_out = &out->mr_mask_n_tuple;
  out->mr_type = MATCH_TYPE_MASK_N_TUPLE;

  rv = match_ip_prefix_decode (&mnt_in->mnt_src_ip, &mnt_out->mnt_src_ip);
  if (rv)
    return (VNET_API_ERROR_INVALID_SRC_ADDRESS);

  rv = match_ip_prefix_decode (&mnt_in->mnt_dst_ip, &mnt_out->mnt_dst_ip);

  if (rv)
    return (VNET_API_ERROR_INVALID_DST_ADDRESS);

  rv = ip_proto_decode (mnt_in->mnt_proto, &mnt_out->mnt_ip_proto);

  if (rv)
    return (rv);

  switch (mnt_out->mnt_ip_proto)
    {
    case IP_PROTOCOL_UDP:
    case IP_PROTOCOL_TCP:
      rv = match_port_range_decode (&mnt_in->mnt_l4.mlu_l4.ml4_src_port,
				    &mnt_out->mnt_src_port);
      rv |=
	match_port_range_decode (&mnt_in->mnt_l4.mlu_l4.ml4_dst_port,
				 &mnt_out->mnt_dst_port);
      if (rv)
	return (VNET_API_ERROR_INVALID_VALUE_2);

      return (match_tcp_flags_decode (&mnt_in->mnt_l4.mlu_l4.ml4_tcp,
				      &mnt_out->mnt_tcp));
      break;
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
      match_icmp_type_range_decode (&mnt_in->mnt_l4.mlu_icmp.mir_types,
				    &mnt_out->mnt_icmp_type);
      match_icmp_code_range_decode (&mnt_in->mnt_l4.mlu_icmp.mir_codes,
				    &mnt_out->mnt_icmp_code);
    default:
      break;
    }

  return (0);
}

int
match_rule_exact_ip_l4_decode (const vl_api_match_exact_ip_l4_t * meil_in,
			       match_rule_t * out)
{
  match_exact_ip_l4_t *meil_out;
  int rv;

  meil_out = &out->mr_exact_ip_l4;
  out->mr_type = MATCH_TYPE_EXACT_IP_L4;

  ip_address_decode2 (&meil_in->meil_ip, &meil_out->meil_ip);

  rv = ip_proto_decode (meil_in->meil_proto, &meil_out->meil_proto);

  if (rv)
    return (rv);

  switch (meil_out->meil_proto)
    {
    case IP_PROTOCOL_UDP:
    case IP_PROTOCOL_TCP:
      /* leave the port in network byte order */
      meil_out->meil_l4.ml_port = meil_in->meil_l4.mel4_port;
      break;
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
      meil_out->meil_l4.ml_icmp.mi_type = meil_in->meil_l4.mel4_icmp.mi_type;
      meil_out->meil_l4.ml_icmp.mi_code = meil_in->meil_l4.mel4_icmp.mi_code;
    default:
      break;
    }

  return (0);
}

void
match_rule_exact_ip_l4_encode (const match_rule_t * in,
			       vl_api_match_exact_ip_l4_t * meil_out)
{
  const match_exact_ip_l4_t *meil_in;

  meil_in = &in->mr_exact_ip_l4;

  ip_address_encode2 (&meil_in->meil_ip, &meil_out->meil_ip);

  meil_out->meil_proto = ip_proto_encode (meil_in->meil_proto);

  switch (meil_in->meil_proto)
    {
    case IP_PROTOCOL_UDP:
    case IP_PROTOCOL_TCP:
      meil_out->meil_l4.mel4_port = meil_in->meil_l4.ml_port;
      break;
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
      meil_out->meil_l4.mel4_icmp.mi_type = meil_in->meil_l4.ml_icmp.mi_type;
      meil_out->meil_l4.mel4_icmp.mi_code = meil_in->meil_l4.ml_icmp.mi_code;
    default:
      break;
    }
}

int
match_rule_sets_decode (const vl_api_match_sets_t * in, match_rule_t * out)
{
  index_t msi;

  msi = clib_host_to_net_u32 (in->mss_src);

  if (match_set_index_is_valid (msi) || INDEX_INVALID == msi)
    out->mr_sets.mss_set[MATCH_SRC] = msi;
  else
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  msi = clib_host_to_net_u32 (in->mss_dst);

  if (match_set_index_is_valid (msi) || INDEX_INVALID == msi)
    out->mr_sets.mss_set[MATCH_DST] = msi;
  else
    return (VNET_API_ERROR_NO_SUCH_ENTRY);

  return (0);
}

int
match_rule_decode (const vl_api_match_rule_t * in, match_rule_t * out)
{
  int rv;

  rv = match_type_decode (in->mr_type, &out->mr_type);

  if (rv)
    return (rv);

  rv = match_orientation_decode (in->mr_orientation, &out->mr_orientation);

  if (rv)
    return (rv);

  rv = ether_type_decode (in->mr_proto, &out->mr_proto);

  if (rv)
    return (rv);

  switch (out->mr_type)
    {
    case MATCH_TYPE_SETS:
      return (match_rule_sets_decode (&in->mr_union.sets, out));
      break;
    case MATCH_TYPE_EXACT_IP:
      ip_address_decode2 (&in->mr_union.exact_ip, &out->mr_exact_ip);
      break;
    case MATCH_TYPE_EXACT_IP_L4:
      return (match_rule_exact_ip_l4_decode (&in->mr_union.exact_ip_l4, out));
    case MATCH_TYPE_MASK_IP:
      return (match_ip_prefix_decode
	      (&in->mr_union.mask_ip, &out->mr_mask_ip));
    case MATCH_TYPE_MASK_IP_MAC:
      return (match_rule_mask_ip_mac_decode (&in->mr_union.mask_ip_mac, out));
    case MATCH_TYPE_MASK_N_TUPLE:
      return (match_rule_mask_n_tuple_decode
	      (&in->mr_union.mask_n_tuple, out));
    }

  return (rv);
}

void
match_rule_mask_n_tuple_encode (const match_rule_t * in,
				vl_api_match_mask_n_tuple_t * out)
{
  const match_mask_n_tuple_t *mnt = &in->mr_mask_n_tuple;

  match_ip_prefix_encode (&mnt->mnt_src_ip, &out->mnt_src_ip);
  match_ip_prefix_encode (&mnt->mnt_dst_ip, &out->mnt_dst_ip);

  out->mnt_proto = ip_proto_encode (mnt->mnt_ip_proto);

  switch (mnt->mnt_ip_proto)
    {
    case IP_PROTOCOL_UDP:
    case IP_PROTOCOL_TCP:
      match_port_range_encode (&mnt->mnt_src_port,
			       &out->mnt_l4.mlu_l4.ml4_src_port);
      match_port_range_encode (&mnt->mnt_dst_port,
			       &out->mnt_l4.mlu_l4.ml4_dst_port);
      match_tcp_flags_encode (&mnt->mnt_tcp, &out->mnt_l4.mlu_l4.ml4_tcp);
      break;
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
      match_icmp_type_range_encode (&mnt->mnt_icmp_type,
				    &out->mnt_l4.mlu_icmp.mir_types);
      match_icmp_code_range_encode (&mnt->mnt_icmp_code,
				    &out->mnt_l4.mlu_icmp.mir_codes);
    default:
      break;
    }
}

void
match_rule_sets_encode (const match_rule_t * in, vl_api_match_sets_t * out)
{
  out->mss_src = clib_host_to_net_u32 (in->mr_sets.mss_set[MATCH_SRC]);
  out->mss_dst = clib_host_to_net_u32 (in->mr_sets.mss_set[MATCH_DST]);
}

void
match_rule_encode (const match_rule_t * in, vl_api_match_rule_t * out)
{
  out->mr_type = match_type_encode (in->mr_type);
  out->mr_orientation = match_orientation_encode (in->mr_orientation);
  out->mr_proto = ether_type_encode (in->mr_proto);

  switch (in->mr_type)
    {
    case MATCH_TYPE_SETS:
      match_rule_sets_encode (in, &out->mr_union.sets);
      break;
    case MATCH_TYPE_MASK_IP_MAC:
      match_rule_mask_ip_mac_encode (in, &out->mr_union.mask_ip_mac);
      break;
    case MATCH_TYPE_EXACT_IP_L4:
      match_rule_exact_ip_l4_encode (in, &out->mr_union.exact_ip_l4);
      break;
    case MATCH_TYPE_MASK_N_TUPLE:
      match_rule_mask_n_tuple_encode (in, &out->mr_union.mask_n_tuple);
      break;
    case MATCH_TYPE_MASK_IP:
      match_ip_prefix_encode (&in->mr_mask_ip, &out->mr_union.mask_ip);
      break;
    case MATCH_TYPE_EXACT_IP:
      ip_address_encode2 (&in->mr_exact_ip, &out->mr_union.exact_ip);
      break;
    }
}

void
match_list_encode (const match_list_t * in, vl_api_match_list_t * out)
{
  ASSERT (0);
}

int
match_list_decode (const vl_api_match_list_t * in, match_list_t * out)
{
  u16 r, n_rules;
  int rv;

  rv = 0;
  n_rules = ntohs (in->ml_n_rules);

  match_list_init (out, NULL, n_rules);

  for (r = 0; r < n_rules; r++)
    {
      match_rule_t rule;

      rv = match_rule_decode (&in->ml_rules[r], &rule);

      if (rv)
	{
	  match_list_free (out);
	  break;
	}

      match_list_push_back (out, &rule);
    }

  return (rv);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
