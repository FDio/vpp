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

#include <vnet/ip/ip_types_api.h>

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
match_rule_mask_ip_mac_decode (const vl_api_match_mask_ip_mac_t * mmim_in,
			       match_rule_t * out)
{
  match_mask_ip_mac_t *mmim_out;
  int rv;

  mmim_out = &out->mr_mask_ip_mac;
  out->mr_type = MATCH_TYPE_MASK_SRC_IP_MAC;

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
match_rule_decode (const vl_api_match_rule_t * in, match_rule_t * out)
{
  int rv;

  rv = match_type_decode (in->mr_type, &out->mr_type);

  if (rv)
    return (rv);

  switch (out->mr_type)
    {
    case MATCH_TYPE_MASK_SRC_IP_MAC:
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
match_rule_encode (const match_rule_t * in, vl_api_match_rule_t * out)
{
  out->mr_type = match_type_encode (in->mr_type);

  switch (in->mr_type)
    {
    case MATCH_TYPE_MASK_SRC_IP_MAC:
      match_rule_mask_ip_mac_encode (in, &out->mr_union.mask_ip_mac);
      break;
    case MATCH_TYPE_MASK_N_TUPLE:
      match_rule_mask_n_tuple_encode (in, &out->mr_union.mask_n_tuple);
      break;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
