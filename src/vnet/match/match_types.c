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

#include <vnet/match/match_types.h>
#include <vnet/ethernet/ethernet.h>

#include <vnet/ip/format.h>

u8 *
format_match_type (u8 * s, va_list * args)
{
  match_type_t mt = va_arg (*args, int);

  switch (mt)
    {
#define _(a,b)                                  \
    case MATCH_TYPE_##a:                        \
      return (format (s, "%s", b));
      foreach_match_type
#undef _
    }
  return (format (s, "unknown"));
}

u8 *
format_match_ip_prefix (u8 * s, va_list * args)
{
  const match_ip_prefix_t *mip = va_arg (*args, match_ip_prefix_t *);

  s = format (s, "%U", format_ip_prefix, &mip->mip_ip);

  return (s);
}

u8 *
format_match_mac_mask (u8 * s, va_list * args)
{
  const match_mac_mask_t *mmm = va_arg (*args, match_mac_mask_t *);

  s = format (s, "%U/%U",
	      format_mac_address_t, &mmm->mmm_mac,
	      format_mac_address_t, &mmm->mmm_mask);

  return (s);
}

u8 *
format_match_port_range (u8 * s, va_list * args)
{
  const match_port_range_t *mpr = va_arg (*args, match_port_range_t *);

  s = format (s, "%d -> %d", mpr->mpr_begin, mpr->mpr_end);

  return (s);
}

u8 *
format_match_icmp_code_range (u8 * s, va_list * args)
{
  const match_icmp_code_range_t *micr =
    va_arg (*args, match_icmp_code_range_t *);

  s = format (s, "%d -> %d", micr->micr_begin, micr->micr_end);

  return (s);
}

u8 *
format_match_icmp_type_range (u8 * s, va_list * args)
{
  const match_icmp_type_range_t *mitr =
    va_arg (*args, match_icmp_type_range_t *);

  s = format (s, "%d -> %d", mitr->mitr_begin, mitr->mitr_end);

  return (s);
}

u8 *
format_match_tcp_flags (u8 * s, va_list * args)
{
  const match_tcp_flags_t *mtf = va_arg (*args, match_tcp_flags_t *);

  s = format (s, "0x%x/0x%x", mtf->mtf_flags, mtf->mtf_mask);

  return (s);
}

uword
unformat_match_rule (unformat_input_t * input, va_list * args)
{
  ASSERT (0);
  return (1);
}

u8 *
format_match_mask_n_tuple (u8 * s, va_list * args)
{
  const match_mask_n_tuple_t *mnt = va_arg (*args, match_mask_n_tuple_t *);
  u32 indent = va_arg (*args, u32);

  s = format (s, "\n%U[src:%U dst:%U, %U, ",
	      format_white_space, indent + 2,
	      format_match_ip_prefix, &mnt->mnt_src_ip,
	      format_match_ip_prefix, &mnt->mnt_dst_ip,
	      format_ip_protocol, mnt->mnt_ip_proto);

  if (IP_PROTOCOL_TCP == mnt->mnt_ip_proto ||
      IP_PROTOCOL_UDP == mnt->mnt_ip_proto)
    s = format (s, "sport:[%U] dport:[%U] tcp-flags:[%U]",
		format_match_port_range, &mnt->mnt_src_port,
		format_match_port_range, &mnt->mnt_dst_port,
		format_match_tcp_flags, &mnt->mnt_tcp);
  else
    s = format (s, "types:[%U], codes:[%U]",
		format_match_icmp_type_range, &mnt->mnt_icmp_type,
		format_match_icmp_code_range, &mnt->mnt_icmp_code);
  s = format (s, "]");

  return (s);
}

u8 *
format_match_rule (u8 * s, va_list * args)
{
  const match_rule_t *mr = va_arg (*args, match_rule_t *);
  u32 indent = va_arg (*args, u32);

  s = format (s, "rule: %U proto:%U index:%d",
	      format_match_type, mr->mr_type,
	      format_ethernet_type, mr->mr_proto, mr->mr_index);

  switch (mr->mr_type)
    {
    case MATCH_TYPE_MASK_SRC_IP_MAC:
      s = format (s, "\n%U[%U, %U]",
		  format_white_space, indent + 2,
		  format_match_ip_prefix, &mr->mr_mask_src_ip_mac.mmim_ip,
		  format_match_mac_mask, &mr->mr_mask_src_ip_mac.mmim_mac);
      break;

    case MATCH_TYPE_MASK_N_TUPLE:
      s = format (s, "%U",
		  format_match_mask_n_tuple, &mr->mr_mask_n_tuple, indent);
      break;
    }
  return (s);
}

u8 *
format_match_rule_w_action (u8 * s, va_list * args)
{
  const match_rule_t *mr;
  format_function_t *fn;
  u32 index, indent;
  void *ctx;

  index = va_arg (*args, u32);
  mr = va_arg (*args, match_rule_t *);
  indent = va_arg (*args, u32);
  fn = va_arg (*args, format_function_t *);
  ctx = va_arg (*args, void *);

  s = format (s, "%U => %U", format_match_rule, mr, indent, fn, ctx, index);
  return (s);
}

u8 *
format_match_list (u8 * s, va_list * args)
{
  const match_list_t *ml = va_arg (*args, match_list_t *);
  u32 indent = va_arg (*args, u32);
  u32 mri;

  s = format (s, "match-list: %v", ml->ml_tag);

  vec_foreach_index (mri, ml->ml_rules)
    s = format (s, "\n%U[%d]: %U",
		format_white_space, indent,
		mri, format_match_rule, &ml->ml_rules[mri], indent + 2);

  return (s);
}

u8 *
format_match_list_w_action (u8 * s, va_list * args)
{
  const match_list_t *ml;
  format_function_t *fn;
  u32 mri, indent;
  void *ctx;

  ml = va_arg (*args, match_list_t *);
  indent = va_arg (*args, u32);
  fn = va_arg (*args, format_function_t *);
  ctx = va_arg (*args, void *);

  s = format (s, "match-list: %v", ml->ml_tag);

  vec_foreach_index (mri, ml->ml_rules)
    s = format (s, "\n%U[%d]: %U",
		format_white_space, indent,
		mri,
		format_match_rule_w_action, mri, &ml->ml_rules[mri],
		indent + 2, fn, ctx);

  return (s);
}

ip_address_family_t
match_rule_get_af (const match_rule_t * mr)
{
  switch (mr->mr_type)
    {
    case MATCH_TYPE_MASK_SRC_IP_MAC:
      return (ip_prefix_version (&mr->mr_mask_src_ip_mac.mmim_ip.mip_ip));
    case MATCH_TYPE_MASK_N_TUPLE:
      return (ip_prefix_version (&mr->mr_mask_n_tuple.mnt_src_ip.mip_ip));
    }

  ASSERT (0);
  return (AF_IP4);
}

bool
match_port_range_is_any (const match_port_range_t * mpr)
{
  return ((0 == mpr->mpr_begin) && (0xffff == mpr->mpr_end));
}

bool
match_port_range_is_one (const match_port_range_t * mpr)
{
  return (mpr->mpr_begin == mpr->mpr_end);
}

u16
match_port_range_size (const match_port_range_t * mpr)
{
  return (mpr->mpr_end - mpr->mpr_begin);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
