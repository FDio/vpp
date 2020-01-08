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
#include <vnet/match/match_set.h>
#include <vnet/ethernet/ethernet.h>

#include <vnet/ip/ip.h>

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
format_match_orientation (u8 * s, va_list * args)
{
  match_orientation_t mo = va_arg (*args, int);

  switch (mo)
    {
    case MATCH_SRC:
      return (format (s, "source"));
    case MATCH_DST:
      return (format (s, "destination"));
    case MATCH_BOTH:
      return (format (s, "both"));
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
format_match_icmp (u8 * s, va_list * args)
{
  const match_icmp_t *mi = va_arg (*args, match_icmp_t *);

  s = format (s, "%d, %d", mi->mi_type, mi->mi_code);

  return (s);
}

u8 *
format_match_tcp_flags (u8 * s, va_list * args)
{
  const match_tcp_flags_t *mtf = va_arg (*args, match_tcp_flags_t *);

  s = format (s, "0x%x/0x%x", mtf->mtf_flags, mtf->mtf_mask);

  return (s);
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
format_match_exact_ip_l4 (u8 * s, va_list * args)
{
  const match_exact_ip_l4_t *meil = va_arg (*args, match_exact_ip_l4_t *);

  s = format (s, "%U %U ",
	      format_ip_address, &meil->meil_ip,
	      format_ip_protocol, meil->meil_proto);

  if (IP_PROTOCOL_TCP == meil->meil_proto ||
      IP_PROTOCOL_UDP == meil->meil_proto)
    s = format (s, "port:%d", clib_net_to_host_u16 (meil->meil_l4.ml_port));
  else
    s = format (s, "type:%d, code:%d",
		&meil->meil_l4.ml_icmp.mi_type,
		&meil->meil_l4.ml_icmp.mi_code);

  return (s);
}

u8 *
format_match_rule (u8 * s, va_list * args)
{
  const match_rule_t *mr = va_arg (*args, match_rule_t *);
  u32 indent = va_arg (*args, u32);

  s = format (s, "rule: %U %U proto:%U index:%d",
	      format_match_type, mr->mr_type,
	      format_match_orientation, mr->mr_orientation,
	      format_ethernet_type, mr->mr_proto, mr->mr_index);

  switch (mr->mr_type)
    {
    case MATCH_TYPE_EXACT_IP:
      s = format (s, "\n%U[%U]",
		  format_white_space, indent + 2,
		  format_ip_address, &mr->mr_exact_ip);
      break;
    case MATCH_TYPE_SETS:
      s = format (s, "\n%U[src:%d dst:%d]",
		  format_white_space, indent + 2,
		  mr->mr_sets.mss_set[MATCH_SRC],
		  mr->mr_sets.mss_set[MATCH_DST]);
      break;
    case MATCH_TYPE_EXACT_IP_L4:
      s = format (s, "\n%U[%U]",
		  format_white_space, indent + 2,
		  format_match_exact_ip_l4, &mr->mr_exact_ip_l4);
      break;
    case MATCH_TYPE_MASK_IP:
      s = format (s, "\n%U[%U]",
		  format_white_space, indent + 2,
		  format_match_ip_prefix, &mr->mr_mask_ip);
      break;
    case MATCH_TYPE_MASK_IP_MAC:
      s = format (s, "\n%U[%U, %U]",
		  format_white_space, indent + 2,
		  format_match_ip_prefix, &mr->mr_mask_ip_mac.mmim_ip,
		  format_match_mac_mask, &mr->mr_mask_ip_mac.mmim_mac);
      break;

    case MATCH_TYPE_MASK_N_TUPLE:
      s = format (s, "%U",
		  format_match_mask_n_tuple, &mr->mr_mask_n_tuple, indent);
      break;
    }
  return (s);
}

u8 *
format_match_rule_w_result (u8 * s, va_list * args)
{
  const match_rule_t *mr;
  format_function_t *fn;
  u32 indent;

  mr = va_arg (*args, match_rule_t *);
  indent = va_arg (*args, u32);
  fn = va_arg (*args, format_function_t *);

  s =
    format (s, "%U => %U", format_match_rule, mr, indent, fn, mr->mr_result);
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
format_match_list_w_result (u8 * s, va_list * args)
{
  const match_list_t *ml;
  format_function_t *fn;
  u32 mri, indent;

  ml = va_arg (*args, match_list_t *);
  indent = va_arg (*args, u32);
  fn = va_arg (*args, format_function_t *);

  s = format (s, "match-list: %v", ml->ml_tag);

  vec_foreach_index (mri, ml->ml_rules)
    s = format (s, "\n%U[%d]: %U",
		format_white_space, indent,
		mri,
		format_match_rule_w_result, &ml->ml_rules[mri],
		indent + 2, fn);

  return (s);
}

ip_address_family_t
match_rule_get_af (const match_rule_t * mr)
{
  switch (mr->mr_type)
    {
    case MATCH_TYPE_SETS:
      return (match_set_get_af (mr->mr_sets.mss_set[MATCH_SRC]));
    case MATCH_TYPE_MASK_IP_MAC:
      return (ip_prefix_version (&mr->mr_mask_ip_mac.mmim_ip.mip_ip));
    case MATCH_TYPE_MASK_IP:
      return (ip_prefix_version (&mr->mr_mask_ip.mip_ip));
    case MATCH_TYPE_EXACT_IP:
      return (ip_addr_version (&mr->mr_exact_ip));
    case MATCH_TYPE_EXACT_IP_L4:
      return (ip_addr_version (&mr->mr_exact_ip_l4.meil_ip));
    case MATCH_TYPE_MASK_N_TUPLE:
      return (ip_prefix_version (&mr->mr_mask_n_tuple.mnt_src_ip.mip_ip));
    }

  ASSERT (0);
  return (AF_IP4);
}

uword
unformat_match_type (unformat_input_t * input, va_list * args)
{
  match_type_t *mt = va_arg (*args, match_type_t *);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0)
	;
#define _(a,b)                                  \
      else if (unformat (input, b)) {           \
        *mt = MATCH_TYPE_##a;                   \
        return (1);                             \
      }
      foreach_match_type
#undef _
	else
	return (0);
    }

  return (0);
}

uword
unformat_match_orientation (unformat_input_t * input, va_list * args)
{
  match_orientation_t *mt = va_arg (*args, match_orientation_t *);

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "src") || unformat (input, "source"))
	{
	  *mt = MATCH_SRC;
	  return (1);
	}
      else if (unformat (input, "dst") || unformat (input, "destination"))
	{
	  *mt = MATCH_SRC;
	  return (1);
	}
      else
	return (0);
    }

  return (0);
}

uword
unformat_match_rule (unformat_input_t * input, va_list * args)
{
  match_rule_t *mr = va_arg (*args, match_rule_t *);
  ip_address_t ipa;
  ip_prefix_t ipp;
  int found;

  found = 0;
  memset (mr, 0, sizeof (*mr));

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%U", unformat_match_type, &mr->mr_type))
	found = 1;
      else if (unformat (input, "%U", unformat_match_orientation,
			 &mr->mr_orientation))
	;
      else if (unformat (input, "ip-src %U", unformat_ip_prefix, &ipp))
	match_ip_prefix_set (&mr->mr_mask_n_tuple.mnt_src_ip, &ipp);
      else if (unformat (input, "ip-dst %U", unformat_ip_prefix, &ipp))
	match_ip_prefix_set (&mr->mr_mask_n_tuple.mnt_dst_ip, &ipp);
      else if (unformat (input, "ip %U", unformat_ip_prefix, &ipp))
	{
	  switch (mr->mr_type)
	    {
	    case MATCH_TYPE_MASK_IP_MAC:
	      match_ip_prefix_set (&mr->mr_mask_ip_mac.mmim_ip, &ipp);
	      break;
	    case MATCH_TYPE_MASK_IP:
	      match_ip_prefix_set (&mr->mr_mask_ip, &ipp);
	      break;
	    case MATCH_TYPE_MASK_N_TUPLE:
	    case MATCH_TYPE_EXACT_IP:
	    case MATCH_TYPE_EXACT_IP_L4:
	    case MATCH_TYPE_SETS:
	      break;
	    }
	}
      else if (unformat (input, "ip %U", unformat_ip_address, &ipa))
	{
	  switch (mr->mr_type)
	    {
	    case MATCH_TYPE_MASK_IP_MAC:
	    case MATCH_TYPE_MASK_IP:
	    case MATCH_TYPE_MASK_N_TUPLE:
	    case MATCH_TYPE_SETS:
	      break;
	    case MATCH_TYPE_EXACT_IP:
	      mr->mr_exact_ip = ipa;
	      break;
	    case MATCH_TYPE_EXACT_IP_L4:
	      mr->mr_exact_ip_l4.meil_ip = ipa;
	      break;
	    }
	}
      else if (unformat (input, "mac %U", unformat_mac_address_t,
			 &mr->mr_mask_ip_mac.mmim_mac.mmm_mac))
	;
      else if (unformat (input, "mac-mask %U", unformat_mac_address_t,
			 &mr->mr_mask_ip_mac.mmim_mac.mmm_mask))
	;
      else if (unformat (input, "src-ports %d-%d",
			 &mr->mr_mask_n_tuple.mnt_src_port.mpr_begin,
			 &mr->mr_mask_n_tuple.mnt_src_port.mpr_end))
	;
      else if (unformat (input, "dst-ports %d-%d",
			 &mr->mr_mask_n_tuple.mnt_dst_port.mpr_begin,
			 &mr->mr_mask_n_tuple.mnt_dst_port.mpr_end))
	;
      else if (unformat (input, "tcp-flags %x/%x",
			 &mr->mr_mask_n_tuple.mnt_tcp.mtf_flags,
			 &mr->mr_mask_n_tuple.mnt_tcp.mtf_mask))
	;
      else if (unformat (input, "%U", unformat_ip_protocol,
			 &mr->mr_mask_n_tuple.mnt_ip_proto))
	;
      else
	return (found);
    }

  return (1);
}

bool
match_icmp_code_range_is_any (const match_icmp_code_range_t * micr)
{
  return (micr->micr_begin == 0 && micr->micr_end == 0xff);
}

bool
match_icmp_type_range_is_any (const match_icmp_type_range_t * mitr)
{
  return (mitr->mitr_begin == 0 && mitr->mitr_end == 0xff);
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

void
match_ip_prefix_set (match_ip_prefix_t * mip, const ip_prefix_t * ip)
{
  mip->mip_ip = *ip;
  ip_prefix_normalize (&mip->mip_ip);

  if (mip->mip_ip.addr.version == AF_IP4)
    ip4_preflen_to_mask (mip->mip_ip.len, &ip_addr_v4 (&mip->mip_mask));
  else
    ip6_preflen_to_mask (mip->mip_ip.len, &ip_addr_v6 (&mip->mip_mask));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
