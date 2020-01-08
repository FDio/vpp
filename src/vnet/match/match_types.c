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

  s = format (s, "%U/%d", format_ip_address, &mip->mip_ip, mip->mip_len);

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
format_match_rule (u8 * s, va_list * args)
{
  const match_rule_t *mr = va_arg (*args, match_rule_t *);
  u32 indent = va_arg (*args, u32);

  s = format (s, "rule: %U %U",
	      format_match_type, mr->mr_type,
	      format_ethernet_type, mr->mr_proto);

  switch (mr->mr_type)
    {
    case MATCH_TYPE_MASK_SRC_IP_MAC:
      s = format (s, "\n%U[%U, %U]",
		  format_white_space, indent + 2,
		  format_match_ip_prefix, &mr->mr_mask_src_ip_mac.mm_ip,
		  format_match_mac_mask, &mr->mr_mask_src_ip_mac.mm_mac);
      break;

    case MATCH_TYPE_MASK_DST_IP_MAC:
      s = format (s, "\n%U[%U, %U]",
		  format_white_space, indent + 2,
		  format_match_ip_prefix, &mr->mr_mask_dst_ip_mac.mm_ip,
		  format_match_mac_mask, &mr->mr_mask_dst_ip_mac.mm_mac);
      break;

    case MATCH_TYPE_EXACT_SRC_IP_MAC:
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

  vec_foreach_index (mri, ml->ml_rules)
    s = format (s, "\n%U[%d]: %U",
		format_white_space, indent,
		mri,
		format_match_rule_w_action, mri, &ml->ml_rules[mri],
		indent + 2, fn, ctx);

  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
