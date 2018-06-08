/*
 *------------------------------------------------------------------
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#include <igmp/igmp.h>
#include <vnet/ip/ip.h>

u8 *
format_igmp_type (u8 * s, va_list * args)
{
  igmp_type_t type = va_arg (*args, int);

  switch (type)
    {
#define _(n,f) case IGMP_TYPE_##f: return (format (s, "%s", #f));
      foreach_igmp_type
#undef _
    }
  return format (s, "unknown:%d", type);
}

u8 *
format_igmp_membership_group_type (u8 * s, va_list * args)
{
  igmp_membership_group_v3_type_t type = va_arg (*args, int);

  switch (type)
    {
#define _(n,f)  case IGMP_MEMBERSHIP_GROUP_##f: return (format (s, "%s", #f));
      foreach_igmp_membership_group_v3_type
#undef _
    }
  return (format (s, "unknown:%d", type));
}

u8 *
format_igmp_filter_mode (u8 * s, va_list * args)
{
  igmp_filter_mode_t mode = va_arg (*args, igmp_filter_mode_t);

  switch (mode)
    {
#define _(n,f)  case IGMP_FILTER_MODE_##f: return (format (s, "%s", #f));
      foreach_igmp_filter_mode
#undef _
    }
  return (format (s, "unknown:%d", mode));

}

u8 *
format_igmp_header (u8 * s, va_list * args)
{
  igmp_header_t *hdr = va_arg (*args, igmp_header_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 indent;

  if (max_header_bytes < sizeof (hdr[0]))
    return format (s, "IGMP header truncated");

  indent = format_get_indent (s);
  indent += 2;

  s =
    format (s, "%U%U: code %u, checksum 0x%04x", format_white_space, indent,
	    format_igmp_type, hdr->type, hdr->code,
	    clib_net_to_host_u16 (hdr->checksum));
  return s;
}

u8 *
format_igmp_report_v3 (u8 * s, va_list * args)
{
  igmp_membership_report_v3_t *igmp =
    va_arg (*args, igmp_membership_report_v3_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  igmp_membership_group_v3_t *group;

  u32 len = sizeof (igmp_membership_report_v3_t);
  u32 indent;

  if (max_header_bytes < sizeof (igmp[0]))
    return format (s, "IGMP report truncated");

  indent = format_get_indent (s);
  indent += 2;

  s =
    format (s, "%Un_groups %u", format_white_space, indent,
	    clib_net_to_host_u16 (igmp->n_groups));
  indent += 2;
  int i, j = 0;
  for (i = 0; i < clib_net_to_host_u16 (igmp->n_groups); i++)
    {
      group = group_ptr (igmp, len);
      s =
	format (s, "\n%U%U: %U, sources %u", format_white_space, indent,
		format_igmp_membership_group_type, group->type,
		format_ip4_address, &group->group_address,
		clib_net_to_host_u16 (group->n_src_addresses));
      indent += 2;
      for (j = 0; j < clib_net_to_host_u16 (group->n_src_addresses); j++)
	{
	  s =
	    format (s, "\n%U%U", format_white_space, indent,
		    format_ip4_address, &group->src_addresses[j]);
	}
      indent -= 2;
      len +=
	sizeof (igmp_membership_group_v3_t) +
	(sizeof (ip4_address_t) *
	 clib_net_to_host_u16 (group->n_src_addresses));
    }
  return s;
}

u8 *
format_igmp_query_v3 (u8 * s, va_list * args)
{
  igmp_membership_query_v3_t *igmp =
    va_arg (*args, igmp_membership_query_v3_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 indent;
  int i;

  if (max_header_bytes < sizeof (igmp[0]))
    return format (s, "IGMP query truncated");

  indent = format_get_indent (s);
  indent += 2;

  ip4_address_t tmp;
  tmp.as_u32 = 0;

  if ((!ip4_address_compare (&igmp->group_address, &tmp))
      && (igmp->n_src_addresses == 0))
    s = format (s, "%UGeneral Query", format_white_space, indent);
  else if (igmp->n_src_addresses == 0)
    s = format (s, "%UGroup-Specific Query: %U", format_white_space, indent,
		format_ip4_address, &igmp->group_address);
  else
    {
      s =
	format (s, "%UGroup-and-Source-Specific Query: %U",
		format_white_space, indent, format_ip4_address,
		&igmp->group_address);
      indent += 2;
      for (i = 0; i < clib_net_to_host_u16 (igmp->n_src_addresses); i++)
	{
	  s = format (s, "\n%U%U", format_white_space, indent,
		      format_ip4_address, &igmp->src_addresses[i]);
	}
    }
  return s;
}

u8 *
format_igmp_src_addr_list (u8 * s, va_list * args)
{
  ip46_address_t *ss, *srcs;

  srcs = va_arg (*args, ip46_address_t *);

  s = format (s, "[");
  vec_foreach (ss, srcs)
  {
    s = format (s, "%U ", format_ip46_address, ss, IP46_TYPE_ANY);
  }
  s = format (s, "]");

  return (s);
}

u8 *
format_igmp_key (u8 * s, va_list * args)
{
  const igmp_key_t *key = va_arg (*args, const igmp_key_t *);

  s = format (s, "%U", format_ip46_address, key, IP46_TYPE_ANY);

  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
