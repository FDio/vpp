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

#include <vnet/ip/igmp.h>
#include <vnet/ip/ip.h>

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

  s = format (s, "\n%Utype 0x%02x, code %u, checksum 0x%04x", format_white_space, indent, hdr->type,
	      hdr->code, clib_net_to_host_u16 (hdr->checksum));
  return s;
}

u8 *
format_igmp_report_v3 (u8 * s, va_list * args)
{
  igmp_membership_report_v3_t *igmp = va_arg (*args, igmp_membership_report_v3_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  igmp_membership_group_v3_t *group;
  u32 len = sizeof (igmp_membership_report_v3_t);
  u32 indent;

  if (max_header_bytes < sizeof (igmp[0]))
    return format (s, "IGMP report truncated");

  indent = format_get_indent (s);
  indent += 2;

  s = format (s, "\n%Ugroups %u", format_white_space, indent, clib_net_to_host_u16 (igmp->n_groups));
  indent += 2;
  int i;
  for (i = 0; i < clib_net_to_host_u16 (igmp->n_groups); i++)
    {
      group = group_ptr (igmp, len);
      s = format (s, "\n%Utype 0x%02x, sources %u", format_white_space, indent, group->type,
		  clib_net_to_host_u16 (group->n_src_addresses));
      len += sizeof (igmp_membership_group_v3_t) +
	(sizeof (ip4_address_t) * clib_net_to_host_u16 (group->n_src_addresses));
    }
  return s;
}

u8 *
format_igmp_query_v3 (u8 * s, va_list * args)
{
  igmp_membership_query_v3_t *igmp = va_arg (*args, igmp_membership_query_v3_t *);
  u32 max_header_bytes = va_arg (*args, u32);
  u32 indent;

  if (max_header_bytes < sizeof (igmp[0]))
    return format (s, "IGMP query truncated");

  indent = format_get_indent (s);
  indent += 2;

  ip4_address_t tmp;
  tmp.as_u32 = 0;

  if (ip4_address_compare (&igmp->dst, &tmp))
    s = format (s, "\n%UGeneral query", format_white_space, indent);
  else
    s = format (s, "\n%UGroup-Specific query: %U", format_white_space,
		indent, format_ip4_address, &igmp->dst);
  return s;
}
