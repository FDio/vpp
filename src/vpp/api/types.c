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

#include <vlib/vlib.h>
#include <vpp/api/types.h>
#include <vat/vat.h>

const vl_api_mac_address_t VL_API_ZERO_MAC_ADDRESS;
const vl_api_address_t VL_API_ZERO_ADDRESS;

u8 *
format_vl_api_address_family (u8 * s, va_list * args)
{
  vl_api_address_family_t af = va_arg (*args, vl_api_address_family_t);

  if (ADDRESS_IP6 == clib_net_to_host_u32 (af))
      s = format (s, "ip4");
  else
      s = format (s, "ip6");

  return s;
}

u8 *
format_vl_api_address (u8 * s, va_list * args)
{
  const vl_api_address_t *addr = va_arg (*args, vl_api_address_t *);

  if (ADDRESS_IP6 == clib_net_to_host_u32 (addr->af))
    s = format (s, "%U", format_ip6_address, addr->un.ip6);
  else
    s = format (s, "%U", format_ip4_address, addr->un.ip4);

  return s;
}

u8 *
format_vl_api_address_union (u8 * s, va_list * args)
{
  const vl_api_address_union_t *addr =
    va_arg (*args, vl_api_address_union_t *);
  vl_api_address_family_t af = va_arg (*args, vl_api_address_family_t);

  if (ADDRESS_IP6 == af)
    s = format (s, "%U", format_ip6_address, addr->ip6);
  else
    s = format (s, "%U", format_ip4_address, addr->ip4);

  return s;
}

u8 *
format_vl_api_ip4_address (u8 * s, va_list * args)
{
  const vl_api_ip4_address_t *addr = va_arg (*args, vl_api_ip4_address_t *);

  s = format (s, "%U", format_ip4_address, addr);

  return s;
}

u8 *
format_vl_api_ip6_address (u8 * s, va_list * args)
{
  const vl_api_ip6_address_t *addr = va_arg (*args, vl_api_ip6_address_t *);

  s = format (s, "%U", format_ip6_address, addr);

  return s;
}

u8 *
format_vl_api_prefix (u8 * s, va_list * args)
{
  const vl_api_prefix_t *pfx = va_arg (*args, vl_api_prefix_t *);

  s = format (s, "%U/%d", format_vl_api_address,
	      &pfx->address, pfx->len);

  return s;
}

u8 *
format_vl_api_mac_address (u8 * s, va_list * args)
{
  vl_api_mac_address_t *mac = va_arg (*args, vl_api_mac_address_t *);

  return (format (s, "%U", format_ethernet_address, mac));
}

u8 *
format_vl_api_version (u8 * s, va_list * args)
{
  vl_api_version_t *ver = va_arg (*args, vl_api_version_t *);
  s = format(s, "%d.%d.%d", ver->major, ver->minor, ver->patch);
  if (ver->pre_release[0] != 0)
  {
    s = format(s, "-%v", ver->pre_release);
    if (ver->build_metadata[0] != 0)
    s = format(s, "+%v", ver->build_metadata);
    }
  return s;
}

uword
unformat_vl_api_mac_address (unformat_input_t * input, va_list * args)
{
  vl_api_mac_address_t *mac = va_arg (*args, vl_api_mac_address_t *);

  return (unformat (input, "%U",unformat_ethernet_address, mac));
}

uword
unformat_vl_api_address (unformat_input_t * input, va_list * args)
{
  vl_api_address_t *ip = va_arg (*args, vl_api_address_t *);

  if (unformat (input, "%U", unformat_ip4_address, &ip->un.ip4))
      ip->af = clib_host_to_net_u32(ADDRESS_IP4);
  else if (unformat (input, "%U", unformat_ip6_address, &ip->un.ip6))
      ip->af = clib_host_to_net_u32(ADDRESS_IP6);
  else
      return (0);

  return (1);
}

uword
unformat_vl_api_address_family (unformat_input_t * input,
                                va_list * args)
{
  vl_api_address_family_t *af = va_arg (*args, vl_api_address_family_t *);

  if (unformat (input, "ip4") || unformat (input, "ipv4"))
      *af = clib_host_to_net_u32(ADDRESS_IP4);
  else if (unformat (input, "ip6") || unformat (input, "ipv6"))
      *af = clib_host_to_net_u32(ADDRESS_IP6);
  else
      return (0);

  return (1);
}

uword
unformat_vl_api_ip4_address (unformat_input_t * input, va_list * args)
{
  vl_api_ip4_address_t *ip = va_arg (*args, vl_api_ip4_address_t *);

  if (unformat (input, "%U", unformat_ip4_address, ip))
      return (1);
  return (0);
}

uword
unformat_vl_api_ip6_address (unformat_input_t * input, va_list * args)
{
  vl_api_ip6_address_t *ip = va_arg (*args, vl_api_ip6_address_t *);

  if (unformat (input, "%U", unformat_ip6_address, ip))
      return (1);
  return (0);
}

uword
unformat_vl_api_prefix (unformat_input_t * input, va_list * args)
{
   vl_api_prefix_t *pfx = va_arg (*args, vl_api_prefix_t *);

  if (unformat (input, "%U/%d", unformat_vl_api_address, &pfx->address,
                &pfx->len))
      return (1);
  return (0);
}

uword
unformat_vl_api_mprefix (unformat_input_t * input, va_list * args)
{
   vl_api_mprefix_t *pfx = va_arg (*args, vl_api_mprefix_t *);

   if (unformat (input, "%U/%d",
                 unformat_vl_api_ip4_address, &pfx->grp_address.ip4,
                 &pfx->grp_address_length))
       pfx->af = ADDRESS_IP4;
   else if (unformat (input, "%U/%d",
                 unformat_vl_api_ip6_address, &pfx->grp_address.ip6,
                 &pfx->grp_address_length))
       pfx->af = ADDRESS_IP6;
   else if (unformat (input, "%U %U",
                      unformat_vl_api_ip4_address, &pfx->src_address.ip4,
                      unformat_vl_api_ip4_address, &pfx->grp_address.ip4))
   {
       pfx->af = ADDRESS_IP4;
       pfx->grp_address_length = 64;
   }
   else if (unformat (input, "%U %U",
                      unformat_vl_api_ip6_address, &pfx->src_address.ip6,
                      unformat_vl_api_ip6_address, &pfx->grp_address.ip6))
   {
       pfx->af = ADDRESS_IP6;
       pfx->grp_address_length = 256;
   }
   else if (unformat (input, "%U",
                      unformat_vl_api_ip4_address, &pfx->grp_address.ip4))
   {
       pfx->af = ADDRESS_IP4;
       pfx->grp_address_length = 32;
       clib_memset(&pfx->src_address, 0, sizeof(pfx->src_address));
   }
   else if (unformat (input, "%U",
                      unformat_vl_api_ip6_address, &pfx->grp_address.ip6))
   {
       pfx->af = ADDRESS_IP6;
       pfx->grp_address_length = 128;
       clib_memset(&pfx->src_address, 0, sizeof(pfx->src_address));
   }
   else
       return (0);

   return (1);
}

uword unformat_vl_api_version (unformat_input_t * input, va_list * args)
{
vl_api_version_t *ver = va_arg (*args, vl_api_version_t *);

if (unformat (input, "%d.%d.%d-%s+%s",  ver->major, ver->minor, ver->patch, ver->pre_release, ver->build_metadata
                ))
      return (1);
else if (unformat (input, "%d.%d.%d-%s",  ver->major, ver->minor, ver->patch, ver->pre_release
                ))
      return (1);
else if (unformat (input, "%d.%d.%d",  ver->major, ver->minor, ver->patch
                ))
      return (1);

  return (0);
}
