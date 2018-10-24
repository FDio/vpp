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

u8 *
format_vl_api_address (u8 * s, va_list * args)
{
  const vl_api_address_t *addr = va_arg (*args, vl_api_address_t *);

  if (ADDRESS_IP6 == clib_net_to_host_u32 (addr->af))
    s = format (s, "ip6:%U", format_ip6_address, addr->un.ip6.address);
  else
    s = format (s, "ip4:%U", format_ip4_address, addr->un.ip4.address);

  return s;
}

u8 *
format_vl_api_address_union (u8 * s, va_list * args)
{
  const vl_api_address_union_t *addr =
    va_arg (*args, vl_api_address_union_t *);
  vl_api_address_family_t af = va_arg (*args, vl_api_address_family_t);

  if (ADDRESS_IP6 == af)
    s = format (s, "ip6:%U", format_ip6_address, addr->ip6.address);
  else
    s = format (s, "ip4:%U", format_ip4_address, addr->ip4.address);

  return s;
}

u8 *
format_vl_api_prefix (u8 * s, va_list * args)
{
  const vl_api_prefix_t *pfx = va_arg (*args, vl_api_prefix_t *);

  s = format (s, "%U/%d", format_vl_api_address,
	      &pfx->address, pfx->address_length);

  return s;
}

uword
unformat_vl_api_mac_address (unformat_input_t * input, va_list * args)
{
  vl_api_mac_address_t *mac = va_arg (*args, vl_api_mac_address_t *);

  return (unformat (input, "%U",unformat_ethernet_address, mac->bytes));
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

u8 *
format_vl_api_mac_address (u8 * s, va_list * args)
{
  vl_api_mac_address_t *mac = va_arg (*args, vl_api_mac_address_t *);

  return (format (s, "%U", format_ethernet_address, mac->bytes));
}

