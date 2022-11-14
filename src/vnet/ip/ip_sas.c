/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include "ip_sas.h"
#include <vppinfra/types.h>
#include <vnet/ip/ip_interface.h>
#include <vnet/fib/fib_table.h>
#include <vnet/ip/ip6_link.h>
#include <vppinfra/byte_order.h>

/*
 * This file implement source address selection for VPP applications
 * (e.g. ping, DNS, ICMP)
 * It does not yet implement full fledged RFC6724 SAS.
 * SAS assumes every IP enabled interface has an address. The algorithm will
 * not go and hunt for a suitable IP address on other interfaces than the
 * output interface or the specified preferred sw_if_index.
 * That means that an interface with just an IPv6 link-local address must also
 * be configured with an unnumbered configuration pointing to a numbered
 * interface.
 */

static int
ip6_sas_commonlen (const ip6_address_t *a1, const ip6_address_t *a2)
{
  u64 fa = clib_net_to_host_u64 (a1->as_u64[0]) ^
	   clib_net_to_host_u64 (a2->as_u64[0]);
  if (fa == 0)
    {
      u64 la = clib_net_to_host_u64 (a1->as_u64[1]) ^
	       clib_net_to_host_u64 (a2->as_u64[1]);
      if (la == 0)
	return 128;
      return 64 + __builtin_clzll (la);
    }
  else
    {
      return __builtin_clzll (fa);
    }
}

static int
ip4_sas_commonlen (const ip4_address_t *a1, const ip4_address_t *a2)
{
  u64 a =
    clib_net_to_host_u32 (a1->as_u32) ^ clib_net_to_host_u32 (a2->as_u32);
  if (a == 0)
    return 32;
  return __builtin_clz (a);
}

/*
 * walk all addresses on an interface:
 *  - prefer a source matching the scope of the destination address.
 *  - last resort pick the source address with the longest
 *    common prefix with destination
 * NOTE: This should at some point implement RFC6724.
 */
bool
ip6_sas_by_sw_if_index (u32 sw_if_index, const ip6_address_t *dst,
			ip6_address_t *src)
{
  ip_interface_address_t *ia = 0;
  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
  ip6_address_t *tmp, *bestsrc = 0;
  int bestlen = 0, l;

  if (ip6_address_is_link_local_unicast (dst) ||
      dst->as_u32[0] == clib_host_to_net_u32 (0xff020000))
    {
      const ip6_address_t *ll = ip6_get_link_local_address (sw_if_index);
      if (NULL == ll)
	{
	  return false;
	}
      ip6_address_copy (src, ll);
      return true;
    }

  foreach_ip_interface_address (
    lm6, ia, sw_if_index, 1, ({
      if (ia->flags & IP_INTERFACE_ADDRESS_FLAG_STALE)
	continue;
      tmp = ip_interface_address_get_address (lm6, ia);
      l = ip6_sas_commonlen (tmp, dst);
      if (l > bestlen || bestsrc == 0)
	{
	  bestsrc = tmp;
	  bestlen = l;
	}
    }));
  if (bestsrc)
    {
      ip6_address_copy (src, bestsrc);
      return true;
    }
  return false;
}

/*
 * walk all addresses on an interface and pick the source address with the
 * longest common prefix with destination.
 */
bool
ip4_sas_by_sw_if_index (u32 sw_if_index, const ip4_address_t *dst,
			ip4_address_t *src)
{
  ip_interface_address_t *ia = 0;
  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
  ip4_address_t *tmp, *bestsrc = 0;
  int bestlen = 0, l;

  foreach_ip_interface_address (
    lm4, ia, sw_if_index, 1, ({
      if (ia->flags & IP_INTERFACE_ADDRESS_FLAG_STALE)
	continue;
      tmp = ip_interface_address_get_address (lm4, ia);
      l = ip4_sas_commonlen (tmp, dst);
      if (l >= bestlen || bestsrc == 0)
	{
	  bestsrc = tmp;
	  bestlen = l;
	}
    }));
  if (bestsrc)
    {
      src->as_u32 = bestsrc->as_u32;
      return true;
    }
  return false;
}

/*
 * table_id must be set. Default = 0.
 * sw_if_index is the interface to pick SA from otherwise ~0 will pick from
 * outbound interface.
 *
 * NOTE: What to do if multiple output interfaces?
 *
 */
bool
ip6_sas (u32 table_id, u32 sw_if_index, const ip6_address_t *dst,
	 ip6_address_t *src)
{
  fib_prefix_t prefix;
  u32 if_index = sw_if_index;

  /* If sw_if_index is not specified use the output interface. */
  if (sw_if_index == ~0)
    {
      clib_memcpy (&prefix.fp_addr.ip6, dst, sizeof (*dst));
      prefix.fp_proto = FIB_PROTOCOL_IP6;
      prefix.fp_len = 128;

      u32 fib_index = fib_table_find (prefix.fp_proto, table_id);
      if (fib_index == (u32) ~0)
	return false;

      fib_node_index_t fei = fib_table_lookup (fib_index, &prefix);
      if (fei == FIB_NODE_INDEX_INVALID)
	return false;

      u32 output_sw_if_index = fib_entry_get_resolving_interface (fei);
      if (output_sw_if_index == ~0)
	return false;
      if_index = output_sw_if_index;
    }
  return ip6_sas_by_sw_if_index (if_index, dst, src);
}

/*
 * table_id must be set. Default = 0.
 * sw_if_index is the interface to pick SA from otherwise ~0 will pick from
 * outbound interface.
 *
 * NOTE: What to do if multiple output interfaces?
 *
 */
bool
ip4_sas (u32 table_id, u32 sw_if_index, const ip4_address_t *dst,
	 ip4_address_t *src)
{
  fib_prefix_t prefix;
  u32 if_index = sw_if_index;

  /* If sw_if_index is not specified use the output interface. */
  if (sw_if_index == ~0)
    {
      clib_memcpy (&prefix.fp_addr.ip4, dst, sizeof (*dst));
      prefix.fp_proto = FIB_PROTOCOL_IP4;
      prefix.fp_len = 32;

      u32 fib_index = fib_table_find (prefix.fp_proto, table_id);
      if (fib_index == (u32) ~0)
	return false;

      fib_node_index_t fei = fib_table_lookup (fib_index, &prefix);
      if (fei == FIB_NODE_INDEX_INVALID)
	return false;

      u32 output_sw_if_index = fib_entry_get_resolving_interface (fei);
      if (output_sw_if_index == ~0)
	return false;
      if_index = output_sw_if_index;
    }
  return ip4_sas_by_sw_if_index (if_index, dst, src);
}
