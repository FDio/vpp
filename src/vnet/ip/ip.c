/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vnet/ip/ip.h>
#include <vnet/fib/fib_table.h>

u8
ip_is_zero (ip46_address_t * ip46_address, u8 is_ip4)
{
  if (is_ip4)
    return (ip46_address->ip4.as_u32 == 0);
  else
    return (ip46_address->as_u64[0] == 0 && ip46_address->as_u64[1] == 0);
}

u8
ip_is_local_host (ip46_address_t * ip46_address, u8 is_ip4)
{
  if (is_ip4)
    return (ip46_address->ip4.as_u8[0] == 127);
  else
    return (ip46_address->as_u64[0] == 0 && ip46_address->as_u64[1] == 1);
}

/**
 * Checks that an ip is local to the requested fib
 */
u8
ip_is_local (u32 fib_index, ip46_address_t * ip46_address, u8 is_ip4)
{
  fib_node_index_t fei;
  fib_entry_flag_t flags;
  fib_prefix_t prefix;

  /* Check if requester is local */
  if (is_ip4)
    {
      prefix.fp_len = 32;
      prefix.fp_proto = FIB_PROTOCOL_IP4;
    }
  else
    {
      prefix.fp_len = 128;
      prefix.fp_proto = FIB_PROTOCOL_IP6;
    }

  clib_memcpy (&prefix.fp_addr, ip46_address, sizeof (ip46_address_t));
  fei = fib_table_lookup (0, &prefix);
  flags = fib_entry_get_flags (fei);

  return (flags & FIB_ENTRY_FLAG_LOCAL);
}

void
ip_copy (ip46_address_t * dst, ip46_address_t * src, u8 is_ip4)
{
  if (is_ip4)
    dst->ip4.as_u32 = src->ip4.as_u32;
  else
    clib_memcpy (&dst->ip6, &src->ip6, sizeof (ip6_address_t));
}

void
ip_set (ip46_address_t * dst, void *src, u8 is_ip4)
{
  if (is_ip4)
    dst->ip4.as_u32 = ((ip4_address_t *) src)->as_u32;
  else
    clib_memcpy (&dst->ip6, (ip6_address_t *) src, sizeof (ip6_address_t));
}

u8
ip_interface_has_address (u32 sw_if_index, ip46_address_t * ip, u8 is_ip4)
{
  ip_interface_address_t *ia = 0;

  if (is_ip4)
    {
      ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
      ip4_address_t *ip4;
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm4, ia, sw_if_index, 1 /* unnumbered */ ,
      ({
        ip4 = ip_interface_address_get_address (lm4, ia);
        if (ip4_address_compare (ip4, &ip->ip4) == 0)
          return 1;
      }));
      /* *INDENT-ON* */
    }
  else
    {
      ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
      ip6_address_t *ip6;
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm6, ia, sw_if_index, 1 /* unnumbered */ ,
      ({
        ip6 = ip_interface_address_get_address (lm6, ia);
        if (ip6_address_compare (ip6, &ip->ip6) == 0)
          return 1;
      }));
      /* *INDENT-ON* */
    }
  return 0;
}

void *
ip_interface_get_first_ip (u32 sw_if_index, u8 is_ip4)
{
  ip_lookup_main_t *lm4 = &ip4_main.lookup_main;
  ip_lookup_main_t *lm6 = &ip6_main.lookup_main;
  ip_interface_address_t *ia = 0;

  if (is_ip4)
    {
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm4, ia, sw_if_index, 1 /* unnumbered */ ,
      ({
        return ip_interface_address_get_address (lm4, ia);
      }));
      /* *INDENT-ON* */
    }
  else
    {
      /* *INDENT-OFF* */
      foreach_ip_interface_address (lm6, ia, sw_if_index, 1 /* unnumbered */ ,
      ({
        ip6_address_t *rv;
        rv = ip_interface_address_get_address (lm6, ia);
        /* Trying to use a link-local ip6 src address is a fool's errand */
        if (!ip6_address_is_link_local_unicast (rv))
          return rv;
      }));
      /* *INDENT-ON* */
    }

  return 0;
}

void
ip4_address_normalize (ip4_address_t * ip4, u8 preflen)
{
  ASSERT (preflen <= 32);
  if (preflen == 0)
    ip4->data_u32 = 0;
  else
    ip4->data_u32 &= clib_net_to_host_u32 (0xffffffff << (32 - preflen));
}

void
ip6_address_normalize (ip6_address_t * ip6, u8 preflen)
{
  ASSERT (preflen <= 128);
  if (preflen == 0)
    {
      ip6->as_u64[0] = 0;
      ip6->as_u64[1] = 0;
    }
  else if (preflen <= 64)
    {
      ip6->as_u64[0] &=
	clib_host_to_net_u64 (0xffffffffffffffffL << (64 - preflen));
      ip6->as_u64[1] = 0;
    }
  else
    ip6->as_u64[1] &=
      clib_host_to_net_u64 (0xffffffffffffffffL << (128 - preflen));
}

void
ip4_preflen_to_mask (u8 pref_len, ip4_address_t * ip)
{
  if (pref_len == 0)
    ip->as_u32 = 0;
  else
    ip->as_u32 = clib_host_to_net_u32 (~((1 << (32 - pref_len)) - 1));
}

u32
ip4_mask_to_preflen (ip4_address_t * mask)
{
  if (mask->as_u32 == 0)
    return 0;
  return (32 - log2_first_set (clib_net_to_host_u32 (mask->as_u32)));
}

void
ip4_prefix_max_address_host_order (ip4_address_t * ip, u8 plen,
				   ip4_address_t * res)
{
  u32 not_mask;
  not_mask = (1 << (32 - plen)) - 1;
  res->as_u32 = clib_net_to_host_u32 (ip->as_u32) + not_mask;
}

void
ip6_preflen_to_mask (u8 pref_len, ip6_address_t * mask)
{
  if (pref_len == 0)
    {
      mask->as_u64[0] = 0;
      mask->as_u64[1] = 0;
    }
  else if (pref_len <= 64)
    {
      mask->as_u64[0] =
	clib_host_to_net_u64 (0xffffffffffffffffL << (64 - pref_len));
      mask->as_u64[1] = 0;
    }
  else
    {
      mask->as_u64[1] =
	clib_host_to_net_u64 (0xffffffffffffffffL << (128 - pref_len));
    }
}

void
ip6_prefix_max_address_host_order (ip6_address_t * ip, u8 plen,
				   ip6_address_t * res)
{
  u64 not_mask;
  if (plen == 0)
    {
      res->as_u64[0] = 0xffffffffffffffffL;
      res->as_u64[1] = 0xffffffffffffffffL;
    }
  else if (plen <= 64)
    {
      not_mask = ((u64) 1 << (64 - plen)) - 1;
      res->as_u64[0] = clib_net_to_host_u64 (ip->as_u64[0]) + not_mask;
      res->as_u64[1] = 0xffffffffffffffffL;
    }
  else
    {
      not_mask = ((u64) 1 << (128 - plen)) - 1;
      res->as_u64[1] = clib_net_to_host_u64 (ip->as_u64[1]) + not_mask;
    }
}

u32
ip6_mask_to_preflen (ip6_address_t * mask)
{
  u8 first1, first0;
  if (mask->as_u64[0] == 0 && mask->as_u64[1] == 0)
    return 0;
  first1 = log2_first_set (mask->as_u64[1]);
  first0 = log2_first_set (mask->as_u64[0]);

  if (first1 != 0)
    return 128 - first1;
  else
    return 64 - first0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
