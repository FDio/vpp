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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
