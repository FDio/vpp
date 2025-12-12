/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015-2019 Cisco and/or its affiliates.
 */

#include <vnet/ip/ip46_address.h>

u8 *
format_ip46_type (u8 * s, va_list * args)
{
  ip46_type_t type = va_arg (*args, ip46_type_t);

  switch (type)
    {
    case IP46_TYPE_IP4:
      return (format (s, "ip4"));
    case IP46_TYPE_IP6:
      return (format (s, "ip6"));
    case IP46_TYPE_ANY:
      return (format (s, "any"));
    }

  return (format (s, "unknown"));
}

void
ip4_address_increment (ip4_address_t * i)
{
  u32 t = clib_net_to_host_u32 (i->as_u32);
  t++;
  i->as_u32 = clib_net_to_host_u32 (t);
}

void
ip6_address_increment (ip6_address_t * i)
{
  u64 tmp = clib_net_to_host_u64 (i->as_u64[1]);

  tmp++;
  i->as_u64[1] = clib_host_to_net_u64 (tmp);

  if (!tmp)
    {
      tmp = clib_net_to_host_u64 (i->as_u64[0]);
      tmp++;
      i->as_u64[0] = clib_host_to_net_u64 (tmp);
    }
}

void
ip46_address_increment (ip46_type_t type, ip46_address_t * ip)
{
  if (IP46_TYPE_IP4 == type ||
      (IP46_TYPE_ANY == type && ip46_address_is_ip4 (ip)))
    ip4_address_increment (&ip->ip4);
  else
    ip6_address_increment (&ip->ip6);
}
