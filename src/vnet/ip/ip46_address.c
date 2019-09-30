/*
 * Copyright (c) 2015-2019 Cisco and/or its affiliates.
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

#include <vnet/ip/ip46_address.h>

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

  if (!tmp) {
    tmp = clib_net_to_host_u64 (i->as_u64[0]);
    tmp++;
    i->as_u64[0] = clib_host_to_net_u64 (tmp);
  }
}

void
ip46_address_increment (ip46_type_t type,
                        ip46_address_t * ip)
{
  if (IP46_TYPE_IP4 == type ||
      (IP46_TYPE_ANY == type && ip46_address_is_ip4 (ip)))
    ip4_address_increment (&ip->ip4);
  else
    ip6_address_increment (&ip->ip6);
}

u32
ip4_address_get_range (const ip4_address_t *start,
                       const ip4_address_t *end)
{
  return (clib_net_to_host_u32 (end->as_u32) -
          clib_net_to_host_u32 (start->as_u32));
}

u32
ip6_address_get_range (const ip6_address_t *start,
                       const ip6_address_t *end)
{
  return (clib_net_to_host_u64 (end->as_u64[0]) -
          clib_net_to_host_u64 (start->as_u64[0]));
}

u32
ip46_address_get_range (ip46_type_t type,
                        const ip46_address_t *start,
                        const ip46_address_t *end)
{
  if (IP46_TYPE_IP4 == type ||
      (IP46_TYPE_ANY == type && ip46_address_is_ip4 (start)))
    return (ip4_address_get_range(&start->ip4, &end->ip4));
  else
    return (ip6_address_get_range(&start->ip6, &end->ip6));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
