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

#ifndef included_ip_psh_cksum_h
#define included_ip_psh_cksum_h

#include <vnet/ip/ip.h>

typedef struct _ip4_psh
{
  ip4_address_t src;
  ip4_address_t dst;
  u8 zero;
  u8 proto;
  u16 l4len;
} ip4_psh_t;

typedef struct _ip6_psh
{
  ip6_address_t src;
  ip6_address_t dst;
  u32 l4len;
  u32 proto;
} ip6_psh_t;

STATIC_ASSERT (sizeof (ip4_psh_t) == 12, "ipv4 pseudo header is 12B");
STATIC_ASSERT (sizeof (ip6_psh_t) == 40, "ipv6 pseudo header is 40B");

static_always_inline u16
ip4_pseudo_header_cksum (ip4_header_t *ip4, u16 l3_hdr_len)
{
  ip4_psh_t psh = { 0 };
  psh.src = ip4->src_address;
  psh.dst = ip4->dst_address;
  psh.proto = ip4->protocol;
  psh.l4len =
    clib_host_to_net_u16 (clib_net_to_host_u16 (ip4->length) - l3_hdr_len);
  return ~clib_net_to_host_u16 (ip_csum (&psh, sizeof (ip4_psh_t)));
}

static_always_inline u16
ip6_pseudo_header_cksum (ip6_header_t *ip6)
{
  ip6_psh_t psh = { 0 };
  psh.src = ip6->src_address;
  psh.dst = ip6->dst_address;
  psh.l4len = ip6->payload_length;
  psh.proto = clib_host_to_net_u32 ((u32) ip6->protocol);
  return ~clib_net_to_host_u16 (ip_csum (&psh, sizeof (ip6_psh_t)));
}

#endif /* included_ip_psh_cksum_h */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
