/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_ip_psh_cksum_h
#define included_ip_psh_cksum_h

#include <vnet/ip/ip.h>
#include <vppinfra/vector/ip_csum.h>

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
ip4_pseudo_header_cksum (ip4_header_t *ip4)
{
  ip4_psh_t psh = { 0 };
  psh.src = ip4->src_address;
  psh.dst = ip4->dst_address;
  psh.proto = ip4->protocol;
  psh.l4len = clib_host_to_net_u16 (clib_net_to_host_u16 (ip4->length) -
				    sizeof (ip4_header_t));
  return ~(clib_ip_csum ((u8 *) &psh, sizeof (ip4_psh_t)));
}

static_always_inline u16
ip6_pseudo_header_cksum (ip6_header_t *ip6)
{
  ip6_psh_t psh = { 0 };
  psh.src = ip6->src_address;
  psh.dst = ip6->dst_address;
  psh.l4len = ip6->payload_length;
  psh.proto = clib_host_to_net_u32 ((u32) ip6->protocol);
  return ~(clib_ip_csum ((u8 *) &psh, sizeof (ip6_psh_t)));
}

#endif /* included_ip_psh_cksum_h */
