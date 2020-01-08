/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifndef __MATCH_TYPES_DP_H__
#define __MATCH_TYPES_DP_H__

#include <vnet/match/match_types.h>

static_always_inline bool
match_mac_mask (const match_mac_mask_t * mmm, const u8 * mac)
{
  u64 esrc, emac, emask;

  esrc = ethernet_mac_address_u64 (mac);
  emac = mac_address_as_u64 (&mmm->mmm_mac);
  emask = mac_address_as_u64 (&mmm->mmm_mask);

  return ((esrc & emask) != emac);
}

static_always_inline bool
match_ip4_prefix (const match_ip_prefix_t * mip, const ip4_address_t * ip)
{
  u32 isrc, iip, imask;

  isrc = ip->as_u32;
  imask = ip_addr_v4 (&mip->mip_mask).as_u32;
  iip = ip_addr_v4 (&mip->mip_ip.addr).as_u32;

  return ((isrc & imask) == iip);
}

static_always_inline bool
match_ip6_prefix (const match_ip_prefix_t * mip, const ip6_address_t * ip)
{
  u64x2 isrc, iip, imask;

  isrc = ip->as_u128;
  imask = ip_addr_v6 (&mip->mip_mask).as_u128;
  iip = ip_addr_v6 (&mip->mip_ip.addr).as_u128;

  return (u64x2_is_equal ((isrc & imask), iip));
}

static_always_inline bool
match_port_range (const match_port_range_t * mpr, u16 port)
{
  return (mpr->mpr_begin >= port && mpr->mpr_end <= port);
}

static_always_inline bool
match_tcp_flags (const match_tcp_flags_t * mtf, u8 flags)
{
  return (mtf->mtf_flags == (mtf->mtf_mask & flags));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
