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

#include <vnet/udp/udp_packet.h>
#include <vnet/ip/icmp46_packet.h>

static_always_inline const ip6_address_t *
ip6_header_address (match_orientation_t mo, const ip6_header_t * ip6)
{
  return (MATCH_SRC == mo ? &ip6->src_address : &ip6->dst_address);
}

static_always_inline const ip4_address_t *
ip4_header_address (match_orientation_t mo, const ip4_header_t * ip4)
{
  return (MATCH_SRC == mo ? &ip4->src_address : &ip4->dst_address);
}

static_always_inline const u8 *
ethernet_header_address (match_orientation_t mo, const ethernet_header_t * eh)
{
  return (MATCH_SRC == mo ? eh->src_address : eh->dst_address);
}

static_always_inline u16
udp_header_port (match_orientation_t mo, const udp_header_t * u)
{
  return (MATCH_SRC == mo ? u->src_port : u->dst_port);
}

static_always_inline bool
match_mac_mask (const match_mac_mask_t * mmm, const u8 * mac)
{
  u64 esrc, emac, emask;

  esrc = ethernet_mac_address_u64 (mac);
  emac = mac_address_as_u64 (&mmm->mmm_mac);
  emask = mac_address_as_u64 (&mmm->mmm_mask);

  return ((esrc & emask) == emac);
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
  return (mpr->mpr_begin <= clib_net_to_host_u16 (port) &&
	  mpr->mpr_end >= clib_net_to_host_u16 (port));
}

static_always_inline bool
match_tcp_flags (const match_tcp_flags_t * mtf, u8 flags)
{
  return (mtf->mtf_flags == (mtf->mtf_mask & flags));
}

static_always_inline bool
match_icmp_code_range (const match_icmp_code_range_t * micr, u8 code)
{
  return (micr->micr_begin <= code && micr->micr_end >= code);
}

static_always_inline bool
match_icmp_type_range (const match_icmp_type_range_t * mitr, u8 type)
{
  return (mitr->mitr_begin <= type && mitr->mitr_end >= type);
}

static_always_inline bool
match_mask_n_tuple_match_l4 (const match_mask_n_tuple_t * mnt, const void *l4)
{
  switch (mnt->mnt_ip_proto)
    {
    case IP_PROTOCOL_TCP:
      {
	const tcp_header_t *t = l4;
	return (match_port_range (&mnt->mnt_src_port, t->src_port) &&
		match_port_range (&mnt->mnt_dst_port, t->dst_port) &&
		match_tcp_flags (&mnt->mnt_tcp, t->flags));
      }
    case IP_PROTOCOL_UDP:
      {
	const udp_header_t *t = l4;
	return (match_port_range (&mnt->mnt_src_port, t->src_port) &&
		match_port_range (&mnt->mnt_dst_port, t->dst_port));
      }
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
      {
	const icmp46_header_t *i = l4;

	return (match_icmp_type_range (&mnt->mnt_icmp_type, i->type) &&
		match_icmp_code_range (&mnt->mnt_icmp_code, i->code));
      }
    default:
      return (false);
    }

  return (false);
}

static_always_inline bool
match_exact_l4 (match_orientation_t mo,
		const match_exact_ip_l4_t * meil, const void *l4)
{
  switch (meil->meil_proto)
    {
    case IP_PROTOCOL_TCP:
    case IP_PROTOCOL_UDP:
      return (meil->meil_l4.ml_port ==
	      udp_header_port (mo, (udp_header_t *) l4));
    case IP_PROTOCOL_ICMP:
    case IP_PROTOCOL_ICMP6:
      {
	icmp46_header_t *ic = (icmp46_header_t *) l4;
	return (meil->meil_l4.ml_icmp.mi_type == ic->type &&
		meil->meil_l4.ml_icmp.mi_code == ic->code);
      }
    default:
      return (false);
    }

  return (false);
}

static_always_inline bool
match_exact_ip4_l4 (match_orientation_t mo,
		    const ip4_header_t * ip, const match_exact_ip_l4_t * meil)
{
  if (!ip4_address_is_equal (&ip_addr_v4 (&meil->meil_ip),
			     ip4_header_address (mo, ip)))
    return (false);

  if (meil->meil_proto)
    {
      if (ip->protocol != meil->meil_proto)
	return (false);
    }
  else
    return (true);

  return (match_exact_l4 (mo, meil, ip + 1));
}

static_always_inline bool
match_exact_ip6_l4 (match_orientation_t mo,
		    const ip6_header_t * ip, const match_exact_ip_l4_t * meil)
{
  if (!ip6_address_is_equal (&ip_addr_v6 (&meil->meil_ip),
			     ip6_header_address (mo, ip)))
    return (false);

  if (meil->meil_proto)
    {
      if (ip->protocol != meil->meil_proto)
	return (false);
    }
  else
    return (true);

  return (match_exact_l4 (mo, meil, ip + 1));
}

static_always_inline bool
match_ip4_mask_n_tuple (const ip4_header_t * ip,
			const match_mask_n_tuple_t * mnt)
{
  if (!match_ip4_prefix (&mnt->mnt_src_ip, &ip->src_address) ||
      !match_ip4_prefix (&mnt->mnt_dst_ip, &ip->dst_address))
    return (false);

  if (mnt->mnt_ip_proto)
    {
      if (ip->protocol != mnt->mnt_ip_proto)
	return (false);
    }
  else
    return (true);

  return (match_mask_n_tuple_match_l4 (mnt, ip + 1));
}

static_always_inline bool
match_ip6_mask_n_tuple (const ip6_header_t * ip,
			const match_mask_n_tuple_t * mnt)
{
  const void *l4;

  if (!match_ip6_prefix (&mnt->mnt_src_ip, &ip->src_address) ||
      !match_ip6_prefix (&mnt->mnt_dst_ip, &ip->dst_address))
    return (false);

  if (PREDICT_FALSE (mnt->mnt_ip_proto))
    {
      u8 protocol = ip->protocol;

      if (PREDICT_FALSE (ip->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION))
	{
	  ip6_ext_header_t *ext = (ip6_ext_header_t *) (ip + 1);
	  l4 = ip6_ext_next_header (ext);
	  protocol = ext->next_hdr;
	}
      else
	l4 = ip + 1;

      if (protocol != mnt->mnt_ip_proto)
	return (false);
    }
  else
    return (true);

  return (match_mask_n_tuple_match_l4 (mnt, l4));
}

static_always_inline const u8 *
match_ip6_strip_frag (const u8 * h0, u8 * scratch, u8 n_bytes)
{
  ip6_header_t *ip6 = (ip6_header_t *) h0;

  if (PREDICT_FALSE (ip6->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION))
    {
      /* copy over the ip6 header */
      clib_memcpy_fast (scratch, h0, sizeof (*ip6));

      /* copy next-hop proto from the frag extension header */
      ip6 = (ip6_header_t *) scratch;
      ip6_ext_header_t *ext0 = (ip6_ext_header_t *) (h0 + sizeof (*ip6));
      ip6->protocol = ext0->next_hdr;

      /* copy over some more of the packet from the end of the ext header */
      clib_memcpy_fast (scratch + sizeof (*ip6),
			ip6_ext_next_header (ext0), n_bytes - sizeof (*ip6));

      /* point to the fudged data */
      h0 = (u8 *) scratch;
    }
  return (h0);
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
