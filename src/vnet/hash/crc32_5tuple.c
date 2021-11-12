/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/hash/hash.h>
#include <vppinfra/crc32.h>

#ifdef clib_crc32c_uses_intrinsics

static const u8 l4_mask_bits[256] = {
  [IP_PROTOCOL_ICMP] = 16,	[IP_PROTOCOL_IGMP] = 8,
  [IP_PROTOCOL_TCP] = 32,	[IP_PROTOCOL_UDP] = 32,
  [IP_PROTOCOL_IPSEC_ESP] = 32, [IP_PROTOCOL_IPSEC_AH] = 32,
  [IP_PROTOCOL_ICMP6] = 16,
};

static_always_inline u32
compute_ip6_key (ip6_header_t *ip)
{
  u32 hash = 0, l4hdr;
  u8 pr;
  /* dst + src ip as u64 */
  hash = clib_crc32c_u64 (hash, *(u64u *) ((u8 *) ip + 8));
  hash = clib_crc32c_u64 (hash, *(u64u *) ((u8 *) ip + 16));
  hash = clib_crc32c_u64 (hash, *(u64u *) ((u8 *) ip + 24));
  hash = clib_crc32c_u64 (hash, *(u64u *) ((u8 *) ip + 32));
  pr = ip->protocol;
  l4hdr = *(u32 *) ip6_next_header (ip) & pow2_mask (l4_mask_bits[pr]);
  /* protocol + l4 hdr */
  return clib_crc32c_u64 (hash, ((u64) pr << 32) | l4hdr);
}

static_always_inline u32
compute_ip4_key (ip4_header_t *ip)
{
  u32 hash = 0, l4hdr;
  u8 pr;
  /* dst + src ip as u64 */
  hash = clib_crc32c_u64 (0, *(u64 *) ((u8 *) ip + 12));
  pr = ip->protocol;
  l4hdr = *(u32 *) ip4_next_header (ip) & pow2_mask (l4_mask_bits[pr]);
  /* protocol + l4 hdr */
  return clib_crc32c_u64 (hash, ((u64) pr << 32) | l4hdr);
}
static_always_inline u32
compute_ip_key (void *p)
{
  if ((((u8 *) p)[0] & 0xf0) == 0x40)
    return compute_ip4_key (p);
  else if ((((u8 *) p)[0] & 0xf0) == 0x60)
    return compute_ip6_key (p);
  return 0;
}

void
vnet_crc32c_5tuple_ip_func (void **p, u32 *hash, u32 n_packets)
{
  u32 n_left_from = n_packets;

  while (n_left_from >= 8)
    {
      clib_prefetch_load (p[4]);
      clib_prefetch_load (p[5]);
      clib_prefetch_load (p[6]);
      clib_prefetch_load (p[7]);

      hash[0] = compute_ip_key (p[0]);
      hash[1] = compute_ip_key (p[1]);
      hash[2] = compute_ip_key (p[2]);
      hash[3] = compute_ip_key (p[3]);

      hash += 4;
      n_left_from -= 4;
      p += 4;
    }

  while (n_left_from > 0)
    {
      hash[0] = compute_ip_key (p[0]);

      hash += 1;
      n_left_from -= 1;
      p += 1;
    }
}

static_always_inline u32
compute_ethernet_key (void *p)
{
  u16 ethertype = 0, l2hdr_sz = 0;

  ethernet_header_t *eh = (ethernet_header_t *) p;
  ethertype = clib_net_to_host_u16 (eh->type);
  l2hdr_sz = sizeof (ethernet_header_t);

  if (ethernet_frame_is_tagged (ethertype))
    {
      ethernet_vlan_header_t *vlan = (ethernet_vlan_header_t *) (eh + 1);

      ethertype = clib_net_to_host_u16 (vlan->type);
      l2hdr_sz += sizeof (*vlan);
      while (ethernet_frame_is_tagged (ethertype))
	{
	  vlan++;
	  ethertype = clib_net_to_host_u16 (vlan->type);
	  l2hdr_sz += sizeof (*vlan);
	}
    }

  if (ethertype == ETHERNET_TYPE_IP4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) (p + l2hdr_sz);
      return compute_ip4_key (ip4);
    }
  else if (ethertype == ETHERNET_TYPE_IP6)
    {
      ip6_header_t *ip6 = (ip6_header_t *) (p + l2hdr_sz);
      return compute_ip6_key (ip6);
    }
  return 0;
}

void
vnet_crc32c_5tuple_ethernet_func (void **p, u32 *hash, u32 n_packets)
{
  u32 n_left_from = n_packets;

  while (n_left_from >= 8)
    {
      clib_prefetch_load (p[4]);
      clib_prefetch_load (p[5]);
      clib_prefetch_load (p[6]);
      clib_prefetch_load (p[7]);

      hash[0] = compute_ethernet_key (p[0]);
      hash[1] = compute_ethernet_key (p[1]);
      hash[2] = compute_ethernet_key (p[2]);
      hash[3] = compute_ethernet_key (p[3]);

      hash += 4;
      n_left_from -= 4;
      p += 4;
    }

  while (n_left_from > 0)
    {
      hash[0] = compute_ethernet_key (p[0]);

      hash += 1;
      n_left_from -= 1;
      p += 1;
    }
}

VNET_REGISTER_HASH_FUNCTION (crc32c_5tuple, static) = {
  .name = "crc32c-5tuple",
  .description = "IPv4/IPv6 header and TCP/UDP ports",
  .priority = 50,
  .function[VNET_HASH_FN_TYPE_ETHERNET] = vnet_crc32c_5tuple_ethernet_func,
  .function[VNET_HASH_FN_TYPE_IP] = vnet_crc32c_5tuple_ip_func,
};

#endif
