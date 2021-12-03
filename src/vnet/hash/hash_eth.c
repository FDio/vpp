/*
 *------------------------------------------------------------------
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
 *------------------------------------------------------------------
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip6_hop_by_hop_packet.h>
#include <vppinfra/lb_hash_hash.h>
#include <vnet/hash/hash.h>

static_always_inline u16 *
locate_ethertype (ethernet_header_t *eth)
{
  u16 *ethertype_p;
  ethernet_vlan_header_t *vlan;

  if (!ethernet_frame_is_tagged (clib_net_to_host_u16 (eth->type)))
    {
      ethertype_p = &eth->type;
    }
  else
    {
      vlan = (void *) (eth + 1);
      ethertype_p = &vlan->type;
      if (*ethertype_p == ntohs (ETHERNET_TYPE_VLAN))
	{
	  vlan++;
	  ethertype_p = &vlan->type;
	}
    }
  return ethertype_p;
}

static void
hash_eth_l2 (void **p, u32 *hash, u32 n_packets)
{
  u32 n_left_from = n_packets;

  while (n_left_from >= 8)
    {
      ethernet_header_t *eth = *p;
      u64 *dst = (u64 *) &eth->dst_address[0];
      u64 a = clib_mem_unaligned (dst, u64);
      u32 *src = (u32 *) &eth->src_address[2];
      u32 b = clib_mem_unaligned (src, u32);

      clib_prefetch_load (p[4]);
      clib_prefetch_load (p[5]);
      clib_prefetch_load (p[6]);
      clib_prefetch_load (p[7]);

      hash[0] = lb_hash_hash_2_tuples (a, b);
      hash[1] = lb_hash_hash_2_tuples (a, b);
      hash[2] = lb_hash_hash_2_tuples (a, b);
      hash[3] = lb_hash_hash_2_tuples (a, b);

      hash += 4;
      n_left_from -= 4;
      p += 4;
    }

  while (n_left_from > 0)
    {
      ethernet_header_t *eth = *p;
      u64 *dst = (u64 *) &eth->dst_address[0];
      u64 a = clib_mem_unaligned (dst, u64);
      u32 *src = (u32 *) &eth->src_address[2];
      u32 b = clib_mem_unaligned (src, u32);

      hash[0] = lb_hash_hash_2_tuples (a, b);

      hash += 1;
      n_left_from -= 1;
      p += 1;
    }
}

static_always_inline u32
hash_eth_l23_inline (void **p)
{
  ethernet_header_t *eth = *p;
  u8 ip_version;
  ip4_header_t *ip4;
  u16 ethertype, *ethertype_p;
  u32 *mac1, *mac2, *mac3;
  u32 hash;

  ethertype_p = locate_ethertype (eth);
  ethertype = clib_mem_unaligned (ethertype_p, u16);

  if ((ethertype != htons (ETHERNET_TYPE_IP4)) &&
      (ethertype != htons (ETHERNET_TYPE_IP6)))
    {
      hash_eth_l2 (p, &hash, 1);
      return hash;
    }

  ip4 = (ip4_header_t *) (ethertype_p + 1);
  ip_version = (ip4->ip_version_and_header_length >> 4);

  if (ip_version == 0x4)
    {
      u32 a;

      mac1 = (u32 *) &eth->dst_address[0];
      mac2 = (u32 *) &eth->dst_address[4];
      mac3 = (u32 *) &eth->src_address[2];

      a = clib_mem_unaligned (mac1, u32) ^ clib_mem_unaligned (mac2, u32) ^
	  clib_mem_unaligned (mac3, u32);
      hash = lb_hash_hash_2_tuples (
	clib_mem_unaligned (&ip4->address_pair, u64), a);
      return hash;
    }

  if (ip_version == 0x6)
    {
      u64 a;
      ip6_header_t *ip6 = (ip6_header_t *) (eth + 1);

      mac1 = (u32 *) &eth->dst_address[0];
      mac2 = (u32 *) &eth->dst_address[4];
      mac3 = (u32 *) &eth->src_address[2];

      a = clib_mem_unaligned (mac1, u32) ^ clib_mem_unaligned (mac2, u32) ^
	  clib_mem_unaligned (mac3, u32);
      hash = lb_hash_hash (
	clib_mem_unaligned (&ip6->src_address.as_uword[0], uword),
	clib_mem_unaligned (&ip6->src_address.as_uword[1], uword),
	clib_mem_unaligned (&ip6->dst_address.as_uword[0], uword),
	clib_mem_unaligned (&ip6->dst_address.as_uword[1], uword), a);
      return hash;
    }

  hash_eth_l2 (p, &hash, 1);
  return hash;
}

static void
hash_eth_l23 (void **p, u32 *hash, u32 n_packets)
{
  u32 n_left_from = n_packets;

  while (n_left_from >= 8)
    {
      clib_prefetch_load (p[4]);
      clib_prefetch_load (p[5]);
      clib_prefetch_load (p[6]);
      clib_prefetch_load (p[7]);

      hash[0] = hash_eth_l23_inline (&p[0]);
      hash[1] = hash_eth_l23_inline (&p[1]);
      hash[2] = hash_eth_l23_inline (&p[2]);
      hash[3] = hash_eth_l23_inline (&p[3]);

      hash += 4;
      n_left_from -= 4;
      p += 4;
    }

  while (n_left_from > 0)
    {
      hash[0] = hash_eth_l23_inline (&p[0]);

      hash += 1;
      n_left_from -= 1;
      p += 1;
    }
}

static_always_inline u32
hash_eth_l34_inline (void **p)
{
  ethernet_header_t *eth = *p;
  u8 ip_version;
  uword is_tcp_udp;
  ip4_header_t *ip4;
  u16 ethertype, *ethertype_p;
  u32 hash;

  ethertype_p = locate_ethertype (eth);
  ethertype = clib_mem_unaligned (ethertype_p, u16);

  if ((ethertype != htons (ETHERNET_TYPE_IP4)) &&
      (ethertype != htons (ETHERNET_TYPE_IP6)))
    {
      hash_eth_l2 (p, &hash, 1);
      return hash;
    }

  ip4 = (ip4_header_t *) (ethertype_p + 1);
  ip_version = (ip4->ip_version_and_header_length >> 4);

  if (ip_version == 0x4)
    {
      u32 a, t1, t2;
      tcp_header_t *tcp = (void *) (ip4 + 1);

      is_tcp_udp = (ip4->protocol == IP_PROTOCOL_TCP) ||
		   (ip4->protocol == IP_PROTOCOL_UDP);
      t1 = is_tcp_udp ? clib_mem_unaligned (&tcp->src, u16) : 0;
      t2 = is_tcp_udp ? clib_mem_unaligned (&tcp->dst, u16) : 0;
      a = t1 ^ t2;
      hash = lb_hash_hash_2_tuples (
	clib_mem_unaligned (&ip4->address_pair, u64), a);
      return hash;
    }

  if (ip_version == 0x6)
    {
      u64 a;
      u32 t1, t2;
      ip6_header_t *ip6 = (ip6_header_t *) (eth + 1);
      tcp_header_t *tcp = (void *) (ip6 + 1);

      is_tcp_udp = 0;
      if (PREDICT_TRUE ((ip6->protocol == IP_PROTOCOL_TCP) ||
			(ip6->protocol == IP_PROTOCOL_UDP)))
	{
	  is_tcp_udp = 1;
	  tcp = (void *) (ip6 + 1);
	}
      else if (ip6->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	{
	  ip6_hop_by_hop_header_t *hbh = (ip6_hop_by_hop_header_t *) (ip6 + 1);
	  if ((hbh->protocol == IP_PROTOCOL_TCP) ||
	      (hbh->protocol == IP_PROTOCOL_UDP))
	    {
	      is_tcp_udp = 1;
	      tcp = (tcp_header_t *) ((u8 *) hbh + ((hbh->length + 1) << 3));
	    }
	}
      t1 = is_tcp_udp ? clib_mem_unaligned (&tcp->src, u16) : 0;
      t2 = is_tcp_udp ? clib_mem_unaligned (&tcp->dst, u16) : 0;
      a = t1 ^ t2;
      hash = lb_hash_hash (
	clib_mem_unaligned (&ip6->src_address.as_uword[0], uword),
	clib_mem_unaligned (&ip6->src_address.as_uword[1], uword),
	clib_mem_unaligned (&ip6->dst_address.as_uword[0], uword),
	clib_mem_unaligned (&ip6->dst_address.as_uword[1], uword), a);
      return hash;
    }

  hash_eth_l2 (p, &hash, 1);
  return hash;
}

static void
hash_eth_l34 (void **p, u32 *hash, u32 n_packets)
{
  u32 n_left_from = n_packets;

  while (n_left_from >= 8)
    {
      clib_prefetch_load (p[4]);
      clib_prefetch_load (p[5]);
      clib_prefetch_load (p[6]);
      clib_prefetch_load (p[7]);

      hash[0] = hash_eth_l34_inline (&p[0]);
      hash[1] = hash_eth_l34_inline (&p[1]);
      hash[2] = hash_eth_l34_inline (&p[2]);
      hash[3] = hash_eth_l34_inline (&p[3]);

      hash += 4;
      n_left_from -= 4;
      p += 4;
    }

  while (n_left_from > 0)
    {
      hash[0] = hash_eth_l34_inline (&p[0]);

      hash += 1;
      n_left_from -= 1;
      p += 1;
    }
}

VNET_REGISTER_HASH_FUNCTION (hash_eth_l2, static) = {
  .name = "hash-eth-l2",
  .description = "Hash ethernet L2 headers",
  .priority = 50,
  .function[VNET_HASH_FN_TYPE_ETHERNET] = hash_eth_l2,
};

VNET_REGISTER_HASH_FUNCTION (hash_eth_l23, static) = {
  .name = "hash-eth-l23",
  .description = "Hash ethernet L23 headers",
  .priority = 50,
  .function[VNET_HASH_FN_TYPE_ETHERNET] = hash_eth_l23,
};

VNET_REGISTER_HASH_FUNCTION (hash_eth_l34, static) = {
  .name = "hash-eth-l34",
  .description = "Hash ethernet L34 headers",
  .priority = 50,
  .function[VNET_HASH_FN_TYPE_ETHERNET] = hash_eth_l34,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
