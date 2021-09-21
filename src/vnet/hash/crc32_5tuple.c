/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/hash/hash.h>
#include <vppinfra/crc32.h>

typedef union
{
  struct
  {
    ip46_address_t src_address;
    ip46_address_t dst_address;
    union
    {
      struct
      {
	u16 src_port;
	u16 dst_port;
      };
      u32 l4_hdr;
    };
  };
  u8 as_u8[36];
} crc32c_5tuple_key_t;

static const u8 l4_mask_bits[256] = {
  [IP_PROTOCOL_ICMP] = 16,	[IP_PROTOCOL_IGMP] = 8,
  [IP_PROTOCOL_TCP] = 32,	[IP_PROTOCOL_UDP] = 32,
  [IP_PROTOCOL_IPSEC_ESP] = 32, [IP_PROTOCOL_IPSEC_AH] = 32,
  [IP_PROTOCOL_ICMP6] = 16,
};

static_always_inline void
compute_ip6_key (ip6_header_t *ip, crc32c_5tuple_key_t *k)
{
  u8 pr;

  /* copy 32 bytes of ip6 src and dst addresses into hash_key_t */
  clib_memcpy_fast ((u8 *) k, (u8 *) ip + 8, sizeof (ip6_address_t) * 2);
  pr = ip->protocol;
  /* write l4 header */
  k->l4_hdr = *(u32 *) ip6_next_header (ip) & pow2_mask (l4_mask_bits[pr]);
}

static_always_inline void
compute_ip4_key (ip4_header_t *ip, crc32c_5tuple_key_t *k)
{
  u8 pr;
  u64 *key = (u64 *) k;
  /* copy 8 bytes of ip src and dst addresses into hash_key_t */
  key[0] = 0;
  key[1] = 0;
  key[2] = 0;
  key[3] = *(u64 *) ((u8 *) ip + 12);
  pr = ip->protocol;
  /* write l4 header */
  k->l4_hdr = *(u32 *) ip4_next_header (ip) & pow2_mask (l4_mask_bits[pr]);
}
static_always_inline void
compute_ip_key (void *p, crc32c_5tuple_key_t *key)
{
  if ((((u8 *) p)[0] & 0xf0) == 0x40)
    compute_ip4_key (p, key);
  else if ((((u8 *) p)[0] & 0xf0) == 0x60)
    compute_ip6_key (p, key);
}

void
vnet_crc32c_5tuple_ip_func (void **p, u32 *hash, u32 n_packets)
{
  u32 n_left_from = n_packets;

  while (n_left_from >= 8)
    {
      crc32c_5tuple_key_t key[4] = {};

      clib_prefetch_load (p[4]);
      clib_prefetch_load (p[5]);
      clib_prefetch_load (p[6]);
      clib_prefetch_load (p[7]);

      compute_ip_key (p[0], &key[0]);
      compute_ip_key (p[1], &key[1]);
      compute_ip_key (p[2], &key[2]);
      compute_ip_key (p[3], &key[3]);

      hash[0] = clib_crc32c (key[0].as_u8, sizeof (key[0]));
      hash[1] = clib_crc32c (key[1].as_u8, sizeof (key[1]));
      hash[2] = clib_crc32c (key[2].as_u8, sizeof (key[2]));
      hash[3] = clib_crc32c (key[3].as_u8, sizeof (key[3]));

      hash += 4;
      n_left_from -= 4;
      p += 4;
    }

  while (n_left_from > 0)
    {
      crc32c_5tuple_key_t key = {};

      compute_ip_key (p[0], &key);

      hash[0] = clib_crc32c (key.as_u8, sizeof (key));

      hash += 1;
      n_left_from -= 1;
      p += 1;
    }
}

static_always_inline void
compute_ethernet_key (void *p, crc32c_5tuple_key_t *key)
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
      compute_ip4_key (ip4, key);
    }
  else if (ethertype == ETHERNET_TYPE_IP6)
    {
      ip6_header_t *ip6 = (ip6_header_t *) (p + l2hdr_sz);
      compute_ip6_key (ip6, key);
    }
}

void
vnet_crc32c_5tuple_ethernet_func (void **p, u32 *hash, u32 n_packets)
{
  u32 n_left_from = n_packets;

  while (n_left_from >= 8)
    {
      crc32c_5tuple_key_t key[4] = {};

      clib_prefetch_load (p[4]);
      clib_prefetch_load (p[5]);
      clib_prefetch_load (p[6]);
      clib_prefetch_load (p[7]);

      compute_ethernet_key (p[0], &key[0]);
      compute_ethernet_key (p[1], &key[1]);
      compute_ethernet_key (p[2], &key[2]);
      compute_ethernet_key (p[3], &key[3]);

      hash[0] = clib_crc32c (key[0].as_u8, sizeof (key[0]));
      hash[1] = clib_crc32c (key[1].as_u8, sizeof (key[1]));
      hash[2] = clib_crc32c (key[2].as_u8, sizeof (key[2]));
      hash[3] = clib_crc32c (key[3].as_u8, sizeof (key[3]));

      hash += 4;
      n_left_from -= 4;
      p += 4;
    }

  while (n_left_from > 0)
    {
      crc32c_5tuple_key_t key = {};

      compute_ethernet_key (p[0], &key);

      hash[0] = clib_crc32c (key.as_u8, sizeof (key));

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
