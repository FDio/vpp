/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef __VNET_CRC32C_5TUPLE_H__
#define __VNET_CRC32C_5TUPLE_H__

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

#endif
