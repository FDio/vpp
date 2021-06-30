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
    u16 src_port;
    u16 dst_port;
  };
  u8 as_u8[36];
} ethernet_key_t;

static_always_inline void
compute_ethernet_key (void *p, ethernet_key_t *key)
{
  u16 ethertype = 0, l2hdr_sz = 0, l4_hdr_offset = 0;
  u8 l4_proto = 0;

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

  if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP4))
    {
      ip4_header_t *ip4 = (ip4_header_t *) (p + l2hdr_sz);
      l4_hdr_offset = l2hdr_sz + ip4_header_bytes (ip4);
      l4_proto = ip4->protocol;
      ip46_address_set_ip4 (&key->src_address, &ip4->src_address);
      ip46_address_set_ip4 (&key->dst_address, &ip4->dst_address);
    }
  else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
    {
      ip6_header_t *ip6 = (ip6_header_t *) (p + l2hdr_sz);
      l4_hdr_offset =
	l2hdr_sz + sizeof (ip6_header_t) + ip6_ext_header_len (ip6);
      l4_proto = ip6->protocol;
      ip46_address_set_ip6 (&key->src_address, &ip6->src_address);
      ip46_address_set_ip6 (&key->dst_address, &ip6->dst_address);
    }

  if (l4_proto == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) (p + l4_hdr_offset);
      key->src_port = tcp->src_port;
      key->dst_port = tcp->dst_port;
    }
  else if (l4_proto == IP_PROTOCOL_UDP)
    {
      udp_header_t *udp = (udp_header_t *) (p + l4_hdr_offset);
      key->src_port = udp->src_port;
      key->dst_port = udp->dst_port;
    }
}

void
vnet_hash_ethernet_func (void **p, u32 *hash, u32 n_packets)
{
  u32 n_left_from = n_packets;

  while (n_left_from >= 8)
    {
      ethernet_key_t key[4];

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
      ethernet_key_t key;

      compute_ethernet_key (p[0], &key);

      hash[0] = clib_crc32c (key.as_u8, sizeof (key));

      hash += 1;
      n_left_from -= 1;
      p += 1;
    }
}

VNET_REGISTER_HASH_FUNCTION (ethernet_hash, static) = {
  .name = "hash-ethernet",
  .type = VNET_HASH_FN_TYPE_ETHERNET,
  .function = vnet_hash_ethernet_func,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
