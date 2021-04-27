/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
 * interface_output.c: interface output node
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __INTERFACE_INLINES_H__
#define __INTERFACE_INLINES_H__

#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>

#include <vppinfra/crc32.h>

static_always_inline void
vnet_calc_ip4_checksums (vlib_main_t *vm, vlib_buffer_t *b, ip4_header_t *ip4,
			 tcp_header_t *th, udp_header_t *uh,
			 vnet_buffer_oflags_t oflags)
{
  if (oflags & VNET_BUFFER_OFFLOAD_F_IP_CKSUM)
    ip4->checksum = ip4_header_checksum (ip4);
  if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
    {
      th->checksum = 0;
      th->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
    }
  if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
    {
      uh->checksum = 0;
      uh->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
    }
}

static_always_inline void
vnet_calc_ip6_checksums (vlib_main_t *vm, vlib_buffer_t *b, ip6_header_t *ip6,
			 tcp_header_t *th, udp_header_t *uh,
			 vnet_buffer_oflags_t oflags)
{
  int bogus;
  if (oflags & VNET_BUFFER_OFFLOAD_F_TCP_CKSUM)
    {
      th->checksum = 0;
      th->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
    }
  if (oflags & VNET_BUFFER_OFFLOAD_F_UDP_CKSUM)
    {
      uh->checksum = 0;
      uh->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
    }
}

static_always_inline void
vnet_calc_checksums_inline (vlib_main_t * vm, vlib_buffer_t * b,
			    int is_ip4, int is_ip6)
{
  ip4_header_t *ip4;
  ip6_header_t *ip6;
  tcp_header_t *th;
  udp_header_t *uh;
  vnet_buffer_oflags_t oflags;

  if (!(b->flags & VNET_BUFFER_F_OFFLOAD))
    return;

  ASSERT (!(is_ip4 && is_ip6));

  ip4 = (ip4_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
  ip6 = (ip6_header_t *) (b->data + vnet_buffer (b)->l3_hdr_offset);
  th = (tcp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
  uh = (udp_header_t *) (b->data + vnet_buffer (b)->l4_hdr_offset);
  oflags = vnet_buffer (b)->oflags;

  if (is_ip4)
    {
      vnet_calc_ip4_checksums (vm, b, ip4, th, uh, oflags);
    }
  else if (is_ip6)
    {
      vnet_calc_ip6_checksums (vm, b, ip6, th, uh, oflags);
    }

  vnet_buffer_offload_flags_clear (b, (VNET_BUFFER_OFFLOAD_F_IP_CKSUM |
				       VNET_BUFFER_OFFLOAD_F_UDP_CKSUM |
				       VNET_BUFFER_OFFLOAD_F_TCP_CKSUM));
}

typedef void (interface_output_hash_func_t) (void **p, u32 *h, u32 n_packets);

typedef union
{
  struct
  {
    u32 sw_if_index[VLIB_N_RX_TX];
    ip46_address_t src_address;
    ip46_address_t dst_address;
    u16 src_port;
    u16 dst_port;
  };
  u8 as_u8[44];
} txq_key_t;

static_always_inline void
hash_func (vlib_buffer_t **b, u32 *h, u32 n_packets)
{

  u32 i;

  vec_validate (h, n_packets);

  for (i = 0; i < n_packets; i++)
    {
      txq_key_t key = { 0 };
      u16 ethertype = 0, l2hdr_sz = 0, l4_hdr_offset = 0;
      u8 l4_proto = 0; //, is_tcp = 0, is_udp = 0;

      // int is_ip4 = (b[i]->flags & VNET_BUFFER_F_IS_IP4) ? 1 : 0;

      // ip4_header_t *ip4 =
      //   (ip4_header_t *) (b[i]->data + vnet_buffer (b[i])->l3_hdr_offset);
      // ip6_header_t *ip6 =
      //   (ip6_header_t *) (b[i]->data + vnet_buffer (b[i])->l3_hdr_offset);
      // tcp_header_t *tcp =
      //   (tcp_header_t *) (b[i]->data + vnet_buffer (b[i])->l4_hdr_offset);
      // udp_header_t *udp =
      //   (udp_header_t *) (b[i]->data + vnet_buffer (b[i])->l4_hdr_offset);

      // l4_proto = is_ip4 ? ip4->protocol : ip6->protocol;
      // is_tcp = (l4_proto == IP_PROTOCOL_TCP) ? 1 : 0;
      // is_udp = (l4_proto == IP_PROTOCOL_UDP) ? 1 : 0;

      key.sw_if_index[VLIB_RX] = vnet_buffer (b[i])->sw_if_index[VLIB_RX];
      key.sw_if_index[VLIB_TX] = vnet_buffer (b[i])->sw_if_index[VLIB_TX];

      ethernet_header_t *eh =
	(ethernet_header_t *) vlib_buffer_get_current (b[i]);
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
	  ip4_header_t *ip4 =
	    (ip4_header_t *) (vlib_buffer_get_current (b[i]) + l2hdr_sz);
	  l4_hdr_offset = l2hdr_sz + ip4_header_bytes (ip4);
	  l4_proto = ip4->protocol;
	  ip46_address_set_ip4 (&key.src_address, &ip4->src_address);
	  ip46_address_set_ip4 (&key.dst_address, &ip4->dst_address);
	}
      else if (PREDICT_TRUE (ethertype == ETHERNET_TYPE_IP6))
	{
	  ip6_header_t *ip6 =
	    (ip6_header_t *) (vlib_buffer_get_current (b[i]) + l2hdr_sz);
	  l4_hdr_offset =
	    l2hdr_sz + sizeof (ip6_header_t) + ip6_ext_header_len (ip6);
	  l4_proto = ip6->protocol;
	  ip46_address_set_ip6 (&key.src_address, &ip6->src_address);
	  ip46_address_set_ip6 (&key.dst_address, &ip6->dst_address);
	}

      if (l4_proto == IP_PROTOCOL_TCP)
	{
	  tcp_header_t *tcp =
	    (tcp_header_t *) (vlib_buffer_get_current (b[i]) + l4_hdr_offset);
	  key.src_port = tcp->src_port;
	  key.dst_port = tcp->dst_port;
	}
      else if (l4_proto == IP_PROTOCOL_UDP)
	{
	  udp_header_t *udp =
	    (udp_header_t *) (vlib_buffer_get_current (b[i]) + l4_hdr_offset);
	  key.src_port = udp->src_port;
	  key.dst_port = udp->dst_port;
	}
      h[i] = clib_crc32c (key.as_u8, sizeof (key));
    }
}

/*
VNET_REGISTER_HASH_FUNCTION() =
{
  .name = “default-hash-func”,
  .function = default_hash_func,
  .type = VNET_HASH_FN_TYPE_ETHERNET,
}
*/

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
