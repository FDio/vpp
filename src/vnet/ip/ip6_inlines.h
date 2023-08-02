/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 * ip/ip6.h: ip6 main include file
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

#ifndef included_ip_ip6_inlines_h
#define included_ip_ip6_inlines_h

#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip6_hop_by_hop_packet.h>

/* Compute flow hash.  We'll use it to select which Sponge to use for this
   flow.  And other things. */
always_inline u32
ip6_compute_flow_hash (const ip6_header_t * ip,
		       flow_hash_config_t flow_hash_config)
{
  const tcp_header_t *tcp;
  const udp_header_t *udp = (void *) (ip + 1);
  const gtpv1u_header_t *gtpu = (void *) (udp + 1);
  u64 a, b, c;
  u64 t1, t2;
  u32 t3;
  uword is_tcp_udp = 0;
  u8 protocol = ip->protocol;
  uword is_udp = protocol == IP_PROTOCOL_UDP;

  if (PREDICT_TRUE ((protocol == IP_PROTOCOL_TCP) || is_udp))
    {
      is_tcp_udp = 1;
      tcp = (void *) (ip + 1);
    }
  else
    {
      const void *cur = ip + 1;
      if (protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
	{
	  const ip6_hop_by_hop_header_t *hbh = cur;
	  protocol = hbh->protocol;
	  cur = hbh + (hbh->length + 1) * 8;
	}
      if (protocol == IP_PROTOCOL_IPV6_FRAGMENTATION)
	{
	  const ip6_fragment_ext_header_t *frag = cur;
	  protocol = frag->protocol;
	  cur = frag + 1;
	}
      if (protocol == IP_PROTOCOL_TCP || protocol == IP_PROTOCOL_UDP)
	{
	  is_tcp_udp = 1;
	  tcp = cur;
	}
    }

  t1 = (ip->src_address.as_u64[0] ^ ip->src_address.as_u64[1]);
  t1 = (flow_hash_config & IP_FLOW_HASH_SRC_ADDR) ? t1 : 0;

  t2 = (ip->dst_address.as_u64[0] ^ ip->dst_address.as_u64[1]);
  t2 = (flow_hash_config & IP_FLOW_HASH_DST_ADDR) ? t2 : 0;

  a = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? t2 : t1;
  b = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? t1 : t2;

  t1 = is_tcp_udp ? tcp->src : 0;
  t2 = is_tcp_udp ? tcp->dst : 0;

  t1 = (flow_hash_config & IP_FLOW_HASH_SRC_PORT) ? t1 : 0;
  t2 = (flow_hash_config & IP_FLOW_HASH_DST_PORT) ? t2 : 0;

  if (flow_hash_config & IP_FLOW_HASH_SYMMETRIC)
    {
      if (b < a)
	{
	  c = a;
	  a = b;
	  b = c;
	}
      if (t2 < t1)
	{
	  t2 += t1;
	  t1 = t2 - t1;
	  t2 = t2 - t1;
	}
    }

  b ^= (flow_hash_config & IP_FLOW_HASH_PROTO) ? protocol : 0;
  c = ((flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? ((t1 << 16) | t2) :
							   ((t2 << 16) | t1));
  t1 = ((u64) ip_flow_hash_router_id << 32);
  t1 |=
    ((flow_hash_config & IP_FLOW_HASH_FL) ? ip6_flow_label_network_order (ip) :
					    0);
  c ^= t1;
  if (PREDICT_TRUE (is_udp) &&
      PREDICT_FALSE ((flow_hash_config & IP_FLOW_HASH_GTPV1_TEID) &&
		     udp->dst_port == GTPV1_PORT_BE))
    {
      t3 = gtpu->teid;
      a ^= t3;
    }
  hash_mix64 (a, b, c);
  return (u32) c;
}

/* ip6_locate_header
 *
 * This function is to search for the header specified by the protocol number
 * in find_hdr_type.
 * This is used to locate a specific IPv6 extension header
 * or to find transport layer header.
 *   1. If the find_hdr_type < 0 then it finds and returns the protocol number and
 *   offset stored in *offset of the transport or ESP header in the chain if
 *   found.
 *   2. If a header with find_hdr_type > 0 protocol number is found then the
 *      offset is stored in *offset and protocol number of the header is
 *      returned.
 *   3. If find_hdr_type is not found or packet is malformed or
 *      it is a non-first fragment -1 is returned.
 */
always_inline int
ip6_locate_header (vlib_buffer_t *b, ip6_header_t *ip, int find_hdr_type,
		   u32 *offset)
{
  ip6_ext_hdr_chain_t hdr_chain;
  int res = ip6_ext_header_walk (b, ip, find_hdr_type, &hdr_chain);
  if (res >= 0)
    {
      *offset = hdr_chain.eh[res].offset;
      return hdr_chain.eh[res].protocol;
    }
  return -1;
}


/**
 * Push IPv6 header to buffer
 *
 * @param vm - vlib_main
 * @param b - buffer to write the header to
 * @param src - source IP
 * @param dst - destination IP
 * @param prot - payload proto
 * @param flow_label - flow label
 *
 * @return - pointer to start of IP header
 */
always_inline void *
vlib_buffer_push_ip6_custom (vlib_main_t * vm, vlib_buffer_t * b,
			     ip6_address_t * src, ip6_address_t * dst,
			     int proto, u32 flow_label)
{
  ip6_header_t *ip6h;
  u16 payload_length;

  /* make some room */
  ip6h = vlib_buffer_push_uninit (b, sizeof (ip6_header_t));
  ASSERT (flow_label < 1 << 20);
  ip6h->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 ((0x6 << 28) | flow_label);

  /* calculate ip6 payload length */
  payload_length = vlib_buffer_length_in_chain (vm, b);
  payload_length -= sizeof (*ip6h);

  ip6h->payload_length = clib_host_to_net_u16 (payload_length);

  ip6h->hop_limit = 0xff;
  ip6h->protocol = proto;
  clib_memcpy_fast (ip6h->src_address.as_u8, src->as_u8,
		    sizeof (ip6h->src_address));
  clib_memcpy_fast (ip6h->dst_address.as_u8, dst->as_u8,
		    sizeof (ip6h->src_address));
  vnet_buffer (b)->l3_hdr_offset = (u8 *) ip6h - b->data;
  b->flags |= VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID;

  return ip6h;
}

/**
 * Push IPv6 header to buffer
 *
 * @param vm - vlib_main
 * @param b - buffer to write the header to
 * @param src - source IP
 * @param dst - destination IP
 * @param prot - payload proto
 *
 * @return - pointer to start of IP header
 */
always_inline void *
vlib_buffer_push_ip6 (vlib_main_t * vm, vlib_buffer_t * b,
		      ip6_address_t * src, ip6_address_t * dst, int proto)
{
  return vlib_buffer_push_ip6_custom (vm, b, src, dst, proto,
				      0 /* flow label */ );

}

#endif /* included_ip_ip6_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
