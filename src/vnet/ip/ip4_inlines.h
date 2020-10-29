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
 * ip/ip4.h: ip4 main include file
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

#ifndef included_ip_ip4_inlines_h
#define included_ip_ip4_inlines_h

#include <vnet/ip/ip_flow_hash.h>
#include <vnet/ip/ip4_packet.h>

#define IP_DF 0x4000		/* don't fragment */

/* Compute flow hash.  We'll use it to select which adjacency to use for this
   flow.  And other things. */
always_inline u32
ip4_compute_flow_hash (const ip4_header_t * ip,
		       flow_hash_config_t flow_hash_config)
{
  tcp_header_t *tcp = (void *) (ip + 1);
  u32 a, b, c, t1, t2;
  uword is_tcp_udp = (ip->protocol == IP_PROTOCOL_TCP
		      || ip->protocol == IP_PROTOCOL_UDP);

  t1 = (flow_hash_config & IP_FLOW_HASH_SRC_ADDR)
    ? ip->src_address.data_u32 : 0;
  t2 = (flow_hash_config & IP_FLOW_HASH_DST_ADDR)
    ? ip->dst_address.data_u32 : 0;

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

  b ^= (flow_hash_config & IP_FLOW_HASH_PROTO) ? ip->protocol : 0;
  c = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ?
    (t1 << 16) | t2 : (t2 << 16) | t1;

  hash_v3_mix32 (a, b, c);
  hash_v3_finalize32 (a, b, c);

  return c;
}

always_inline void *
vlib_buffer_push_ip4_custom (vlib_main_t * vm, vlib_buffer_t * b,
			     ip4_address_t * src, ip4_address_t * dst,
			     int proto, u8 csum_offload, u8 is_df)
{
  ip4_header_t *ih;

  /* make some room */
  ih = vlib_buffer_push_uninit (b, sizeof (ip4_header_t));

  ih->ip_version_and_header_length = 0x45;
  ih->tos = 0;
  ih->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b));

  /* No fragments */
  ih->flags_and_fragment_offset = is_df ? clib_host_to_net_u16 (IP_DF) : 0;
  ih->ttl = 255;
  ih->protocol = proto;
  ih->src_address.as_u32 = src->as_u32;
  ih->dst_address.as_u32 = dst->as_u32;

  vnet_buffer (b)->l3_hdr_offset = (u8 *) ih - b->data;
  b->flags |= VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID;

  /* Offload ip4 header checksum generation */
  if (csum_offload)
    {
      ih->checksum = 0;
      vnet_buffer_offload_flags_set (b, VNET_BUFFER_OFFLOAD_F_IP_CKSUM);
    }
  else
    ih->checksum = ip4_header_checksum (ih);

  return ih;
}

/**
 * Push IPv4 header to buffer
 *
 * This does not support fragmentation.
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
vlib_buffer_push_ip4 (vlib_main_t * vm, vlib_buffer_t * b,
		      ip4_address_t * src, ip4_address_t * dst, int proto,
		      u8 csum_offload)
{
  return vlib_buffer_push_ip4_custom (vm, b, src, dst, proto, csum_offload,
				      1 /* is_df */ );
}

#endif /* included_ip_ip4_inlines_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
