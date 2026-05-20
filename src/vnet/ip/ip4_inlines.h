/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip/ip4.h: ip4 main include file */

#ifndef included_ip_ip4_inlines_h
#define included_ip_ip4_inlines_h

#include <vnet/ip/ip_flow_hash.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip_inner_aware_hash.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/udp/udp_packet.h>

#define IP_DF 0x4000		/* don't fragment */

/* Compute flow hash.  We'll use it to select which adjacency to use for this
   flow.  And other things.

   If IP_FLOW_HASH_PEEK_INNER is set in flow_hash_config and the outer
   protocol is an IP-in-IP encapsulation (4 = IPv4-in-IPv4, 41 = IPv6-in-
   IPv4) or GRE / NVGRE (47), walk into the inner header and compute the
   hash from inner src/dst/proto plus inner L4 sport/dport.  This matches
   the default ECMP behavior of merchant-silicon ASICs which hash on inner
   fields for transit tunnel traffic.  See src/vnet/ip/ip_inner_aware_hash.h
   for the shared helpers used here, in ip6_inlines.h, and in
   src/vnet/hash/hash_eth.c.  */
always_inline u32
ip4_compute_flow_hash (const ip4_header_t * ip,
		       flow_hash_config_t flow_hash_config)
{
  const tcp_header_t *tcp;
  const udp_header_t *udp;
  const gtpv1u_header_t *gtpu;
  u32 a, b, c, t1, t2;
  u32 src_addr_u32, dst_addr_u32;
  u8 hash_protocol;
  ip_inner_hdr_t inner = { .valid = 0 };

  if (PREDICT_FALSE ((flow_hash_config & IP_FLOW_HASH_PEEK_INNER) && !ip4_is_fragment (ip)))
    {
      u32 total_len = clib_net_to_host_u16 (ip->length);
      u32 ihl = ip4_header_bytes (ip);
      if (PREDICT_TRUE (total_len >= ihl))
	{
	  u32 remaining = total_len - ihl;
	  ip_inner_resolve (ip->protocol, (const u8 *) ip + ihl, remaining, &inner);
	}
    }

  if (PREDICT_FALSE (inner.valid))
    {
      if (inner.is_v6)
	{
	  src_addr_u32 = ip6_addr_fold_u32 (&inner.ip.v6->src_address);
	  dst_addr_u32 = ip6_addr_fold_u32 (&inner.ip.v6->dst_address);
	}
      else
	{
	  src_addr_u32 = inner.ip.v4->src_address.data_u32;
	  dst_addr_u32 = inner.ip.v4->dst_address.data_u32;
	}
      hash_protocol = inner.protocol;
      tcp = (const tcp_header_t *) inner.l4;
      udp = (const udp_header_t *) inner.l4;
    }
  else
    {
      src_addr_u32 = ip->src_address.data_u32;
      dst_addr_u32 = ip->dst_address.data_u32;
      hash_protocol = ip->protocol;
      tcp = (const tcp_header_t *) (ip + 1);
      udp = (const udp_header_t *) (ip + 1);
    }
  gtpu = (const gtpv1u_header_t *) (udp + 1);

  uword is_udp = hash_protocol == IP_PROTOCOL_UDP;
  uword is_tcp_udp = (hash_protocol == IP_PROTOCOL_TCP || is_udp);

  t1 = (flow_hash_config & IP_FLOW_HASH_SRC_ADDR) ? src_addr_u32 : 0;
  t2 = (flow_hash_config & IP_FLOW_HASH_DST_ADDR) ? dst_addr_u32 : 0;

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

  b ^= (flow_hash_config & IP_FLOW_HASH_PROTO) ? hash_protocol : 0;
  c = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ?
    (t1 << 16) | t2 : (t2 << 16) | t1;
  if (PREDICT_TRUE (is_udp) &&
      PREDICT_FALSE ((flow_hash_config & IP_FLOW_HASH_GTPV1_TEID) &&
		     udp->dst_port == GTPV1_PORT_BE))
    {
      t1 = gtpu->teid;
      c ^= t1;
    }
  a ^= ip_flow_hash_router_id;

  hash_v3_mix32 (a, b, c);
  hash_v3_finalize32 (a, b, c);

  return c;
}

always_inline void *
vlib_buffer_push_ip4_custom (vlib_main_t *vm, vlib_buffer_t *b,
			     ip4_address_t *src, ip4_address_t *dst, int proto,
			     u8 csum_offload, u8 is_df, u8 dscp)
{
  ip4_header_t *ih;

  /* make some room */
  ih = vlib_buffer_push_uninit (b, sizeof (ip4_header_t));

  ih->ip_version_and_header_length = 0x45;
  ip4_header_set_dscp (ih, dscp);
  ip4_header_set_ecn (ih, 0);
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
				      1 /* is_df */, 0);
}

#endif /* included_ip_ip4_inlines_h */
