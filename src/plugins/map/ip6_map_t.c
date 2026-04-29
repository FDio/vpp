/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#include "map.h"

#include <vnet/ip/ip4_to_ip6.h>
#include <vnet/ip/ip6_to_ip4.h>
#include <vnet/ip/ip_frag.h>

typedef enum
{
  IP6_MAPT_NEXT_MAPT_TCP_UDP,
  IP6_MAPT_NEXT_MAPT_ICMP,
  IP6_MAPT_NEXT_MAPT_FRAGMENTED,
  IP6_MAPT_NEXT_DROP,
  IP6_MAPT_NEXT_ICMP,
  IP6_MAPT_N_NEXT
} ip6_mapt_next_t;

typedef enum
{
  IP6_MAPT_ICMP_NEXT_IP4_LOOKUP,
  IP6_MAPT_ICMP_NEXT_IP4_REWRITE,
  IP6_MAPT_ICMP_NEXT_IP4_FRAG,
  IP6_MAPT_ICMP_NEXT_DROP,
  IP6_MAPT_ICMP_N_NEXT
} ip6_mapt_icmp_next_t;

typedef enum
{
  IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP,
  IP6_MAPT_TCP_UDP_NEXT_IP4_REWRITE,
  IP6_MAPT_TCP_UDP_NEXT_IP4_FRAG,
  IP6_MAPT_TCP_UDP_NEXT_DROP,
  IP6_MAPT_TCP_UDP_N_NEXT
} ip6_mapt_tcp_udp_next_t;

typedef enum
{
  IP6_MAPT_FRAGMENTED_NEXT_IP4_LOOKUP,
  IP6_MAPT_FRAGMENTED_NEXT_IP4_REWRITE,
  IP6_MAPT_FRAGMENTED_NEXT_IP4_FRAG,
  IP6_MAPT_FRAGMENTED_NEXT_DROP,
  IP6_MAPT_FRAGMENTED_N_NEXT
} ip6_mapt_fragmented_next_t;

typedef struct
{
  map_domain_t *d;
  u16 sender_port;
} icmp6_to_icmp_ctx_t;

static int
ip6_to_ip4_set_icmp_cb (ip6_header_t * ip6, ip4_header_t * ip4, void *arg)
{
  icmp6_to_icmp_ctx_t *ctx = arg;
  u32 ip4_sadr;

  /*
   * For per-VRF MAP-T 1:1 mode (ip6_prefix_len == 128 && ea_bits_len == 0),
   * the reverse packet's v6 source is the opaque /128 DMR that the
   * headend listens on — it carries no embedded v4. Use d->ip4_prefix
   * as the v4 source and skip the DMR-encoded security check: the
   * dst-keyed domain resolution in the ip6_map_t entry node has
   * already authenticated this packet against the domain's per-tenant
   * ip6_src prefix (see the matching short-circuit in ip6_map_t /
   * map_ip6_to_ip4_tcp_udp).
   *
   * For legacy encodings (DMR < /128 or ea_bits_len > 0), the
   * upstream behaviour still applies: recover v4 src from v6 src via
   * RFC 6052 offset, then verify v6 src matches the domain's
   * DMR-encoded (v4 + port) form.
   */
  if (ctx->d->ip6_prefix_len == 128 && ctx->d->ea_bits_len == 0)
    {
      ip4_sadr = ctx->d->ip4_prefix.as_u32;
    }
  else
    {
      ip4_sadr = map_get_ip4 (&ip6->src_address, ctx->d->ip6_src_len);
      if (ip6->src_address.as_u64[0] != map_get_pfx_net (ctx->d, ip4_sadr, ctx->sender_port) ||
	  ip6->src_address.as_u64[1] != map_get_sfx_net (ctx->d, ip4_sadr, ctx->sender_port))
	return -1;
    }

  ip4->dst_address.as_u32 =
    ip6_map_t_embedded_address (ctx->d, &ip6->dst_address);
  ip4->src_address.as_u32 = ip4_sadr;

  return 0;
}

static int
ip6_to_ip4_set_inner_icmp_cb (ip6_header_t * ip6, ip4_header_t * ip4,
			      void *arg)
{
  icmp6_to_icmp_ctx_t *ctx = arg;
  u32 inner_ip4_dadr;

  /*
   * Inner-header ICMP translation. The inner v6 header's direction is
   * flipped relative to the outer, so for 1:1 mode the inner v6 dst
   * is the opaque /128 DMR (the thing the original v4 flow was
   * destined to). Use d->ip4_prefix directly; no DMR-encoded security
   * check to invert here either — the outer header's authenticity has
   * already been established by ip6_map_t's entry node.
   */
  if (ctx->d->ip6_prefix_len == 128 && ctx->d->ea_bits_len == 0)
    {
      inner_ip4_dadr = ctx->d->ip4_prefix.as_u32;
    }
  else
    {
      inner_ip4_dadr = map_get_ip4 (&ip6->dst_address, ctx->d->ip6_src_len);
      if (ip6->dst_address.as_u64[0] !=
	    map_get_pfx_net (ctx->d, inner_ip4_dadr, ctx->sender_port) ||
	  ip6->dst_address.as_u64[1] != map_get_sfx_net (ctx->d, inner_ip4_dadr, ctx->sender_port))
	return -1;
    }

  ip4->dst_address.as_u32 = inner_ip4_dadr;
  ip4->src_address.as_u32 =
    ip6_map_t_embedded_address (ctx->d, &ip6->src_address);

  return 0;
}

static uword
ip6_map_t_icmp (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_t_icmp_node.index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  vlib_combined_counter_main_t *cm = map_main.domain_counters;
  clib_thread_index_t thread_index = vm->thread_index;

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  u8 error0;
	  ip6_mapt_icmp_next_t next0;
	  map_domain_t *d0;
	  u16 len0;
	  icmp6_to_icmp_ctx_t ctx0;
	  ip6_header_t *ip60;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  error0 = MAP_ERROR_NONE;
	  next0 = IP6_MAPT_ICMP_NEXT_IP4_LOOKUP;

	  p0 = vlib_get_buffer (vm, pi0);
	  ip60 = vlib_buffer_get_current (p0);
	  len0 = clib_net_to_host_u16 (ip60->payload_length);
	  d0 =
	    pool_elt_at_index (map_main.domains,
			       vnet_buffer (p0)->map_t.map_domain_index);
	  ctx0.d = d0;
	  ctx0.sender_port = 0;
	  if (!ip6_get_port (vm, p0, ip60, p0->current_length, NULL,
			     &ctx0.sender_port, NULL, NULL, NULL, NULL, NULL))
	    {
	      // In case of 1:1 mapping, we don't care about the port
	      if (!(d0->ea_bits_len == 0 && d0->rules))
		{
		  error0 = MAP_ERROR_ICMP;
		  goto err0;
		}
	    }

	  if (icmp6_to_icmp (vm, p0, ip6_to_ip4_set_icmp_cb, &ctx0,
			     ip6_to_ip4_set_inner_icmp_cb, &ctx0))
	    {
	      error0 = MAP_ERROR_ICMP;
	      goto err0;
	    }

	  /* Per-VRF FIB override. Must be set regardless of which branch
	   * we take below: the ip_frag path eventually enqueues to
	   * ip4-lookup too, and needs the same tenant FIB selection as
	   * the fast-path rewrite branch. */
	  if (d0->ip4_fib_index != 0)
	    vnet_buffer (p0)->sw_if_index[VLIB_TX] = d0->ip4_fib_index;

	  if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
	    {
	      // Send to fragmentation node if necessary
	      vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
	      vnet_buffer (p0)->ip_frag.next_index = IP_FRAG_NEXT_IP4_LOOKUP;
	      next0 = IP6_MAPT_ICMP_NEXT_IP4_FRAG;
	    }
	  else
	    {
	      next0 =
		ip6_map_ip4_lookup_bypass (p0, NULL, d0) ? IP6_MAPT_ICMP_NEXT_IP4_REWRITE : next0;
	    }
	err0:
	  if (PREDICT_TRUE (error0 == MAP_ERROR_NONE))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_RX,
					       thread_index,
					       vnet_buffer (p0)->
					       map_t.map_domain_index, 1,
					       len0);
	    }
	  else
	    {
	      next0 = IP6_MAPT_ICMP_NEXT_DROP;
	    }

	  p0->error = error_node->errors[error0];
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, pi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

/*
 * Translate IPv6 fragmented packet to IPv4.
 */
always_inline int
map_ip6_to_ip4_fragmented (vlib_main_t * vm, vlib_buffer_t * p)
{
  ip6_header_t *ip6;
  ip6_frag_hdr_t *frag;
  ip4_header_t *ip4;
  u16 frag_id;
  u8 frag_more;
  u16 frag_offset;
  u8 l4_protocol;
  u16 l4_offset;

  ip6 = vlib_buffer_get_current (p);

  if (ip6_parse
      (vm, p, ip6, p->current_length, &l4_protocol, &l4_offset, &frag_offset))
    return -1;

  frag = (ip6_frag_hdr_t *) u8_ptr_add (ip6, frag_offset);
  ip4 = (ip4_header_t *) u8_ptr_add (ip6, l4_offset - sizeof (*ip4));
  vlib_buffer_advance (p, l4_offset - sizeof (*ip4));

  frag_id = frag_id_6to4 (frag->identification);
  frag_more = ip6_frag_hdr_more (frag);
  frag_offset = ip6_frag_hdr_offset (frag);

  ip4->dst_address.as_u32 = vnet_buffer (p)->map_t.v6.daddr;
  ip4->src_address.as_u32 = vnet_buffer (p)->map_t.v6.saddr;

  ip4->ip_version_and_header_length =
    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
  ip4->tos = ip6_translate_tos (ip6->ip_version_traffic_class_and_flow_label);
  ip4->length =
    u16_net_add (ip6->payload_length,
		 sizeof (*ip4) - l4_offset + sizeof (*ip6));
  ip4->fragment_id = frag_id;
  ip4->flags_and_fragment_offset =
    clib_host_to_net_u16 (frag_offset |
			  (frag_more ? IP4_HEADER_FLAG_MORE_FRAGMENTS : 0));
  ip4->ttl = ip6->hop_limit;
  ip4->protocol =
    (l4_protocol == IP_PROTOCOL_ICMP6) ? IP_PROTOCOL_ICMP : l4_protocol;
  ip4->checksum = ip4_header_checksum (ip4);

  return 0;
}

static uword
ip6_map_t_fragmented (vlib_main_t * vm,
		      vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_t_fragmented_node.index);

  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  u32 next0;
	  map_domain_t *d0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  next0 = IP6_MAPT_FRAGMENTED_NEXT_IP4_LOOKUP;
	  p0 = vlib_get_buffer (vm, pi0);
	  d0 = pool_elt_at_index (map_main.domains, vnet_buffer (p0)->map_t.map_domain_index);

	  if (map_ip6_to_ip4_fragmented (vm, p0))
	    {
	      p0->error = error_node->errors[MAP_ERROR_FRAGMENT_DROPPED];
	      next0 = IP6_MAPT_FRAGMENTED_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
		{
		  // Send to fragmentation node if necessary
		  vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
		  vnet_buffer (p0)->ip_frag.next_index =
		    IP_FRAG_NEXT_IP4_LOOKUP;
		  next0 = IP6_MAPT_FRAGMENTED_NEXT_IP4_FRAG;
		}
	      else
		{
		  next0 = ip6_map_ip4_lookup_bypass (p0, NULL, d0) ?
			    IP6_MAPT_FRAGMENTED_NEXT_IP4_REWRITE :
			    next0;
		}
	      if (d0->ip4_fib_index != 0)
		vnet_buffer (p0)->sw_if_index[VLIB_TX] = d0->ip4_fib_index;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, pi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

/*
 * Translate IPv6 UDP/TCP packet to IPv4.
 * Returns 0 on success.
 * Returns a non-zero error code on error.
 */
always_inline int
map_ip6_to_ip4_tcp_udp (vlib_main_t * vm, vlib_buffer_t * p,
			bool udp_checksum)
{
  map_main_t *mm = &map_main;
  ip6_header_t *ip6;
  u16 *checksum;
  ip_csum_t csum = 0;
  ip4_header_t *ip4;
  u16 fragment_id;
  u16 flags;
  u16 frag_offset;
  u8 l4_protocol;
  u16 l4_offset;
  ip6_address_t old_src, old_dst;

  ip6 = vlib_buffer_get_current (p);

  if (ip6_parse
      (vm, p, ip6, p->current_length, &l4_protocol, &l4_offset, &frag_offset))
    return -1;

  if (l4_protocol == IP_PROTOCOL_TCP)
    {
      tcp_header_t *tcp = (tcp_header_t *) u8_ptr_add (ip6, l4_offset);
      if (mm->tcp_mss > 0)
	{
	  csum = tcp->checksum;
	  map_mss_clamping (tcp, &csum, mm->tcp_mss);
	  tcp->checksum = ip_csum_fold (csum);
	}
      checksum = &tcp->checksum;
    }
  else
    {
      udp_header_t *udp = (udp_header_t *) u8_ptr_add (ip6, l4_offset);
      checksum = &udp->checksum;
    }

  old_src.as_u64[0] = ip6->src_address.as_u64[0];
  old_src.as_u64[1] = ip6->src_address.as_u64[1];
  old_dst.as_u64[0] = ip6->dst_address.as_u64[0];
  old_dst.as_u64[1] = ip6->dst_address.as_u64[1];

  ip4 = (ip4_header_t *) u8_ptr_add (ip6, l4_offset - sizeof (*ip4));

  vlib_buffer_advance (p, l4_offset - sizeof (*ip4));

  if (PREDICT_FALSE (frag_offset))
    {
      // Only the first fragment
      ip6_frag_hdr_t *hdr = (ip6_frag_hdr_t *) u8_ptr_add (ip6, frag_offset);
      fragment_id = frag_id_6to4 (hdr->identification);
      flags = clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
    }
  else
    {
      fragment_id = 0;
      flags = 0;
    }

  ip4->dst_address.as_u32 = vnet_buffer (p)->map_t.v6.daddr;
  ip4->src_address.as_u32 = vnet_buffer (p)->map_t.v6.saddr;

  /*
   * Drop spoofed packets that from a known domain source.
   */
  u32 map_domain_index = -1;
  u8 error = 0;

  /* Anti-spoof callback runs on the reverse path; drive the LPM
   * lookup in the tenant IPv4 FIB that the resolved MAP domain
   * belongs to so overlapping v4 prefixes in different VRFs don't
   * alias one another. For single-tenant/default-FIB domains the
   * fib_index resolves to 0 and behaviour matches upstream. */
  u32 anti_spoof_fib_index = 0;
  if (vnet_buffer (p)->map_t.map_domain_index != ~0)
    {
      map_domain_t *sd = pool_elt_at_index (mm->domains, vnet_buffer (p)->map_t.map_domain_index);
      anti_spoof_fib_index = sd->ip4_fib_index;
    }

  ip4_map_get_domain (anti_spoof_fib_index, &ip4->src_address, &map_domain_index, &error);
  if (error)
    return error;

  ip4->ip_version_and_header_length =
    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
  ip4->tos = ip6_translate_tos (ip6->ip_version_traffic_class_and_flow_label);
  ip4->length =
    u16_net_add (ip6->payload_length,
		 sizeof (*ip4) + sizeof (*ip6) - l4_offset);
  ip4->fragment_id = fragment_id;
  ip4->flags_and_fragment_offset = flags;
  ip4->ttl = ip6->hop_limit;
  ip4->protocol = l4_protocol;
  ip4->checksum = ip4_header_checksum (ip4);

  // UDP checksum is optional over IPv4
  if (!udp_checksum && l4_protocol == IP_PROTOCOL_UDP)
    {
      *checksum = 0;
    }
  else
    {
      csum = ip_csum_sub_even (*checksum, old_src.as_u64[0]);
      csum = ip_csum_sub_even (csum, old_src.as_u64[1]);
      csum = ip_csum_sub_even (csum, old_dst.as_u64[0]);
      csum = ip_csum_sub_even (csum, old_dst.as_u64[1]);
      csum = ip_csum_add_even (csum, ip4->dst_address.as_u32);
      csum = ip_csum_add_even (csum, ip4->src_address.as_u32);
      *checksum = ip_csum_fold (csum);
    }

  return 0;
}

static uword
ip6_map_t_tcp_udp (vlib_main_t * vm,
		   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_t_tcp_udp_node.index);

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  ip6_mapt_tcp_udp_next_t next0;
	  map_domain_t *d0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  next0 = IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP;

	  p0 = vlib_get_buffer (vm, pi0);
	  d0 = pool_elt_at_index (map_main.domains, vnet_buffer (p0)->map_t.map_domain_index);

	  if (map_ip6_to_ip4_tcp_udp (vm, p0, true))
	    {
	      p0->error = error_node->errors[MAP_ERROR_UNKNOWN];
	      next0 = IP6_MAPT_TCP_UDP_NEXT_DROP;
	    }
	  else
	    {
	      if (vnet_buffer (p0)->map_t.mtu < p0->current_length)
		{
		  // Send to fragmentation node if necessary
		  vnet_buffer (p0)->ip_frag.mtu = vnet_buffer (p0)->map_t.mtu;
		  vnet_buffer (p0)->ip_frag.next_index =
		    IP_FRAG_NEXT_IP4_LOOKUP;
		  next0 = IP6_MAPT_TCP_UDP_NEXT_IP4_FRAG;
		}
	      else
		{
		  next0 = ip6_map_ip4_lookup_bypass (p0, NULL, d0) ?
			    IP6_MAPT_TCP_UDP_NEXT_IP4_REWRITE :
			    next0;
		}
	      if (d0->ip4_fib_index != 0)
		vnet_buffer (p0)->sw_if_index[VLIB_TX] = d0->ip4_fib_index;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, pi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

static uword
ip6_map_t (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_map_t_node.index);
  map_main_t *mm = &map_main;
  vlib_combined_counter_main_t *cm = map_main.domain_counters;
  clib_thread_index_t thread_index = vm->thread_index;

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0)
    {
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 pi0;
	  vlib_buffer_t *p0;
	  ip6_header_t *ip60;
	  u8 error0;
	  u32 l4_len0;
	  i32 map_port0;
	  map_domain_t *d0;
	  ip6_frag_hdr_t *frag0;
	  ip6_mapt_next_t next0 = 0;
	  u32 saddr;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  error0 = MAP_ERROR_NONE;
	  p0 = vlib_get_buffer (vm, pi0);
	  u16 l4_src_port = vnet_buffer (p0)->ip.reass.l4_src_port;

	  ip60 = vlib_buffer_get_current (p0);

	  /*
	   * Resolve the MAP domain. Upstream and cndp-vpp key on the v6
	   * source against ip6_prefix_tbl (which holds DMR prefixes);
	   * per-VRF domains key on the v6 destination against
	   * ip6_src_prefix_tbl (which holds each domain's per-tenant
	   * ip6_src prefix). We don't know which kind of domain the
	   * packet belongs to yet, so try the upstream (src-in-DMR)
	   * lookup first and fall back to the per-VRF (dst-in-ip6_src)
	   * table if it misses.
	   *
	   * Each hit is filtered by d->v6_lookup_side so a mixed-mode
	   * deployment — legacy SRC-keyed domain and per-VRF DST-keyed
	   * domain both installing entries that collide on the same v6
	   * address — cannot misroute return traffic. A DST-keyed
	   * domain's ip6_src prefix inserted into ip6_src_prefix_tbl
	   * must never be resolved via the SRC-keyed path, and vice
	   * versa. If the filter rejects the hit we re-run the lookup
	   * on the other side.
	   */
	  d0 = ip6_map_get_domain (&ip60->src_address, &vnet_buffer (p0)->map_t.map_domain_index,
				   &error0);
	  if (d0 && d0->v6_lookup_side != MAP_V6_LOOKUP_SRC)
	    {
	      /* SRC-keyed hit returned a domain that is not actually
	       * SRC-keyed (shared DMR with a DST-keyed domain). Discard
	       * and try the DST-keyed path. */
	      d0 = 0;
	      error0 = MAP_ERROR_NONE;
	    }
	  if (!d0)
	    {
	      error0 = MAP_ERROR_NONE;
	      d0 = ip6_map_get_domain_dst (&ip60->dst_address,
					   &vnet_buffer (p0)->map_t.map_domain_index, &error0);
	      if (d0 && d0->v6_lookup_side != MAP_V6_LOOKUP_DST)
		{
		  /* DST-keyed hit on a domain that is SRC-keyed — this
		   * would silently promote a legacy domain into MAP-T
		   * processing for the wrong packet. Reject. */
		  d0 = 0;
		  error0 = MAP_ERROR_NO_DOMAIN;
		}
	    }
	  if (!d0)
	    {			/* Guess it wasn't for us */
	      vnet_feature_next (&next0, p0);
	      goto exit;
	    }

	  /*
	   * Recover the original IPv4 source. Upstream MAP-T extracts it
	   * from the v6 source using RFC 6052 offset-based encoding
	   * (ip6_src_len of 64 or 96). Per-VRF MAP-T domains commonly run
	   * in 1:1 mode (RFC 7597 §5.1) with a fixed /128 DMR — the v6
	   * source of the return packet is the headend's listen address,
	   * it carries no encoded v4. For those domains the v4 source is
	   * fixed at domain-create time in d->ip4_prefix and must be used
	   * as-is.
	   */
	  if (d0->ip6_prefix_len == 128 && d0->ea_bits_len == 0)
	    saddr = d0->ip4_prefix.as_u32;
	  else
	    saddr = map_get_ip4 (&ip60->src_address, d0->ip6_src_len);
	  vnet_buffer (p0)->map_t.v6.saddr = saddr;
	  vnet_buffer (p0)->map_t.v6.daddr =
	    ip6_map_t_embedded_address (d0, &ip60->dst_address);
	  vnet_buffer (p0)->map_t.mtu = d0->mtu ? d0->mtu : ~0;

	  map_port0 = -1;

	  if (PREDICT_FALSE (ip60->hop_limit == 1))
	    {
	      icmp6_error_set_vnet_buffer (p0, ICMP6_time_exceeded,
					   ICMP6_time_exceeded_ttl_exceeded_in_transit,
					   0);
	      p0->error = error_node->errors[MAP_ERROR_TIME_EXCEEDED];
	      next0 = IP6_MAPT_NEXT_ICMP;
	      goto trace;
	    }

	  if (PREDICT_FALSE
	      (ip6_parse (vm, p0, ip60, p0->current_length,
			  &(vnet_buffer (p0)->map_t.v6.l4_protocol),
			  &(vnet_buffer (p0)->map_t.v6.l4_offset),
			  &(vnet_buffer (p0)->map_t.v6.frag_offset))))
	    {
	      error0 =
		error0 == MAP_ERROR_NONE ? MAP_ERROR_MALFORMED : error0;
	    }

	  l4_len0 =
	    (u32) clib_net_to_host_u16 (ip60->payload_length) +
	    sizeof (*ip60) - vnet_buffer (p0)->map_t.v6.l4_offset;
	  frag0 =
	    (ip6_frag_hdr_t *) u8_ptr_add (ip60,
					   vnet_buffer (p0)->map_t.v6.
					   frag_offset);

	  if (PREDICT_FALSE
	      (vnet_buffer (p0)->map_t.v6.frag_offset
	       && ip6_frag_hdr_offset (frag0)))
	    {
	      map_port0 = l4_src_port;
	      next0 = IP6_MAPT_NEXT_MAPT_FRAGMENTED;
	    }
	  else
	    if (PREDICT_TRUE
		(vnet_buffer (p0)->map_t.v6.l4_protocol == IP_PROTOCOL_TCP))
	    {
	      error0 =
		l4_len0 <
		sizeof (tcp_header_t) ? MAP_ERROR_MALFORMED : error0;
	      vnet_buffer (p0)->map_t.checksum_offset =
		vnet_buffer (p0)->map_t.v6.l4_offset + 16;
	      next0 = IP6_MAPT_NEXT_MAPT_TCP_UDP;
	      map_port0 = l4_src_port;
	    }
	  else
	    if (PREDICT_TRUE
		(vnet_buffer (p0)->map_t.v6.l4_protocol == IP_PROTOCOL_UDP))
	    {
	      error0 =
		l4_len0 <
		sizeof (udp_header_t) ? MAP_ERROR_MALFORMED : error0;
	      vnet_buffer (p0)->map_t.checksum_offset =
		vnet_buffer (p0)->map_t.v6.l4_offset + 6;
	      next0 = IP6_MAPT_NEXT_MAPT_TCP_UDP;
	      map_port0 = l4_src_port;
	    }
	  else if (vnet_buffer (p0)->map_t.v6.l4_protocol ==
		   IP_PROTOCOL_ICMP6)
	    {
	      error0 =
		l4_len0 <
		sizeof (icmp46_header_t) ? MAP_ERROR_MALFORMED : error0;
	      next0 = IP6_MAPT_NEXT_MAPT_ICMP;
	      if (((icmp46_header_t *)
		   u8_ptr_add (ip60,
			       vnet_buffer (p0)->map_t.v6.l4_offset))->type ==
		  ICMP6_echo_reply
		  || ((icmp46_header_t *)
		      u8_ptr_add (ip60,
				  vnet_buffer (p0)->map_t.v6.l4_offset))->
		  type == ICMP6_echo_request)
		map_port0 = l4_src_port;
	    }
	  else
	    {
	      // TODO: In case of 1:1 mapping, it might be possible to
	      // do something with those packets.
	      error0 = MAP_ERROR_BAD_PROTOCOL;
	    }

	  if (PREDICT_FALSE (map_port0 != -1) &&
	      (ip60->src_address.as_u64[0] !=
	       map_get_pfx_net (d0, vnet_buffer (p0)->map_t.v6.saddr,
				map_port0)
	       || ip60->src_address.as_u64[1] != map_get_sfx_net (d0,
								  vnet_buffer
								  (p0)->map_t.
								  v6.saddr,
								  map_port0)))
	    {
	      // Security check when map_port0 is not zero (non-first
	      // fragment, UDP or TCP)
	      error0 =
		error0 == MAP_ERROR_NONE ? MAP_ERROR_SEC_CHECK : error0;
	    }

	  if (PREDICT_TRUE
	      (error0 == MAP_ERROR_NONE && next0 != IP6_MAPT_NEXT_MAPT_ICMP))
	    {
	      vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_RX,
					       thread_index,
					       vnet_buffer (p0)->map_t.
					       map_domain_index, 1,
					       clib_net_to_host_u16 (ip60->
								     payload_length));
	    }

	  if (PREDICT_FALSE
	      (error0 == MAP_ERROR_SEC_CHECK && mm->icmp6_enabled))
	    {
	      icmp6_error_set_vnet_buffer (p0, ICMP6_destination_unreachable,
					   ICMP6_destination_unreachable_source_address_failed_policy,
					   0);
	      next0 = IP6_MAPT_NEXT_ICMP;
	    }
	  else
	    {
	      next0 = (error0 != MAP_ERROR_NONE) ? IP6_MAPT_NEXT_DROP : next0;
	    }

	  p0->error = error_node->errors[error0];
	trace:
	  if (PREDICT_FALSE (p0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      map_add_trace (vm, node, p0,
			     vnet_buffer (p0)->map_t.map_domain_index,
			     map_port0);
	    }
	exit:
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
					   to_next, n_left_to_next, pi0,
					   next0);
	}
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(ip6_map_t_fragmented_node) = {
  .function = ip6_map_t_fragmented,
  .name = "ip6-map-t-fragmented",
  .vector_size = sizeof (u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_counters = map_error_counters,

  .n_next_nodes = IP6_MAPT_FRAGMENTED_N_NEXT,
  .next_nodes =
  {
    [IP6_MAPT_FRAGMENTED_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IP6_MAPT_FRAGMENTED_NEXT_IP4_REWRITE] = "ip4-load-balance",
    [IP6_MAPT_FRAGMENTED_NEXT_IP4_FRAG] = IP4_FRAG_NODE_NAME,
    [IP6_MAPT_FRAGMENTED_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE(ip6_map_t_icmp_node) = {
  .function = ip6_map_t_icmp,
  .name = "ip6-map-t-icmp",
  .vector_size = sizeof (u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_counters = map_error_counters,

  .n_next_nodes = IP6_MAPT_ICMP_N_NEXT,
  .next_nodes =
  {
    [IP6_MAPT_ICMP_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IP6_MAPT_ICMP_NEXT_IP4_REWRITE] = "ip4-load-balance",
    [IP6_MAPT_ICMP_NEXT_IP4_FRAG] = IP4_FRAG_NODE_NAME,
    [IP6_MAPT_ICMP_NEXT_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE(ip6_map_t_tcp_udp_node) = {
  .function = ip6_map_t_tcp_udp,
  .name = "ip6-map-t-tcp-udp",
  .vector_size = sizeof (u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_counters = map_error_counters,

  .n_next_nodes = IP6_MAPT_TCP_UDP_N_NEXT,
  .next_nodes =
  {
    [IP6_MAPT_TCP_UDP_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IP6_MAPT_TCP_UDP_NEXT_IP4_REWRITE] = "ip4-load-balance",
    [IP6_MAPT_TCP_UDP_NEXT_IP4_FRAG] = IP4_FRAG_NODE_NAME,
    [IP6_MAPT_TCP_UDP_NEXT_DROP] = "error-drop",
  },
};

VNET_FEATURE_INIT (ip6_map_t_feature, static) = {
    .arc_name = "ip6-unicast",
    .node_name = "ip6-map-t",
    .runs_before = VNET_FEATURES ("ip6-flow-classify"),
    .runs_after = VNET_FEATURES ("ip6-sv-reassembly-feature"),
};

VLIB_REGISTER_NODE(ip6_map_t_node) = {
  .function = ip6_map_t,
  .name = "ip6-map-t",
  .vector_size = sizeof(u32),
  .format_trace = format_map_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = MAP_N_ERROR,
  .error_counters = map_error_counters,

  .n_next_nodes = IP6_MAPT_N_NEXT,
  .next_nodes =
  {
    [IP6_MAPT_NEXT_MAPT_TCP_UDP] = "ip6-map-t-tcp-udp",
    [IP6_MAPT_NEXT_MAPT_ICMP] = "ip6-map-t-icmp",
    [IP6_MAPT_NEXT_MAPT_FRAGMENTED] = "ip6-map-t-fragmented",
    [IP6_MAPT_NEXT_DROP] = "error-drop",
    [IP6_MAPT_NEXT_ICMP] = "ip6-icmp-error",
  },
};
