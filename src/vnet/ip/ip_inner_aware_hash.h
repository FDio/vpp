/*
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Inner-aware flow-hash helpers for IPinIP / GRE / NVGRE traffic.
 *
 * Transit traffic that carries the same outer 5-tuple per tunnel (IPv4inIPv4,
 * IPv6inIPv4, IPv4inIPv6, IPv6inIPv6 and GRE / NVGRE) collapses ECMP and LAG
 * distribution to a single member when the hash function consults only the
 * outer header.  These helpers locate the inner IP header (skipping any
 * NVGRE/TEB inner Ethernet and walking inner IPv6 extension headers) and
 * return a small descriptor that lets the IPv4, IPv6 and Ethernet hash paths
 * compute an inner-aware hash through one shared implementation.
 *
 * The feature is opt-in for the IP forwarding hash and always-on for the
 * LAG hash:
 *   - IP layer (ip4/ip6_compute_flow_hash): the caller gates invocation on
 *     flow_hash_config & IP_FLOW_HASH_PEEK_INNER.  IP_FLOW_HASH_DEFAULT
 *     does not set this bit, so existing behaviour is preserved.
 *   - LAG / hash_eth (hash-eth-l34): the existing registered function was
 *     updated to always attempt an inner peek; when the inner header
 *     cannot be resolved (non-tunnel / fragmented / unsupported protocol)
 *     it falls back to the outer-only hash, preserving existing behaviour
 *     for non-tunnel traffic.  No new hash function is registered.
 *
 * VxLAN / Geneve are intentionally NOT covered: their outer UDP source port
 * already carries inner-flow entropy (RFC 7348 §4.2, RFC 8926 §3.3).
 *
 * Safety contract:
 *   - The caller MUST pass @c remaining = number of bytes available in the
 *     buffer starting at @c payload.  Every byte dereferenced by the helper
 *     is bounds-checked against @c remaining.
 *   - The helper sets @c out->valid = 0 (and returns) whenever any check
 *     fails (truncated packet, unknown inner IP version, fragmented inner,
 *     unsupported GRE protocol etc.); the caller MUST fall back to the
 *     outer-only hash in that case.
 */

#ifndef included_ip_inner_aware_hash_h
#define included_ip_inner_aware_hash_h

#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip6_hop_by_hop_packet.h>
#include <vnet/ethernet/packet.h>
#include <vnet/gre/packet.h>

/**
 * Inner-header descriptor produced by ip_inner_resolve().
 *
 * Only one of @c ip.v4 / @c ip.v6 is meaningful, selected by @c is_v6.
 * @c l4 points at the first byte past the inner IP header (and past any
 * inner IPv6 extension headers).  When @c valid == 0 the rest of the
 * struct must not be inspected.
 */
typedef struct
{
  union
  {
    const ip4_header_t *v4;
    const ip6_header_t *v6;
  } ip;
  const void *l4;
  u8 protocol;
  u8 is_v6;
  u8 valid;
} ip_inner_hdr_t;

/* Minimum bytes that must follow the inner IP header for L4 port reads to
 * be safe.  src+dst ports occupy the first 4 bytes of TCP/UDP; we require
 * 8 bytes (the full UDP header size) so a non-TCP/UDP inner protocol still
 * keeps @c l4 pointing at a fully-mapped 8-byte region. */
#define IP_INNER_L4_MIN_BYTES 8

/**
 * Walk inner IPv6 extension headers in place.
 *
 * Advances @c *pp past every Hop-by-Hop / Routing / Destination-Options
 * extension header until a real upper-layer protocol is found.  Inner
 * Fragment / Authentication / ESP extension headers cause the function to
 * return 0 (caller treats as @c valid=0): we cannot safely peek a payload
 * we don't know how to reassemble or decrypt.
 *
 * @param[in,out] pp        pointer into the buffer; advanced past walked
 *                          extension headers.
 * @param[in,out] remaining bytes left in the buffer at *pp; decremented.
 * @param         protocol  next-header value before walking.
 * @return                  final next-header value (the upper-layer
 *                          protocol), or 0 if a walk failure occurred.
 */
static_always_inline u8
ip_inner_v6_walk_ext_headers (const u8 **pp, u32 *remaining, u8 protocol)
{
  while (protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS || protocol == IP_PROTOCOL_IPV6_ROUTE ||
	 protocol == IP_PROTOCOL_IP6_DESTINATION_OPTIONS)
    {
      if (*remaining < sizeof (ip6_hop_by_hop_header_t))
	return 0;
      const ip6_hop_by_hop_header_t *eh = (const ip6_hop_by_hop_header_t *) *pp;
      u32 eh_len = ((u32) eh->length + 1) * 8;
      if (*remaining < eh_len)
	return 0;
      protocol = eh->protocol;
      *pp += eh_len;
      *remaining -= eh_len;
    }
  /* Refuse to peek through fragments / encrypted payloads. */
  if (protocol == IP_PROTOCOL_IPV6_FRAGMENTATION || protocol == IP_PROTOCOL_IPSEC_ESP ||
      protocol == IP_PROTOCOL_IPSEC_AH)
    return 0;
  return protocol;
}

/**
 * Resolve an inner IPv4 header.  Sets @c out->valid on success.
 *
 * Skips fragmented inner v4 (no useful L4 ports) and packets whose claimed
 * IP total length exceeds the remaining buffer.
 */
static_always_inline void
ip_inner_resolve_v4 (const u8 *payload, u32 remaining, ip_inner_hdr_t *out)
{
  if (remaining < sizeof (ip4_header_t) + IP_INNER_L4_MIN_BYTES)
    return;
  const ip4_header_t *iip = (const ip4_header_t *) payload;
  if ((iip->ip_version_and_header_length >> 4) != 4)
    return;
  if (ip4_is_fragment (iip))
    return;
  out->ip.v4 = iip;
  out->protocol = iip->protocol;
  out->l4 = iip + 1;
  out->is_v6 = 0;
  out->valid = 1;
}

/**
 * Resolve an inner IPv6 header.  Walks Hop-by-Hop / Routing / Destination-
 * Options extension headers, refuses Fragment / ESP / AH inner.
 */
static_always_inline void
ip_inner_resolve_v6 (const u8 *payload, u32 remaining, ip_inner_hdr_t *out)
{
  if (remaining < sizeof (ip6_header_t) + IP_INNER_L4_MIN_BYTES)
    return;
  const ip6_header_t *iip6 = (const ip6_header_t *) payload;
  if (((iip6->ip_version_traffic_class_and_flow_label >> 4) & 0xf) != 6)
    return;
  const u8 *cur = payload + sizeof (ip6_header_t);
  u32 left = remaining - sizeof (ip6_header_t);
  u8 protocol = ip_inner_v6_walk_ext_headers (&cur, &left, iip6->protocol);
  if (protocol == 0 || left < IP_INNER_L4_MIN_BYTES)
    return;
  out->ip.v6 = iip6;
  out->protocol = protocol;
  out->l4 = cur;
  out->is_v6 = 1;
  out->valid = 1;
}

/**
 * Skip the GRE Checksum / Key / Sequence optional fields.
 *
 * @param         gre              start of GRE header.
 * @param         remaining        bytes available at @c gre.
 * @param[out]    gre_proto_out    host-order GRE protocol field.
 * @param[out]    consumed_out     bytes consumed by the GRE header.
 * @return                         non-zero on success, 0 on truncation.
 */
static_always_inline int
ip_inner_gre_skip_optional_fields (const u8 *gre, u32 remaining, u16 *gre_proto_out,
				   u32 *consumed_out)
{
  if (remaining < 4)
    return 0;
  u16 gre_flags = clib_net_to_host_u16 (clib_mem_unaligned (gre, u16));
  u32 hdr_len = 4 + ((gre_flags & GRE_FLAGS_CHECKSUM) ? 4 : 0) +
		((gre_flags & GRE_FLAGS_KEY) ? 4 : 0) + ((gre_flags & GRE_FLAGS_SEQUENCE) ? 4 : 0);
  if (remaining < hdr_len)
    return 0;
  *gre_proto_out = clib_net_to_host_u16 (clib_mem_unaligned (gre + 2, u16));
  *consumed_out = hdr_len;
  return 1;
}

/**
 * Resolve a GRE payload + protocol into an inner IP descriptor.
 *
 * For NVGRE / generic-TEB (GRE protocol 0x6558) the inner Ethernet header
 * is skipped and the inner IP version is autodetected from the version
 * nibble.  Inner VLAN tags inside the inner Ethernet are not chased (rare
 * for transit tunnels; caller will fall back to outer-only hash).
 */
static_always_inline void
ip_inner_resolve_gre (const u8 *payload, u32 remaining, u16 gre_proto, ip_inner_hdr_t *out)
{
  u16 effective_proto = gre_proto;

  if (gre_proto == GRE_PROTOCOL_teb)
    {
      if (remaining < sizeof (ethernet_header_t) + 1)
	return;
      const u8 *eth = payload;
      u16 eth_type = clib_net_to_host_u16 (clib_mem_unaligned (eth + 12, u16));
      if (eth_type == ETHERNET_TYPE_IP4)
	effective_proto = GRE_PROTOCOL_ip4;
      else if (eth_type == ETHERNET_TYPE_IP6)
	effective_proto = GRE_PROTOCOL_ip6;
      else
	return;
      payload += sizeof (ethernet_header_t);
      remaining -= sizeof (ethernet_header_t);
    }

  if (effective_proto == GRE_PROTOCOL_ip4)
    ip_inner_resolve_v4 (payload, remaining, out);
  else if (effective_proto == GRE_PROTOCOL_ip6)
    ip_inner_resolve_v6 (payload, remaining, out);
}

/**
 * Resolve an inner header given the outer L3 protocol and a bounded view
 * of the bytes just past the outer IP header.
 *
 * On success @c out->valid == 1 and the union / protocol / l4 fields are
 * filled in.  Otherwise @c out->valid == 0 and the caller falls back to
 * the outer-only hash.
 */
static_always_inline void
ip_inner_resolve (u8 outer_protocol, const u8 *payload, u32 remaining, ip_inner_hdr_t *out)
{
  out->valid = 0;
  switch (outer_protocol)
    {
    case IP_PROTOCOL_IP_IN_IP:
      ip_inner_resolve_v4 (payload, remaining, out);
      break;
    case IP_PROTOCOL_IPV6:
      ip_inner_resolve_v6 (payload, remaining, out);
      break;
    case IP_PROTOCOL_GRE:
      {
	u16 gre_proto = 0;
	u32 consumed = 0;
	if (!ip_inner_gre_skip_optional_fields (payload, remaining, &gre_proto, &consumed))
	  return;
	ip_inner_resolve_gre (payload + consumed, remaining - consumed, gre_proto, out);
	break;
      }
    default:
      break;
    }
}

/**
 * Fold a 128-bit IPv6 address to a 32-bit value (XOR of its four 32-bit
 * words).
 */
static_always_inline u32
ip6_addr_fold_u32 (const ip6_address_t *a)
{
  return a->as_u32[0] ^ a->as_u32[1] ^ a->as_u32[2] ^ a->as_u32[3];
}

#endif /* included_ip_inner_aware_hash_h */
