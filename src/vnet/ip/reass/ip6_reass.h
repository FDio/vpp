/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rubicon Communications, LLC.
 */

/**
 * @file
 * @brief IPv6 reassembly policy shared by the full and shallow-virtual nodes.
 */

#ifndef __included_ip6_reass_h__
#define __included_ip6_reass_h__

#include <vnet/ip/icmp46_packet.h>
#include <vnet/ip/icmp6.h>
#include <vnet/ip/ip.api_enum.h>
#include <vnet/ip/ip6_packet.h>

/**
 * @brief ICMPv6 Parameter Problem response for a malformed header chain.
 *
 * code and pointer are the ICMPv6 Parameter Problem fields. error is the
 * ip6 error counter to increment when the packet is dropped.
 */
typedef struct
{
  u8 code;
  u32 pointer;
  u32 error;
} ip6_reass_icmp_error_t;

/**
 * @brief Classify a walked header chain for an ICMPv6 Parameter Problem.
 *
 * A chain that reached a usable terminating header needs no ICMP
 * error. Such a chain ended at a complete L4 header or at a non-first
 * fragment. A first fragment whose chain is truncated or whose L4
 * header did not fit has an incomplete upper layer, so it gets code 3
 * with pointer 0. Any other truncated chain is malformed and gets code
 * 0 pointing at the header that did not fit. A chain stopped at the
 * scan limit is not malformed, because its L4 header may lie beyond the
 * limit.
 *
 * term_offset is relative to the walk's ip. ip0_offset is the distance
 * from the packet start, vlib_buffer_get_current(), to that ip, so the
 * returned pointer is relative to the packet that ip6-icmp-error quotes.
 *
 * @returns true when the chain requires an ICMP error, false otherwise.
 */
always_inline bool
ip6_ext_hdr_chain_icmp_error (const ip6_ext_hdr_chain_t *chain, u32 ip0_offset,
			      ip6_reass_icmp_error_t *err)
{
  switch (chain->status)
    {
    case IP6_EXT_HDR_CHAIN_L4:
    case IP6_EXT_HDR_CHAIN_NON_FIRST_FRAG:
      return false;

    case IP6_EXT_HDR_CHAIN_TRUNCATED:
    case IP6_EXT_HDR_CHAIN_L4_TRUNCATED:
      /*
       * The header may continue into the next buffer segment. Only a
       * header that does not fit in the datagram is incomplete.
       */
      if (chain->buffer_bound)
	return false;
      if (chain->frag_kind == IP6_FRAG_FIRST)
	{
	  err->code = ICMP6_parameter_problem_first_fragment_has_incomplete_header_chain;
	  err->pointer = 0;
	  err->error = IP6_ERROR_REASS_MISSING_UPPER;
	  return true;
	}
      err->code = ICMP6_parameter_problem_erroneous_header_field;
      err->pointer = ip0_offset + chain->term_offset;
      err->error = IP6_ERROR_REASS_MALFORMED_PACKET;
      return true;

    case IP6_EXT_HDR_CHAIN_LIMIT:
      /*
       * The scan limit stopped the walk before the terminating header.
       * The packet may still carry a valid chain whose L4 header lies
       * beyond the limit, so no ICMP error is warranted.
       */
      return false;
    }
  return false;
}

/**
 * @brief Return true when the packet that triggered a classified ICMPv6
 * error is an ICMPv6 error or redirect message.
 *
 * RFC 4443 sections 2.4(e.1) and 2.4(e.2) forbid originating an ICMPv6
 * error in response to an ICMPv6 error message or a redirect message. The
 * ICMPv6 type is read when the walk reached a complete terminating ICMPv6
 * header. When the terminating protocol is known to be ICMPv6 but its
 * header did not fit, the type cannot be read, so the packet is treated as
 * an offender. A chain that stopped at a chain header cannot be identified
 * as an ICMPv6 offender; the caller answers it with a Parameter Problem.
 */
static_always_inline bool
ip6_reass_offender_is_icmp6 (const ip6_header_t *ip, const ip6_ext_hdr_chain_t *chain)
{
  const icmp46_header_t *icmp;

  if (chain->status == IP6_EXT_HDR_CHAIN_L4 && chain->term_protocol == IP_PROTOCOL_ICMP6)
    {
      icmp = (const icmp46_header_t *) ((const u8 *) ip + chain->term_offset);
      return icmp->type < 128 || icmp->type == ICMP6_redirect;
    }

  return ip->protocol == IP_PROTOCOL_ICMP6 || chain->term_protocol == IP_PROTOCOL_ICMP6;
}

/**
 * @brief Return true when the node may originate an ICMPv6 error for a
 * packet.
 *
 * RFC 4443 sections 2.4(e.3) and 2.4(e.6) forbid an ICMPv6 error for a
 * multicast destination or a source that does not identify a single
 * node, and sections 2.4(e.1) and 2.4(e.2) forbid answering an ICMPv6
 * error or redirect message. An output feature cannot originate an error
 * because the packet is already routed.
 */
static_always_inline bool
ip6_reass_icmp_error_allowed (const ip6_header_t *ip, const ip6_ext_hdr_chain_t *chain,
			      bool is_output_feature)
{
  return !is_output_feature && !ip6_address_is_multicast (&ip->dst_address) &&
	 !ip6_address_is_multicast (&ip->src_address) &&
	 !ip6_address_is_unspecified (&ip->src_address) && !ip6_reass_offender_is_icmp6 (ip, chain);
}

/**
 * @brief Apply a classified ICMPv6 Parameter Problem to a buffer.
 *
 * Sets the ICMPv6 error fields on the buffer and returns the ip6 error
 * counter to increment when the packet is dropped.
 */
static_always_inline u32
ip6_reass_set_icmp_error (vlib_buffer_t *b, const ip6_reass_icmp_error_t *err)
{
  icmp6_error_set_vnet_buffer (b, ICMP6_parameter_problem, err->code, err->pointer);
  return err->error;
}

#endif /* __included_ip6_reass_h__ */
