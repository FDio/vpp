/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_lookup_common_h__
#define __included_lookup_common_h__
#include <vlib/vlib.h>
#include <vnet/ip/ip.h>

#ifndef CLIB_HAVE_VEC256
#define u32x8_splat(i) ((u32) (i) & (u32x8){ ~0, ~0, ~0, ~0, ~0, ~0, ~0, ~0 })
#endif

__clib_unused static const u8 l4_mask_bits[256] = {
  [IP_PROTOCOL_ICMP] = 16,     [IP_PROTOCOL_IGMP] = 8,
  [IP_PROTOCOL_ICMP6] = 16,    [IP_PROTOCOL_TCP] = 32,
  [IP_PROTOCOL_UDP] = 32,      [IP_PROTOCOL_IPSEC_ESP] = 32,
  [IP_PROTOCOL_IPSEC_AH] = 32,
};

/* L4 data offset to copy into session */
__clib_unused static const u8 l4_offset_32w[256] = {
  [IP_PROTOCOL_ICMP] = 1, [IP_PROTOCOL_ICMP6] = 1
};

/* TODO: add ICMP, ESP, and AH (+ additional
 * branching or lookup for different
 * shuffling mask) */
__clib_unused static const u64 tcp_udp_bitmask =
  ((1 << IP_PROTOCOL_TCP) | (1 << IP_PROTOCOL_UDP));

#endif /* __included_lookup_common_h__ */