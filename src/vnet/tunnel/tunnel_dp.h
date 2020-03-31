/*
 * tunnel_dp.h: data-plane functions tunnels.
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#ifndef __TUNNEL_DP_H__
#define __TUNNEL_DP_H__

#include <vnet/tunnel/tunnel.h>

static_always_inline void
tunnel_encap_fixup_4o4 (tunnel_encap_decap_flags_t flags,
			const ip4_header_t * inner, ip4_header_t * outer)
{
  if (flags & TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP)
    ip4_header_set_dscp (outer, ip4_header_get_dscp (inner));
  if (flags & TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN)
    ip4_header_set_ecn (outer, ip4_header_get_ecn (inner));
  if ((flags & TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DF) &&
      ip4_header_get_df (inner))
    ip4_header_set_df (outer);
}

static_always_inline void
tunnel_encap_fixup_6o4 (tunnel_encap_decap_flags_t flags,
			const ip6_header_t * inner, ip4_header_t * outer)
{
  if (flags & TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP)
    ip4_header_set_dscp (outer, ip6_dscp_network_order (inner));
  if (flags & TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN)
    ip4_header_set_ecn (outer, ip6_ecn_network_order ((inner)));
}

static_always_inline void
tunnel_encap_fixup_6o6 (tunnel_encap_decap_flags_t flags,
			const ip6_header_t * inner, ip6_header_t * outer)
{
  if (flags & TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP)
    ip6_set_dscp_network_order (outer, ip6_dscp_network_order (inner));
  if (flags & TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN)
    ip6_set_ecn_network_order (outer, ip6_ecn_network_order (inner));
}

static_always_inline void
tunnel_encap_fixup_4o6 (tunnel_encap_decap_flags_t flags,
			const ip4_header_t * inner, ip6_header_t * outer)
{
  if (flags & TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_DSCP)
    ip6_set_dscp_network_order (outer, ip4_header_get_dscp (inner));
  if (flags & TUNNEL_ENCAP_DECAP_FLAG_ENCAP_COPY_ECN)
    ip6_set_ecn_network_order (outer, ip4_header_get_ecn (inner));
}

static_always_inline void
tunnel_decap_fixup_4o6 (tunnel_encap_decap_flags_t flags,
			ip4_header_t * inner, const ip6_header_t * outer)
{
  if (flags & TUNNEL_ENCAP_DECAP_FLAG_DECAP_COPY_ECN)
    ip4_header_set_ecn_w_chksum (inner, ip6_ecn_network_order (outer));
}

static_always_inline void
tunnel_decap_fixup_6o6 (tunnel_encap_decap_flags_t flags,
			ip6_header_t * inner, const ip6_header_t * outer)
{
  if (flags & TUNNEL_ENCAP_DECAP_FLAG_DECAP_COPY_ECN)
    ip6_set_ecn_network_order (inner, ip6_ecn_network_order (outer));
}

static_always_inline void
tunnel_decap_fixup_6o4 (tunnel_encap_decap_flags_t flags,
			ip6_header_t * inner, const ip4_header_t * outer)
{
  if (flags & TUNNEL_ENCAP_DECAP_FLAG_DECAP_COPY_ECN)
    ip6_set_ecn_network_order (inner, ip4_header_get_ecn (outer));
}

static_always_inline void
tunnel_decap_fixup_4o4 (tunnel_encap_decap_flags_t flags,
			ip4_header_t * inner, const ip4_header_t * outer)
{
  if (flags & TUNNEL_ENCAP_DECAP_FLAG_DECAP_COPY_ECN)
    ip4_header_set_ecn_w_chksum (inner, ip4_header_get_ecn (outer));
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
