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

#ifndef __ADJ_DP_H__
#define __ADJ_DP_H__

#include <vnet/adj/adj.h>
#include <vnet/tunnel/tunnel_dp.h>
#include <vnet/ip/ip4_inlines.h>
#include <vnet/ip/ip6_inlines.h>
#include <vnet/mpls/mpls_lookup.h>

static_always_inline void
adj_midchain_ipip44_fixup (vlib_main_t * vm,
                           const ip_adjacency_t * adj,
                           vlib_buffer_t * b)
{
  tunnel_encap_decap_flags_t flags;
  ip4_header_t *ip4;

  flags = pointer_to_uword (adj->sub_type.midchain.fixup_data);

  ip4 = vlib_buffer_get_current (b);
  ip4->length = clib_host_to_net_u16 (vlib_buffer_length_in_chain (vm, b));

  if (PREDICT_TRUE(TUNNEL_ENCAP_DECAP_FLAG_NONE == flags))
  {
      ip_csum_t sum;
      u16 old,new;

      old = 0;
      new = ip4->length;

      sum = ip4->checksum;
      sum = ip_csum_update (sum, old, new, ip4_header_t, length);
      ip4->checksum = ip_csum_fold (sum);
  }
  else
  {
      tunnel_encap_fixup_4o4 (flags, ip4 + 1, ip4);
      ip4->checksum = ip4_header_checksum (ip4);
  }
}

static_always_inline void
adj_midchain_fixup (vlib_main_t *vm,
                    const ip_adjacency_t *adj,
                    vlib_buffer_t * b,
                    vnet_link_t lt)
{
    if (PREDICT_TRUE(adj->rewrite_header.flags &
                     VNET_REWRITE_FIXUP_IP4_O_4))
        adj_midchain_ipip44_fixup (vm, adj, b);
    else if (adj->sub_type.midchain.fixup_func)
        adj->sub_type.midchain.fixup_func
            (vm, adj, b, adj->sub_type.midchain.fixup_data);

    if (PREDICT_FALSE(adj->rewrite_header.flags &
                      VNET_REWRITE_FIXUP_FLOW_HASH))
    {
        if (VNET_LINK_IP4 == lt)
            vnet_buffer (b)->ip.flow_hash =
                ip4_compute_flow_hash (vlib_buffer_get_current (b) + adj->rewrite_header.data_bytes,
                                       IP_FLOW_HASH_DEFAULT);
        else if (VNET_LINK_IP6 == lt)
            vnet_buffer (b)->ip.flow_hash =
                ip6_compute_flow_hash (vlib_buffer_get_current (b) + adj->rewrite_header.data_bytes,
                                       IP_FLOW_HASH_DEFAULT);
        else if (VNET_LINK_MPLS == lt)
            vnet_buffer (b)->ip.flow_hash =
                mpls_compute_flow_hash (vlib_buffer_get_current (b) + adj->rewrite_header.data_bytes,
                                       IP_FLOW_HASH_DEFAULT);
    }
}

#endif
