/*
 *
 * ip6_nd_inline.h: ip6 neighbor discovery inline
 *
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#ifndef __IP6_ND_INLINE_H__
#define __IP6_ND_INLINE_H__

#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip-neighbor/ip_neighbor_types.h>
#include <vnet/ip6-nd/ip6_ra.h>

typedef enum
{
  ICMP6_NEIGHBOR_SOLICITATION_NEXT_DROP,
  ICMP6_NEIGHBOR_SOLICITATION_NEXT_REPLY,
  ICMP6_NEIGHBOR_SOLICITATION_N_NEXT,
} icmp6_neighbor_solicitation_or_advertisement_next_t;

static_always_inline void
icmp6_send_neighbor_advertisement (
  vlib_main_t *vm, vlib_buffer_t *b, ip6_header_t *ip6_h,
  icmp6_neighbor_solicitation_or_advertisement_header_t *icmp6_nsa,
  icmp6_neighbor_discovery_ethernet_link_layer_address_option_t
    *icmp6_nd_ell_addr,
  u32 sw_if_index0)
{
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw_if;
  ethernet_interface_t *eth_if;
  ethernet_header_t *eth;
  int bogus_length;

  /* dst address is either source address or the all-nodes mcast addr */
  if (!ip6_address_is_unspecified (&ip6_h->src_address))
    ip6_h->dst_address = ip6_h->src_address;
  else
    ip6_set_reserved_multicast_address (&ip6_h->dst_address,
					IP6_MULTICAST_SCOPE_link_local,
					IP6_MULTICAST_GROUP_ID_all_hosts);

  ip6_h->src_address = icmp6_nsa->target_address;
  ip6_h->hop_limit = 255;
  icmp6_nsa->icmp.type = ICMP6_neighbor_advertisement;

  sw_if = vnet_get_sup_sw_interface (vnm, sw_if_index0);
  ASSERT (sw_if->type == VNET_SW_INTERFACE_TYPE_HARDWARE);
  eth_if = ethernet_get_interface (&ethernet_main, sw_if->hw_if_index);
  if (eth_if && icmp6_nd_ell_addr)
    {
      clib_memcpy (icmp6_nd_ell_addr->ethernet_address, &eth_if->address, 6);
      icmp6_nd_ell_addr->header.type =
	ICMP6_NEIGHBOR_DISCOVERY_OPTION_target_link_layer_address;
    }

  icmp6_nsa->advertisement_flags =
    clib_host_to_net_u32 (ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_SOLICITED |
			  ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_OVERRIDE);

  /* if sending RAs is enabled, the "router" flag should be set,
   * otherwise, neighbors may believe we have changed from a router
   * to a host - RFC 4861 section 4.4 */
  if (ip6_ra_adv_enabled (sw_if_index0))
    icmp6_nsa->advertisement_flags |=
      clib_host_to_net_u32 (ICMP6_NEIGHBOR_ADVERTISEMENT_FLAG_ROUTER);

  icmp6_nsa->icmp.checksum = 0;
  icmp6_nsa->icmp.checksum =
    ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6_h, &bogus_length);
  ASSERT (bogus_length == 0);

  /* Reuse current MAC header, copy SMAC to DMAC and
   * interface MAC to SMAC */
  vlib_buffer_advance (b, -ethernet_buffer_header_size (b));
  eth = vlib_buffer_get_current (b);
  clib_memcpy (eth->dst_address, eth->src_address, 6);
  if (eth_if)
    clib_memcpy (eth->src_address, &eth_if->address, 6);

  /* Setup input and output sw_if_index for packet */
  ASSERT (vnet_buffer (b)->sw_if_index[VLIB_RX] == sw_if_index0);
  vnet_buffer (b)->sw_if_index[VLIB_TX] = sw_if_index0;
  vnet_buffer (b)->sw_if_index[VLIB_RX] =
    vnet_main.local_interface_sw_if_index;

  vlib_increment_simple_counter (
    &ip_neighbor_counters[AF_IP6].ipnc[VLIB_TX][IP_NEIGHBOR_CTR_REPLY],
    vm->thread_index, sw_if_index0, 1);
}

#endif /* included_ip6_nd_inline_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
