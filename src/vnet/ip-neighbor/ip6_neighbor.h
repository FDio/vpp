/*
 * ip/ip6_neighbor.h: IP6 NS transmit
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

#ifndef __IP6_NEIGHBOR_H__
#define __IP6_NEIGHBOR_H__

#include <vlib/vlib.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip6_link.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/adj/adj_internal.h>

/* Template used to generate IP6 neighbor solicitation packets. */
extern vlib_packet_template_t ip6_neighbor_packet_template;

extern void ip6_neighbor_advertise (vlib_main_t * vm,
				    vnet_main_t * vnm,
				    u32 sw_if_index,
				    const ip6_address_t * addr);

extern void ip6_neighbor_probe_dst (u32 sw_if_index,
				    const ip6_address_t * dst);

always_inline vlib_buffer_t *
ip6_neighbor_probe (vlib_main_t * vm,
		    vnet_main_t * vnm,
		    u32 sw_if_index,
		    const ip6_address_t * src, const ip6_address_t * dst)
{
  icmp6_neighbor_solicitation_header_t *h0;
  vnet_hw_interface_t *hw_if0;
  const ip_adjacency_t *adj;
  vlib_buffer_t *b0;
  int bogus_length;
  u32 bi0 = 0;

  h0 = vlib_packet_template_get_packet
    (vm, &ip6_neighbor_packet_template, &bi0);
  if (!h0)
    return NULL;

  /* if the interface has been disabled for ip6, later steps to retrieve
   * an adjacency will result in a segv.
   */
  if (!ip6_link_is_enabled (sw_if_index))
    return NULL;

  b0 = vlib_get_buffer (vm, bi0);

  hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index);

  /*
   * Destination address is a solicited node multicast address.
   * We need to fill in
   * the low 24 bits with low 24 bits of target's address.
   */
  h0->ip.src_address = *src;
  h0->ip.dst_address.as_u8[13] = dst->as_u8[13];
  h0->ip.dst_address.as_u8[14] = dst->as_u8[14];
  h0->ip.dst_address.as_u8[15] = dst->as_u8[15];

  h0->neighbor.target_address = *dst;

  clib_memcpy (h0->link_layer_option.ethernet_address,
	       hw_if0->hw_address, vec_len (hw_if0->hw_address));

  /* $$$$ appears we need this; why is the checksum non-zero? */
  h0->neighbor.icmp.checksum = 0;
  h0->neighbor.icmp.checksum =
    ip6_tcp_udp_icmp_compute_checksum (vm, 0, &h0->ip, &bogus_length);

  ASSERT (bogus_length == 0);
  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);

  vnet_buffer (b0)->sw_if_index[VLIB_TX] = sw_if_index;

  /* Use the link's mcast adj to ship the packet */
  vnet_buffer (b0)->ip.adj_index[VLIB_TX] =
    ip6_link_get_mcast_adj (sw_if_index);
  adj = adj_get (vnet_buffer (b0)->ip.adj_index[VLIB_TX]);

  b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;

  {
    vlib_frame_t *f = vlib_get_frame_to_node (vm, adj->ia_node_index);
    u32 *to_next = vlib_frame_vector_args (f);
    to_next[0] = bi0;
    f->n_vectors = 1;
    vlib_put_frame_to_node (vm, adj->ia_node_index, f);
  }

  return b0;
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
