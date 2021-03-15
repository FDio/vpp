/*
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

#ifndef __IP4_NEIGHBOR_H__
#define __IP4_NEIGHBOR_H__

#include <vnet/ip/ip.h>
#include <vnet/ethernet/arp_packet.h>

extern void ip4_neighbor_probe_dst (u32 sw_if_index,
				    const ip4_address_t * dst);
extern void ip4_neighbor_advertise (vlib_main_t * vm,
				    vnet_main_t * vnm,
				    u32 sw_if_index,
				    const ip4_address_t * addr);

always_inline vlib_buffer_t *
ip4_neighbor_probe (vlib_main_t * vm,
		    vnet_main_t * vnm,
		    const ip_adjacency_t * adj0,
		    const ip4_address_t * src, const ip4_address_t * dst)
{
  vnet_hw_interface_t *hw_if0;
  ethernet_arp_header_t *h0;
  vlib_buffer_t *b0;
  u32 bi0;

  hw_if0 = vnet_get_sup_hw_interface (vnm, adj0->rewrite_header.sw_if_index);

  /* if (NULL == hw_if0->hw_address) */
  /*   return (NULL); */

  /* Send ARP request. */
  h0 = vlib_packet_template_get_packet (vm,
					&ip4_main.ip4_arp_request_packet_template,
					&bi0);
  /* Seems we're out of buffers */
  if (PREDICT_FALSE (!h0))
    return (NULL);

  b0 = vlib_get_buffer (vm, bi0);

  /* Add rewrite/encap string for ARP packet. */
  vnet_rewrite_one_header (adj0[0], h0, sizeof (ethernet_header_t));

  /* Src ethernet address in ARP header. */
  mac_address_from_bytes (&h0->ip4_over_ethernet[0].mac, hw_if0->hw_address);

  h0->ip4_over_ethernet[0].ip4 = *src;
  h0->ip4_over_ethernet[1].ip4 = *dst;

  VLIB_BUFFER_TRACE_TRAJECTORY_INIT (b0);
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = adj0->rewrite_header.sw_if_index;

  vlib_buffer_advance (b0, -adj0->rewrite_header.data_bytes);

  {
    vlib_frame_t *f = vlib_get_frame_to_node (vm, hw_if0->output_node_index);
    u32 *to_next = vlib_frame_vector_args (f);
    to_next[0] = bi0;
    f->n_vectors = 1;
    vlib_put_frame_to_node (vm, hw_if0->output_node_index, f);
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
