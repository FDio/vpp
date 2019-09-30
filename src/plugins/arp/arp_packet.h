/*
 * ethernet/arp.c: IP v4 ARP node
 *
 * Copyright (c) 2010 Cisco and/or its affiliates.
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

#ifndef __ARP_PACKET_H__
#define __ARP_PACKET_H__

#include <plugins/arp/arp.h>

/* Either we drop the packet or we send a reply to the sender. */
typedef enum
{
  ARP_REPLY_NEXT_DROP,
  ARP_REPLY_NEXT_REPLY_TX,
  ARP_REPLY_N_NEXT,
} arp_reply_next_t;

static_always_inline u32
arp_mk_reply (vnet_main_t * vnm,
	      vlib_buffer_t * p0,
	      u32 sw_if_index0,
	      const ip4_address_t * if_addr0,
	      ethernet_arp_header_t * arp0, ethernet_header_t * eth_rx)
{
  vnet_hw_interface_t *hw_if0;
  u8 *rewrite0, rewrite0_len;
  ethernet_header_t *eth_tx;
  u32 next0;

  /* Send a reply.
     An adjacency to the sender is not always present,
     so we use the interface to build us a rewrite string
     which will contain all the necessary tags. */
  rewrite0 = ethernet_build_rewrite (vnm, sw_if_index0,
				     VNET_LINK_ARP, eth_rx->src_address);
  rewrite0_len = vec_len (rewrite0);

  /* Figure out how much to rewind current data from adjacency. */
  vlib_buffer_advance (p0, -rewrite0_len);
  eth_tx = vlib_buffer_get_current (p0);

  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;
  hw_if0 = vnet_get_sup_hw_interface (vnm, sw_if_index0);

  /* Send reply back through input interface */
  vnet_buffer (p0)->sw_if_index[VLIB_TX] = sw_if_index0;
  next0 = ARP_REPLY_NEXT_REPLY_TX;

  arp0->opcode = clib_host_to_net_u16 (ETHERNET_ARP_OPCODE_reply);

  arp0->ip4_over_ethernet[1] = arp0->ip4_over_ethernet[0];

  mac_address_from_bytes (&arp0->ip4_over_ethernet[0].mac,
			  hw_if0->hw_address);
  clib_mem_unaligned (&arp0->ip4_over_ethernet[0].ip4.data_u32, u32) =
    if_addr0->data_u32;

  /* Hardware must be ethernet-like. */
  ASSERT (vec_len (hw_if0->hw_address) == 6);

  /* the rx nd tx ethernet headers wil overlap in the case
   * when we received a tagged VLAN=0 packet, but we are sending
   * back untagged */
  clib_memcpy_fast (eth_tx, rewrite0, vec_len (rewrite0));
  vec_free (rewrite0);

  return (next0);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
