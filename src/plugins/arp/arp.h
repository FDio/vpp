/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef __ARP_H__
#define __ARP_H__

#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/arp_packet.h>

#define foreach_ethernet_arp_error					\
  _ (replies_sent, "ARP replies sent")					\
  _ (l2_type_not_ethernet, "L2 type not ethernet")			\
  _ (l3_type_not_ip4, "L3 type not IP4")				\
  _ (l3_src_address_not_local, "IP4 source address not local to subnet") \
  _ (l3_dst_address_not_local, "IP4 destination address not local to subnet") \
  _ (l3_dst_address_unset, "IP4 destination address is unset")          \
  _ (l3_src_address_is_local, "IP4 source address matches local interface") \
  _ (l3_src_address_learned, "ARP request IP4 source address learned")  \
  _ (replies_received, "ARP replies received")				\
  _ (opcode_not_request, "ARP opcode not request")                      \
  _ (proxy_arp_replies_sent, "Proxy ARP replies sent")			\
  _ (l2_address_mismatch, "ARP hw addr does not match L2 frame src addr") \
  _ (gratuitous_arp, "ARP probe or announcement dropped") \
  _ (interface_no_table, "Interface is not mapped to an IP table") \
  _ (interface_not_ip_enabled, "Interface is not IP enabled") \
  _ (unnumbered_mismatch, "RX interface is unnumbered to different subnet") \

typedef enum
{
#define _(sym,string) ETHERNET_ARP_ERROR_##sym,
  foreach_ethernet_arp_error
#undef _
    ETHERNET_ARP_N_ERROR,
} ethernet_arp_reply_error_t;

extern int arp_proxy_add (u32 fib_index,
			  const ip4_address_t * lo_addr,
			  const ip4_address_t * hi_addr);
extern int arp_proxy_del (u32 fib_index,
			  const ip4_address_t * lo_addr,
			  const ip4_address_t * hi_addr);

extern int arp_proxy_enable (u32 sw_if_index);
extern int arp_proxy_disable (u32 sw_if_index);

/**
 * call back function when walking the DB of proxy ARPs
 * @return 0 to stop the walk !0 to continue
 */
typedef walk_rc_t (proxy_arp_walk_t) (const ip4_address_t * lo_addr,
				      const ip4_address_t * hi_addr,
				      u32 fib_index, void *dat);

extern void proxy_arp_walk (proxy_arp_walk_t cb, void *data);

/**
 * call back function when walking the DB of proxy ARP interface
 * @return 0 to stop the walk !0 to continue
 */
typedef walk_rc_t (proxy_arp_intf_walk_t) (u32 sw_if_index, void *data);

extern void proxy_arp_intfc_walk (proxy_arp_intf_walk_t cb, void *data);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
