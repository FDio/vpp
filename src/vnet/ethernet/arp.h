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
#include <vnet/ethernet/arp_packet.h>
#include <vnet/ip/ip.h>

extern int vnet_proxy_arp_add_del (ip4_address_t * lo_addr,
				   ip4_address_t * hi_addr,
				   u32 fib_index, int is_del);

extern int vnet_arp_set_ip4_over_ethernet (vnet_main_t * vnm,
					   u32 sw_if_index,
					   const
					   ethernet_arp_ip4_over_ethernet_address_t
					   * a, int is_static,
					   int is_no_fib_entry);

extern int vnet_arp_unset_ip4_over_ethernet (vnet_main_t * vnm,
					     u32 sw_if_index,
					     const
					     ethernet_arp_ip4_over_ethernet_address_t
					     * a);

extern int vnet_proxy_arp_fib_reset (u32 fib_id);

/**
 * call back function when walking the DB of proxy ARPs
 * @return 0 to stop the walk !0 to continue
 */
typedef walk_rc_t (proxy_arp_walk_t) (const ip4_address_t * lo_addr,
				      const ip4_address_t * hi_addr,
				      u32 fib_index, void *dat);

extern void proxy_arp_walk (proxy_arp_walk_t cb, void *data);

void vnet_arp_delete_sw_interface (u32 sw_if_index);
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
