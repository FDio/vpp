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
#include <vnet/arp/arp.api_enum.h>

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
