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
#include <vnet/ip/ip_neighbor.h>

typedef struct
{
  u32 sw_if_index;
  ip4_address_t ip4_address;

  mac_address_t mac;

  ip_neighbor_flags_t flags;

  f64 time_last_updated;

  /**
   * The index of the adj-fib entry created
   */
  fib_node_index_t fib_entry_index;
} ethernet_arp_ip4_entry_t;

extern u8 *format_ethernet_arp_ip4_entry (u8 * s, va_list * va);

ethernet_arp_ip4_entry_t *ip4_neighbors_pool (void);
ethernet_arp_ip4_entry_t *ip4_neighbor_entries (u32 sw_if_index);

extern int vnet_proxy_arp_add_del (ip4_address_t * lo_addr,
				   ip4_address_t * hi_addr,
				   u32 fib_index, int is_del);

extern int vnet_arp_set_ip4_over_ethernet (vnet_main_t * vnm,
					   u32 sw_if_index,
					   const
					   ethernet_arp_ip4_over_ethernet_address_t
					   * a, ip_neighbor_flags_t flags);

extern int vnet_arp_unset_ip4_over_ethernet (vnet_main_t * vnm,
					     u32 sw_if_index,
					     const
					     ethernet_arp_ip4_over_ethernet_address_t
					     * a);

extern int vnet_proxy_arp_fib_reset (u32 fib_id);

void vnet_register_ip4_arp_resolution_event (vnet_main_t * vnm,
					     void *address_arg,
					     uword node_index,
					     uword type_opaque, uword data);

typedef int (*arp_change_event_cb_t) (u32 pool_index,
				      const mac_address_t * mac,
				      u32 sw_if_index,
				      const ip4_address_t * address);

int vnet_add_del_ip4_arp_change_event (vnet_main_t * vnm,
				       arp_change_event_cb_t data_callback,
				       u32 pid,
				       void *address_arg,
				       uword node_index,
				       uword type_opaque,
				       uword data, int is_add);

void wc_arp_set_publisher_node (uword inode_index, uword event_type);

void ethernet_arp_change_mac (u32 sw_if_index);
void ethernet_ndp_change_mac (u32 sw_if_index);

void arp_update_adjacency (vnet_main_t * vnm, u32 sw_if_index, u32 ai);

typedef struct
{
  u32 sw_if_index;
  u32 ip4;
  mac_address_t mac;
} wc_arp_report_t;

/**
 * call back function when walking the DB of proxy ARPs
 * @return 0 to stop the walk !0 to continue
 */
typedef walk_rc_t (proxy_arp_walk_t) (const ip4_address_t * lo_addr,
				      const ip4_address_t * hi_addr,
				      u32 fib_index, void *dat);

extern void proxy_arp_walk (proxy_arp_walk_t cb, void *data);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
