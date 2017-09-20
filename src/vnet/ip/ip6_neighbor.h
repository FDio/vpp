/*
 *
 * ip6_neighboor.h: ip6 neighbor structures
 *
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

#ifndef included_ip6_neighbor_h
#define included_ip6_neighbor_h

#include <vnet/fib/fib_types.h>

typedef struct
{
  ip6_address_t ip6_address;
  u32 sw_if_index;
  u32 pad;
} ip6_neighbor_key_t;

typedef enum ip6_neighbor_flags_t_
{
  IP6_NEIGHBOR_FLAG_STATIC = (1 << 0),
  IP6_NEIGHBOR_FLAG_DYNAMIC = (1 << 1),
  IP6_NEIGHBOR_FLAG_NO_FIB_ENTRY = (1 << 2),
} __attribute__ ((packed)) ip6_neighbor_flags_t;

typedef struct
{
  ip6_neighbor_key_t key;
  u8 link_layer_address[8];
  ip6_neighbor_flags_t flags;
  u64 cpu_time_last_updated;
  fib_node_index_t fib_entry_index;
} ip6_neighbor_t;

extern ip6_neighbor_t *ip6_neighbors_entries (u32 sw_if_index);

extern int ip6_neighbor_ra_config (vlib_main_t * vm, u32 sw_if_index,
				   u8 suppress, u8 managed, u8 other,
				   u8 ll_option, u8 send_unicast, u8 cease,
				   u8 use_lifetime, u32 lifetime,
				   u32 initial_count, u32 initial_interval,
				   u32 max_interval, u32 min_interval,
				   u8 is_no);

extern int ip6_neighbor_ra_prefix (vlib_main_t * vm, u32 sw_if_index,
				   ip6_address_t * prefix_addr, u8 prefix_len,
				   u8 use_default, u32 val_lifetime,
				   u32 pref_lifetime, u8 no_advertise,
				   u8 off_link, u8 no_autoconfig,
				   u8 no_onlink, u8 is_no);

extern clib_error_t *ip6_set_neighbor_limit (u32 neighbor_limit);

extern void vnet_register_ip6_neighbor_resolution_event (vnet_main_t * vnm,
							 void *address_arg,
							 uword node_index,
							 uword type_opaque,
							 uword data);

extern int vnet_set_ip6_ethernet_neighbor (vlib_main_t * vm,
					   u32 sw_if_index,
					   ip6_address_t * a,
					   u8 * link_layer_address,
					   uword n_bytes_link_layer_address,
					   int is_static,
					   int is_no_fib_entry);

extern int vnet_unset_ip6_ethernet_neighbor (vlib_main_t * vm,
					     u32 sw_if_index,
					     ip6_address_t * a,
					     u8 * link_layer_address,
					     uword
					     n_bytes_link_layer_address);

extern int ip6_neighbor_proxy_add_del (u32 sw_if_index,
				       ip6_address_t * addr, u8 is_add);

u32 ip6_neighbor_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index,
				       u32 is_add);
typedef struct
{
  u32 sw_if_index;
  ip6_address_t ip6;
  u8 mac[6];
} wc_nd_report_t;

void wc_nd_set_publisher_node (uword node_index, uword event_type);

#endif /* included_ip6_neighbor_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
