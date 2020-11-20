/*
 * ip_neighboor.h: ip neighbor generic services
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __INCLUDE_IP_NEIGHBOR_H__
#define __INCLUDE_IP_NEIGHBOR_H__

#include <vnet/ip-neighbor/ip_neighbor_types.h>

#include <vnet/adj/adj.h>


/*****
 * APIs external modules can invoke on the neighbor subsystem
 */

extern ip_neighbor_t *ip_neighbor_get (index_t ipni);
extern int ip_neighbor_add (const ip46_address_t * ip,
			    ip46_type_t type,
			    const mac_address_t * mac,
			    u32 sw_if_index,
			    ip_neighbor_flags_t flags, u32 * stats_index);
extern int ip_neighbor_del (const ip46_address_t * ip,
			    ip46_type_t type, u32 sw_if_index);

extern int ip_neighbor_config (ip46_type_t type, u32 limit, u32 age,
			       bool recycle);

extern void ip_neighbor_del_all (ip46_type_t type, u32 sw_if_index);

typedef walk_rc_t (*ip_neighbor_walk_cb_t) (index_t ipni, void *ctx);
extern void ip_neighbor_walk (ip46_type_t type,
			      u32 sw_if_index,
			      ip_neighbor_walk_cb_t fn, void *ctx);

extern const ip46_address_t *ip_neighbor_get_ip (const ip_neighbor_t * ipn);
extern const mac_address_t *ip_neighbor_get_mac (const ip_neighbor_t * ipn);
extern const u32 ip_neighbor_get_sw_if_index (const ip_neighbor_t * ipn);

extern void ip_neighbor_learn (const ip_neighbor_learn_t * l);

extern void ip_neighbor_update (vnet_main_t * vnm, adj_index_t ai);

extern void ip_neighbor_advertise (vlib_main_t * vm,
				   ip46_type_t tyoe,
				   const ip46_address_t * addr,
				   u32 sw_if_index);
extern void ip_neighbor_probe (const ip_adjacency_t * adj);
extern void ip_neighbor_probe_dst (const ip_adjacency_t * adj,
				   const ip46_address_t * ip);

extern void ip_neighbor_mark (ip46_type_t type);
extern void ip_neighbor_sweep (ip46_type_t type);

/**
 * From the watcher to the API to publish a new neighbor
 */
extern void ip_neighbor_handle_event (ip_neighbor_event_t * ipne);

/**
 * The set of function that vnet requires from the IP neighbour module.
 * Note that an implementation of these functions will not exist
 * if the ip-neighbour plugin is not loaded. so check the error codes!
 */
extern int ip4_neighbor_proxy_add (u32 fib_index,
				   const ip4_address_t * start,
				   const ip4_address_t * end);
extern int ip4_neighbor_proxy_delete (u32 fib_index,
				      const ip4_address_t * start,
				      const ip4_address_t * end);
extern int ip4_neighbor_proxy_enable (u32 sw_if_index);
extern int ip4_neighbor_proxy_disable (u32 sw_if_index);
extern int ip6_neighbor_proxy_add (u32 sw_if_index,
				   const ip6_address_t * addr);
extern int ip6_neighbor_proxy_del (u32 sw_if_index,
				   const ip6_address_t * addr);

/**
 * neighbor protocol implementation registration functions
 *  this are provided by ARP and IP-ND
 */
typedef int (*ip4_neighbor_proxy_addr_t) (u32 fib_index,
					  const ip4_address_t * start,
					  const ip4_address_t * end);
typedef int (*ip4_neighbor_proxy_cfg_t) (u32 sw_if_index);
typedef int (*ip6_neighbor_proxy_cfg_t) (u32 sw_if_index,
					 const ip6_address_t * addr);

/**
 * Virtual function Table for neighbor protocol implementations to register
 */
typedef struct ip_neighbor_vft_t_
{
  ip4_neighbor_proxy_cfg_t inv_proxy4_enable;
  ip4_neighbor_proxy_cfg_t inv_proxy4_disable;
  ip4_neighbor_proxy_addr_t inv_proxy4_add;
  ip4_neighbor_proxy_addr_t inv_proxy4_del;
  ip6_neighbor_proxy_cfg_t inv_proxy6_add;
  ip6_neighbor_proxy_cfg_t inv_proxy6_del;
} ip_neighbor_vft_t;

extern void ip_neighbor_register (ip46_type_t type,
				  const ip_neighbor_vft_t * vft);


#endif /* __INCLUDE_IP_NEIGHBOR_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
