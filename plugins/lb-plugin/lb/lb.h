/*
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

/**
 * lb-plugin implements a MagLev-like load balancer.
 * http://research.google.com/pubs/pub44824.html
 *
 * It hasn't been tested for interoperability with the original MagLev
 * but intends to provide similar functionality.
 * The load-balancer receives traffic destined to VIP (Virtual IP)
 * addresses from one or multiple(ECMP) routers.
 * The load-balancer tunnels the traffic toward many application servers
 * ensuring session stickyness (i.e. that a single sessions is tunneled
 * towards a single application server).
 *
 */

#ifndef LB_PLUGIN_LB_LB_H_
#define LB_PLUGIN_LB_LB_H_

#include <lb/util.h>
#include <lb/refcount.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

#include <lb/lbhash.h>

#define LB_STICKY_BUCKETS 1 << 10
#define LB_STICKY_TIMEOUT 40

/**
 * Each VIP is configured with a set of
 * application server.
 */
typedef struct {
  /**
   * Destination address used to tunnel traffic towards
   * that application server.
   * The address is also used as ID and pseudo-random
   * seed for the load-balancing process.
   */
  ip46_address_t address;
} lb_as_t;

typedef struct {
  u32 as_index;
} lb_new_flow_entry_t;


/**
 * Load balancing service is provided per VIP.
 * In this data model, a VIP can be a whole prefix.
 */
typedef struct {

  //Runtime

  /**
   * Vector mapping (flow-hash & new_connect_table_mask) to AS index.
   * This is used for new flows.
   */
  lb_new_flow_entry_t *new_flow_table;

  /**
   * New flows table length - 1
   * (length MUST be a power of 2)
   */
  u32 new_flow_table_mask;

  /**
   * Pool of bindings with associated VIPs.
   */
  lb_as_t *ass;

  /**
   * Ass reference counters
   */
  vlib_refcount_t as_refcount;

  //Not runtime

  /**
   * A Virtual IP represents a given service delivered
   * by a set of application servers. It can be a single
   * address or a prefix.
   * IPv4 prefixes are encoded using IPv4-in-IPv6 embedded address
   * (i.e. ::/96 prefix).
   */
  ip46_address_t prefix;

  /**
   * The VIP prefix length.
   * In case of IPv4, plen = 96 + ip4_plen.
   */
  u8 plen;

} lb_vip_t;

#define lb_vip_is_ip4(vip) ip46_prefix_is_ip4(&(vip)->prefix, (vip)->plen)
format_function_t format_lb_vip;
format_function_t format_lb_vip_detailed;

typedef struct {
  /**
   * Pool of all Virtual IPs
   */
  lb_vip_t *vips;

  /**
   * Each CPU has its own sticky flow hash table.
   * One single table is used for all VIPs.
   */
  lb_hash_t **per_cpu_sticky_ht;

  /**
   * next index for ip6-lookup node.
   * This is used in lookup adjacency created for the IPv6 VIPs.
   */
  u32 ip6_lookup_next_index;

  /**
   * next index for ip4-lookup node.
   * This is used in lookup adjacency created for the IPv4 VIPs.
   */
  u32 ip4_lookup_next_index;

  /**
   * Source address used in IPv6 encapsulated traffic
   */
  ip6_address_t ip6_src_address;

  /**
   * Source address used for IPv4 encapsulated traffic
   */
  ip4_address_t ip4_src_address;
} lb_main_t;

/**
 * struct stored in adj->opaque data.
 */
typedef struct {
  /**
   * Index of the VIP associated with that IP adjacency.
   */
  u32 vip_index;
} lb_adj_data_t;

extern lb_main_t lb_main;
extern vlib_node_registration_t lb6_node;
extern vlib_node_registration_t lb4_node;

enum {
  VNET_LB_ERR_NONE = 0,
  VNET_LB_ERR_EXISTS = -1,
  VNET_LB_ERR_MEMORY = -2,
  VNET_LB_ERR_INVALID_SIZE = -3,
  VNET_LB_ERR_NOT_FOUND = -4,
  VNET_LB_ERR_ADDRESS_TYPE = -5,
};

/**
 * Fix global load-balancer parameters.
 * @param ip4_address IPv4 source address used for encapsulated traffic
 * @param ip6_address IPv6 source address used for encapsulated traffic
 * @return 0 on success. VNET_LB_ERR_XXX on error
 */
int lb_conf(ip4_address_t *ip4_address, ip6_address_t *ip6_address);

int lb_vip_add(ip46_address_t *prefix, u8 plen,
               u32 new_length, u32 *vip_index);
int lb_vip_del(u32 vip_index);

int lb_vip_find_index(ip46_address_t *prefix, u8 plen, u32 *vip_index);

#define lb_vip_get_by_index(index) (pool_is_free_index(lb_main.vips, index)?NULL:pool_elt_at_index(lb_main.vips, index))

int lb_vip_add_ass(u32 vip_index, ip46_address_t *addresses, u32 n);
int lb_vip_del_ass(u32 vip_index, ip46_address_t *addresses, u32 n);

#endif /* LB_PLUGIN_LB_LB_H_ */
