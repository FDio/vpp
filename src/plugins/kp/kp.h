/*
 * Copyright (c) 2016 Intel and/or its affiliates.
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
 * kp-plugin implements a MagLev-like load balancer.
 * http://research.google.com/pubs/pub44824.html
 *
 * It hasn't been tested for interoperability with the original MagLev
 * but intends to provide similar functionality.
 * The kube-proxy receives traffic destined to VIP (Virtual IP)
 * addresses from one or multiple(ECMP) routers.
 * The kube-proxy tunnels the traffic toward many application servers
 * ensuring session stickyness (i.e. that a single sessions is tunneled
 * towards a single application server).
 *
 */

#ifndef KP_PLUGIN_KP_KP_H_
#define KP_PLUGIN_KP_KP_H_

#include <kp/kp_util.h>
#include <kp/kp_refcount.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_table.h>

#include <kp/kphash.h>

#define KP_DEFAULT_PER_CPU_STICKY_BUCKETS 1 << 10
#define KP_DEFAULT_FLOW_TIMEOUT 40

typedef enum {
  KP_NEXT_DROP,
  KP_N_NEXT,
} kp_next_t;

/**
 * Each VIP is configured with a set of PODs
 */
typedef struct {
  /**
   * Registration to FIB event.
   */
  fib_node_t fib_node;

  /**
   * Destination address used to tunnel traffic towards to that POD.
   * The address is also used as ID and pseudo-random
   * seed for the load-balancing process.
   */
  ip46_address_t address;

  /**
   * ASs are indexed by address and VIP Index.
   * Which means there will be duplicated if the same server
   * address is used for multiple VIPs.
   */
  u32 vip_index;

  /**
   * Some per-AS flags.
   * For now only KP_AS_FLAGS_USED is defined.
   */
  u8 flags;

#define KP_AS_FLAGS_USED 0x1

  /**
   * Rotating timestamp of when KP_AS_FLAGS_USED flag was last set.
   *
   * AS removal is based on garbage collection and reference counting.
   * When an AS is removed, there is a race between configuration core
   * and worker cores which may still add a reference while it should not
   * be used. This timestamp is used to not remove the AS while a race condition
   * may happen.
   */
  u32 last_used;

  /**
   * The FIB entry index for the next-hop
   */
  fib_node_index_t next_hop_fib_entry_index;

  /**
   * The child index on the FIB entry
   */
  u32 next_hop_child_index;

  /**
   * The next DPO in the graph to follow.
   */
  dpo_id_t dpo;

} kp_as_t;

format_function_t format_kp_as;

typedef struct {
  u32 as_index;
} kp_new_flow_entry_t;

#define kp_foreach_vip_counter \
 _(NEXT_PACKET, "packet from existing sessions", 0) \
 _(FIRST_PACKET, "first session packet", 1) \
 _(UNTRACKED_PACKET, "untracked packet", 2) \
 _(NO_SERVER, "no server configured", 3)

typedef enum {
#define _(a,b,c) KP_VIP_COUNTER_##a = c,
  kp_foreach_vip_counter
#undef _
  KP_N_VIP_COUNTERS
} kp_vip_counter_t;

/**
 * kube-proxy supports IPv4 and IPv6 traffic
 * and NAT4 and NAT6.
 */
typedef enum {
  KP_VIP_TYPE_IP4_NAT44,
  KP_VIP_TYPE_IP4_NAT46,
  KP_VIP_TYPE_IP6_NAT64,
  KP_VIP_TYPE_IP6_NAT66,
  KP_VIP_N_TYPES,
} kp_vip_type_t;

format_function_t format_kp_vip_type;
unformat_function_t unformat_kp_vip_type;

/**
 * Load balancing service is provided per VIP.
 * In this data model, a VIP can be a whole prefix.
 * But load balancing only
 * occurs on a per-source-address/port basis. Meaning that if a given source
 * reuses the same port for multiple destinations within the same VIP,
 * they will be considered as a single flow.
 */
typedef struct {

  //Runtime

  /**
   * Vector mapping (flow-hash & new_connect_table_mask) to AS index.
   * This is used for new flows.
   */
  kp_new_flow_entry_t *new_flow_table;

  /**
   * New flows table length - 1
   * (length MUST be a power of 2)
   */
  u32 new_flow_table_mask;

  /**
   * Last time garbage collection was run to free the ASs.
   */
  u32 last_garbage_collection;

  //Not runtime

  /**
   * A Virtual IP represents a given service delivered
   * by a set of PODs. It can be a single
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

  /**
   * Service port. network byte order
   */
  u16 port;

  /**
   * Pod's port corresponding to specific service. network byte order
   */
  u16 target_port;

  /**
   * Node's port, can access service via NodeIP:node_port. network byte order
   */
  u16 node_port;


  /**
   * The type of traffic for this.
   * KP_TYPE_UNDEFINED if unknown.
   */
  kp_vip_type_t type;

  /**
   * Flags related to this VIP.
   * KP_VIP_FLAGS_USED means the VIP is active.
   * When it is not set, the VIP in the process of being removed.
   * We cannot immediately remove a VIP because the VIP index still may be stored
   * in the adjacency index.
   */
  u8 flags;
#define KP_VIP_FLAGS_USED 0x1

  /**
   * Pool of AS indexes used for this VIP.
   * This also includes ASs that have been removed (but are still referenced).
   */
  u32 *as_indexes;
} kp_vip_t;

#define kp_vip_is_ip4(vip) ((vip)->type == KP_VIP_TYPE_IP4_NAT44 || (vip)->type == KP_VIP_TYPE_IP4_NAT46)
#define kp_vip_is_nat4(vip) ((vip)->type == KP_VIP_TYPE_IP6_NAT64 || (vip)->type == KP_VIP_TYPE_IP4_NAT44)
format_function_t format_kp_vip;
format_function_t format_kp_vip_detailed;

typedef struct {
  /**
   * Each CPU has its own sticky flow hash table.
   * One single table is used for all VIPs.
   */
  kp_hash_t *sticky_ht;
} kp_per_cpu_t;

typedef struct {
  /**
   * Pool of all Virtual IPs
   */
  kp_vip_t *vips;

  /**
   * Pool of ASs.
   * ASs are referenced by address and vip index.
   * The first element (index 0) is special and used only to fill
   * new_flow_tables when no AS has been configured.
   */
  kp_as_t *ass;

  /**
   * Each AS has an associated reference counter.
   * As ass[0] has a special meaning, its associated counter
   * starts at 0 and is decremented instead. i.e. do not use it.
   */
  vlib_refcount_t as_refcount;

  /**
   * Some global data is per-cpu
   */
  kp_per_cpu_t *per_cpu;

  /**
   * Node next index for IP adjacencies, for each of the traffic types.
   */
  u32 ip_lookup_next_index[KP_VIP_N_TYPES];

  /**
   * Number of buckets in the per-cpu sticky hash table.
   */
  u32 per_cpu_sticky_buckets;

  /**
   * Flow timeout in seconds.
   */
  u32 flow_timeout;

  /**
   * Per VIP counter
   */
  vlib_simple_counter_main_t vip_counters[KP_N_VIP_COUNTERS];

  /**
   * DPO used to send packet from IP4/6 lookup to KP node.
   */
  dpo_type_t dpo_nat4_type;
  dpo_type_t dpo_nat6_type;

  /**
   * Node type for registering to fib changes.
   */
  fib_node_type_t fib_node_type;

  /**
   * API dynamically registered base ID.
   */
  u16 msg_id_base;

  volatile u32 *writer_lock;
} kp_main_t;

extern kp_main_t kp_main;
extern vlib_node_registration_t kp6_node;
extern vlib_node_registration_t kp4_node;

/**
 * Fix global kube-proxy parameters.
 * @return 0 on success. VNET_KP_ERR_XXX on error
 */
int kp_conf(u32 sticky_buckets, u32 flow_timeout);

int kp_vip_add(ip46_address_t *prefix, u8 plen, kp_vip_type_t type,
	       u32 new_length, u32 *vip_index,
	       u16 port, u16 target_port, u16 node_port);
int kp_vip_del(u32 vip_index);

int kp_vip_find_index(ip46_address_t *prefix, u8 plen, u32 *vip_index);

#define kp_vip_get_by_index(index) (pool_is_free_index(kp_main.vips, index)?NULL:pool_elt_at_index(kp_main.vips, index))

int kp_vip_add_ass(u32 vip_index, ip46_address_t *addresses, u32 n);
int kp_vip_del_ass(u32 vip_index, ip46_address_t *addresses, u32 n);

u32 kp_hash_time_now(vlib_main_t * vm);

void kp_garbage_collection();

format_function_t format_kp_main;

#endif /* KP_PLUGIN_KP_KP_H_ */
