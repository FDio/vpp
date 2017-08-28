/*
 * Copyright (c) 2017 Intel and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "POD IS" BPODIS,
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

#include <vnet/util/refcount.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_table.h>
#include <vppinfra/bihash_8_8.h>

#include <kubeproxy/kphash.h>

#define KP_DEFAULT_PER_CPU_STICKY_BUCKETS 1 << 10
#define KP_DEFAULT_FLOW_TIMEOUT 40
#define KP_MAPPING_BUCKETS  1024
#define KP_MAPPING_MEMORY_SIZE  64<<20

typedef enum {
  KP_NEXT_DROP,
  KP_N_NEXT,
} kp_next_t;

typedef enum {
  KP_NAT4_IN2OUT_NEXT_DROP,
  KP_NAT4_IN2OUT_NEXT_LOOKUP,
  KP_NAT4_IN2OUT_N_NEXT,
} kp_nat4_in2out_next_t;

#define foreach_kp_nat_in2out_error                       \
_(UNSUPPORTED_PROTOCOL, "Unsupported protocol")         \
_(IN2OUT_PACKETS, "Good in2out packets processed")      \
_(NO_TRANSLATION, "No translation")

typedef enum {
#define _(sym,str) KP_NAT_IN2OUT_ERROR_##sym,
  foreach_kp_nat_in2out_error
#undef _
  KP_NAT_IN2OUT_N_ERROR,
} kp_nat_in2out_error_t;

/**
 * kube-proxy supports three types of service
 */
typedef enum {
  KP_SVR_TYPE_VIP_PORT,
  KP_SVR_TYPE_NODEIP_PORT,
  KP_SVR_TYPE_EXT_LB,
  KP_SVR_N_TYPES,
} kp_svr_type_t;

typedef enum {
  KP_NODEPORT_NEXT_IP4_NAT4,
  KP_NODEPORT_NEXT_IP4_NAT6,
  KP_NODEPORT_NEXT_IP6_NAT4,
  KP_NODEPORT_NEXT_IP6_NAT6,
  KP_NODEPORT_NEXT_DROP,
  KP_NODEPORT_N_NEXT,
} kp_nodeport_next_t;

/**
 * Each VIP is configured with a set of PODs
 */
typedef struct {
  /**
   * Registration to FIB event.
   */
  fib_node_t fib_node;

  /**
   * Destination address used to transfer traffic towards to that POD.
   * The address is also used pod ID and pseudo-random
   * seed for the load-balancing process.
   */
  ip46_address_t address;

  /**
   * PODs are indexed by address and VIP Index.
   * Which means there will be duplicated if the same server
   * address is used for multiple VIPs.
   */
  u32 vip_index;

  /**
   * Some per-POD flags.
   * For now only KP_POD_FLAGS_USED is defined.
   */
  u8 flags;

#define KP_POD_FLAGS_USED 0x1

  /**
   * Rotating timestamp of when KP_POD_FLAGS_USED flag was last set.
   *
   * POD removal is based on garbage collection and reference counting.
   * When an POD is removed, there is a race between configuration core
   * and worker cores which may still add a reference while it should not
   * be used. This timestamp is used to not remove the POD while a race condition
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

} kp_pod_t;

format_function_t format_kp_pod;

typedef struct {
  u32 pod_index;
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
   * Vector mapping (flow-hash & new_connect_table_mask) to POD index.
   * This is used for new flows.
   */
  kp_new_flow_entry_t *new_flow_table;

  /**
   * New flows table length - 1
   * (length MUST be a power of 2)
   */
  u32 new_flow_table_mask;

  /**
   * last time garbage collection was run to free the PODs.
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
   * Pool of POD indexes used for this VIP.
   * This also includes PODs that have been removed (but are still referenced).
   */
  u32 *pod_indexes;

} kp_vip_t;

/*
 * mapping from nodeport to vip_index
 */
typedef struct {

  u32 vip_index;

} kp_nodeport_t;

#define kp_vip_is_ip4(vip) ((vip)->type == KP_VIP_TYPE_IP4_NAT44 \
                            || (vip)->type == KP_VIP_TYPE_IP4_NAT46)
#define kp_vip_is_nat4(vip) ((vip)->type == KP_VIP_TYPE_IP6_NAT64 \
                            || (vip)->type == KP_VIP_TYPE_IP4_NAT44)
format_function_t format_kp_vip;
format_function_t format_kp_vip_detailed;

#define foreach_kp_nat_protocol \
  _(UDP, 0, udp, "udp")       \
  _(TCP, 1, tcp, "tcp")

typedef enum {
#define _(N, i, n, s) KP_NAT_PROTOCOL_##N = i,
  foreach_kp_nat_protocol
#undef _
} kp_nat_protocol_t;

always_inline u32
kp_ip_proto_to_nat_proto (u8 ip_proto)
{
  u32 nat_proto = ~0;

  nat_proto = (ip_proto == IP_PROTOCOL_UDP) ? KP_NAT_PROTOCOL_UDP : nat_proto;
  nat_proto = (ip_proto == IP_PROTOCOL_TCP) ? KP_NAT_PROTOCOL_TCP : nat_proto;

  return nat_proto;
}

/* Key for Pod's egress SNAT */
typedef struct {
  union
  {
    struct
    {
      ip4_address_t addr;
      u16 port;
      u16 protocol:3,
        fib_index:13;
    };
    u64 as_u64;
  };
} kp_snat4_key_t;

typedef struct
{
  ip6_address_t prefix;
  u8 plen;
  u32 vrf_id;
  u32 fib_index;
} kp_snat6_key_t;

typedef struct {
  kp_svr_type_t svr_type;
  ip46_address_t vip;
  ip46_address_t node_ip;
  ip46_address_t pod_ip;
  u8 vip_is_ipv6;
  u8 node_ip_is_ipv6;
  u8 pod_ip_is_ipv6;
  u16 port;        /* Network byte order */
  u16 node_port;   /* Network byte order */
  u16 target_port; /* Network byte order */
  u32 vrf_id;
  u32 fib_index;
} kp_snat_mapping_t;

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
   * Pool of PODs.
   * PODs are referenced by address and vip index.
   * The first element (index 0) is special and used only to fill
   * new_flow_tables when no POD has been configured.
   */
  kp_pod_t *pods;

  /**
   * Each POD has an associated reference counter.
   * As pods[0] has a special meaning, its associated counter
   * starts at 0 and is decremented instead. i.e. do not use it.
   */
  vlib_refcount_t pod_refcount;

  /* hash lookup vip_index by key: {u16: nodeport} */
  uword * nodeport_by_key;


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

  /* Find a static mapping by pod IP : target_port */
  clib_bihash_8_8_t mapping_by_pod;

  /* Static mapping pool */
  kp_snat_mapping_t * snat_mappings;

  /**
   * API dynamically registered base ID.
   */
  u16 msg_id_base;

  volatile u32 *writer_lock;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} kp_main_t;

#define ip46_address_type(ip46) (ip46_address_is_ip4(ip46)?IP46_TYPE_IP4:IP46_TYPE_IP6)
#define ip46_prefix_is_ip4(ip46, len) ((len) >= 96 && ip46_address_is_ip4(ip46))
#define ip46_prefix_type(ip46, len) (ip46_prefix_is_ip4(ip46, len)?IP46_TYPE_IP4:IP46_TYPE_IP6)

void ip46_prefix_normalize(ip46_address_t *prefix, u8 plen);
uword unformat_ip46_prefix (unformat_input_t * input, va_list * args);
u8 *format_ip46_prefix (u8 * s, va_list * args);


extern kp_main_t kp_main;
extern vlib_node_registration_t kp4_node;
extern vlib_node_registration_t kp6_node;
extern vlib_node_registration_t kp4_nodeport_node;
extern vlib_node_registration_t kp6_nodeport_node;
extern vlib_node_registration_t kp_nat4_in2out_node;

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

int kp_vip_add_pods(u32 vip_index, ip46_address_t *addresses, u32 n);
int kp_vip_del_pods(u32 vip_index, ip46_address_t *addresses, u32 n);

u32 kp_hash_time_now(vlib_main_t * vm);

void kp_garbage_collection();

int kp_nat4_interface_add_del (u32 sw_if_index, int is_del);

format_function_t format_kp_main;

#endif /* KP_PLUGIN_KP_KP_H_ */
