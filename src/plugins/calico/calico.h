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
 * calico-plugin implements a MagLev-like load balancer.
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

#ifndef CALICO_PLUGIN_CALICO_CALICO_H_
#define CALICO_PLUGIN_CALICO_CALICO_H_

#include <calico/util.h>
#include <vnet/util/refcount.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_table.h>
#include <vppinfra/hash.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_40_8.h>
#include <calico/calicohash.h>
#include <vppinfra/lock.h>

#define CALICO_DEFAULT_PER_CPU_STICKY_BUCKETS 1 << 10
#define CALICO_DEFAULT_FLOW_TIMEOUT 40
#define CALICO_MAPPING_BUCKETS  1024
#define CALICO_MAPPING_MEMORY_SIZE  64<<20

#define CALICO_VIP_PER_PORT_BUCKETS  1024
#define CALICO_VIP_PER_PORT_MEMORY_SIZE  64<<20
/* ms expiration of NAT 5tuple entries */
#define CALICO_NAT_TIMEOUT 60000

typedef enum {
  CALICO_NEXT_DROP,
  CALICO_N_NEXT,
} calico_next_t;

typedef enum {
  CALICO_NAT4_IN2OUT_NEXT_DROP,
  CALICO_NAT4_IN2OUT_NEXT_LOOKUP,
  CALICO_NAT4_IN2OUT_N_NEXT,
} CALICO_nat4_in2out_next_t;

typedef enum {
  CALICO_NAT6_IN2OUT_NEXT_DROP,
  CALICO_NAT6_IN2OUT_NEXT_LOOKUP,
  CALICO_NAT6_IN2OUT_NEXT_SNAT6,
  CALICO_NAT6_IN2OUT_N_NEXT,
} CALICO_nat6_in2out_next_t;

typedef enum {
  CALICO_SNAT6_NEXT_DROP,
  CALICO_SNAT6_NEXT_OUTPUT,
  CALICO_SNAT6_N_NEXT,
} CALICO_snat6_next_t;

#define foreach_calico_nat_in2out_error                       \
_(UNSUPPORTED_PROTOCOL, "Unsupported protocol")         \
_(IN2OUT_PACKETS, "Good in2out packets processed")      \
_(NO_TRANSLATION, "No translation")

typedef enum {
#define _(sym,str) CALICO_NAT_IN2OUT_ERROR_##sym,
  foreach_calico_nat_in2out_error
#undef _
  CALICO_NAT_IN2OUT_N_ERROR,
} calico_nat_in2out_error_t;

/**
 * Each VIP is configured with a set of
 * application server.
 */
typedef struct {
  /**
   * Registration to FIB event.
   */
  fib_node_t fib_node;

  /**
   * Destination address used to tunnel traffic towards
   * that application server.
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
   * For now only CALICO_AS_FLAGS_USED is defined.
   */
  u8 flags;

#define CALICO_AS_FLAGS_USED 0x1

  /**
   * Rotating timestamp of when CALICO_AS_FLAGS_USED flag was last set.
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

} calico_as_t;

format_function_t format_calico_as;

typedef struct {
  u32 as_index;
} calico_new_flow_entry_t;

#define calico_foreach_vip_counter \
 _(NEXT_PACKET, "packet from existing sessions", 0) \
 _(FIRST_PACKET, "first session packet", 1) \
 _(UNTRACKED_PACKET, "untracked packet", 2) \
 _(NO_SERVER, "no server configured", 3)

typedef enum {
#define _(a,b,c) CALICO_VIP_COUNTER_##a = c,
  calico_foreach_vip_counter
#undef _
  CALICO_N_VIP_COUNTERS
} calico_vip_counter_t;

typedef enum {
  CALICO_ENCAP_TYPE_NAT4,
  CALICO_ENCAP_TYPE_NAT6,
  CALICO_ENCAP_N_TYPES,
} calico_encap_type_t;

/**
 * Lookup type
 */

typedef enum {
  CALICO_LKP_SAME_IP_PORT,
  CALICO_LKP_DIFF_IP_PORT,
  CALICO_LKP_ALL_PORT_IP,
  CALICO_LKP_N_TYPES,
} calico_lkp_type_t;

/**
 * The load balancer supports IPv4 and IPv6 traffic
 * and GRE4, GRE6, L3DSR and NAT4, NAT6 encap.
 */
typedef enum {
  CALICO_VIP_TYPE_IP4_NAT4,
  CALICO_VIP_TYPE_IP6_NAT6,
  CALICO_VIP_N_TYPES,
} calico_vip_type_t;

format_function_t format_calico_vip_type;
unformat_function_t unformat_calico_vip_type;

typedef struct {
  /* all fields in NET byte order */
  union {
    struct {
      u32 vip_prefix_index;
      u16 port;
      u8  protocol;
      u8 rsv;
    };
    u64 as_u64;
  };
} vip_port_key_t;

/**
 * Load balancing service is provided per VIP+protocol+port.
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
  calico_new_flow_entry_t *new_flow_table;

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

  /* tcp or udp. If not per-port vip, set to ~0 */
  u8 protocol;

  /* tcp port or udp port. If not per-port vip, set to ~0 */
  u16 port;

  /* Valid for per-port vip */
  u32 vip_prefix_index;

  u8 is_ip6;

  /* args for different vip encap types */
  u16 target_port;

  /**
   * Flags related to this VIP.
   * CALICO_VIP_FLAGS_USED means the VIP is active.
   * When it is not set, the VIP in the process of being removed.
   * We cannot immediately remove a VIP because the VIP index still may be stored
   * in the adjacency index.
   */
  u8 flags;
#define CALICO_VIP_FLAGS_USED 0x1

  /**
   * Pool of AS indexes used for this VIP.
   * This also includes ASs that have been removed (but are still referenced).
   */
  u32 *as_indexes;
} calico_vip_t;

#define calico_encap_is_ip4(vip) ((vip)->type == CALICO_VIP_TYPE_IP4_NAT4 )

format_function_t format_calico_vip;
format_function_t format_calico_vip_detailed;

#define foreach_calico_nat_protocol \
  _(UDP, 0, udp, "udp")       \
  _(TCP, 1, tcp, "tcp")

typedef enum {
#define _(N, i, n, s) CALICO_NAT_PROTOCOL_##N = i,
  foreach_calico_nat_protocol
#undef _
} calico_nat_protocol_t;

always_inline u32
calico_ip_proto_to_nat_proto (u8 ip_proto)
{
  u32 nat_proto = ~0;

  nat_proto = (ip_proto == IP_PROTOCOL_UDP) ? CALICO_NAT_PROTOCOL_UDP : nat_proto;
  nat_proto = (ip_proto == IP_PROTOCOL_TCP) ? CALICO_NAT_PROTOCOL_TCP : nat_proto;

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
} calico_snat4_key_t;

typedef struct
{
  union
  {
    struct
    {
      ip6_address_t addr;
      u16 port;
      u16 protocol;
      u32 fib_index;
    };
    u64 as_u64[3];
  };
} calico_snat6_key_t;

typedef struct {
  /**
   * for vip + port case, src_ip = vip;
   * for node ip + node_port, src_ip = node_ip
   */
  ip46_address_t src_ip;
  ip46_address_t as_ip;
  u8 src_ip_is_ipv6;
  u8 as_ip_is_ipv6;
  /**
   * Network byte order
   * for vip + port case, src_port = port;
   * for node ip + node_port, src_port = node_port
   */
  u16 src_port;
  u16 target_port; /* Network byte order */
  u32 vrf_id;
  u32 fib_index;
} calico_snat_mapping_t;

typedef struct {
  /**
   * Each CPU has its own sticky flow hash table.
   * One single table is used for all VIPs.
   */
  calico_hash_t *sticky_ht;
} calico_per_cpu_t;

typedef struct {
  /* SNAT prefixes -> snat_address_index map */
  clib_bihash_24_8_t ip6_hash;

  ip6_address_t * dst_addresses;
  u32 dst_address_length_refcounts[129];
  u16 *prefix_lengths_in_search_order;
  uword *non_empty_dst_address_length_bitmap;

  ip6_address_t fib_masks[129];
} calico_fib6;

typedef struct {
  /**
   * Pool of all Virtual IPs
   */
  calico_vip_t *vips;

  /**
   * bitmap for vip prefix to support per-port vip
   */
  uword *vip_prefix_indexes;

  /**
   * Pool of ASs.
   * ASs are referenced by address and vip index.
   * The first element (index 0) is special and used only to fill
   * new_flow_tables when no AS has been configured.
   */
  calico_as_t *ass;

  /**
   * Each AS has an associated reference counter.
   * As ass[0] has a special meaning, its associated counter
   * starts at 0 and is decremented instead. i.e. do not use it.
   */
  vlib_refcount_t as_refcount;

  /**
   * Some global data is per-cpu
   */
  calico_per_cpu_t *per_cpu;

  /**
   * Node next index for IP adjacencies, for each of the traffic types.
   */
  u32 ip_lookup_next_index[CALICO_VIP_N_TYPES];

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
  vlib_simple_counter_main_t vip_counters[CALICO_N_VIP_COUNTERS];

  /**
   * DPO used to send packet from IP4/6 lookup to LB node.
   */
  dpo_type_t dpo_nat4_port_type;
  dpo_type_t dpo_nat6_port_type;
  /**
   * Node type for registering to fib changes.
   */
  fib_node_type_t fib_node_type;

  /* lookup per_port vip by key */
  clib_bihash_8_8_t vip_index_per_port;

  /* Mapping (dst, src, sport, dport, proto) -> vip_index
     for de-NAT-ing packets on the return (out2in) path */
  clib_bihash_40_8_t return_path_5tuple_map;

  /* Static mapping pool TODO : REMOVE */
  calico_fib6 snat6_fib;

  /**
   * API dynamically registered base ID.
   */
  u16 msg_id_base;

  clib_spinlock_t writer_lock;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} calico_main_t;

/* args for different vip encap types */
typedef struct {
  ip46_address_t prefix;
  u8 plen;
  u8 protocol;
  u16 port;
  calico_vip_type_t type;
  u32 new_length;
  u16 target_port;
} calico_vip_add_args_t;

typedef struct {
  ip46_address_t prefix;
  ip46_address_t target_addr;
  u8 len;
  u32 fib_index;
} calico_add_del_snat_args_t;

extern calico_main_t calico_main;
extern vlib_node_registration_t calico4_node;
extern vlib_node_registration_t calico6_node;
extern vlib_node_registration_t calico_nat4_in2out_node;
extern vlib_node_registration_t calico_nat6_in2out_node;

/**
 * Fix global load-balancer parameters.
 * @return 0 on success. VNET_CALICO_ERR_XXX on error
 */
int calico_conf(u32 sticky_buckets, u32 flow_timeout);

int calico_vip_add(calico_vip_add_args_t args, u32 *vip_index);

int calico_vip_del(u32 vip_index);

int calico_vip_find_index(ip46_address_t *prefix, u8 plen, u8 protocol,
                      u16 port, u32 *vip_index);

#define calico_vip_get_by_index(index) (pool_is_free_index(calico_main.vips, index)?NULL:pool_elt_at_index(calico_main.vips, index))

int calico_vip_add_ass(u32 vip_index, ip46_address_t *addresses, u32 n);
int calico_vip_del_ass(u32 vip_index, ip46_address_t *addresses, u32 n, u8 flush);
int calico_flush_vip_as (u32 vip_index, u32 as_index);

u32 calico_hash_time_now(vlib_main_t * vm);

void calico_garbage_collection();

int calico_nat4_interface_add_del (u32 sw_if_index, int is_del);
int calico_nat6_interface_add_del (u32 sw_if_index, int is_del);
int calico_add_del_snat_entry(calico_add_del_snat_args_t * args, u8 is_add);
int calico_search_snat6_entry(ip6_address_t *addr, ip6_address_t *notaddr, ip6_address_t *dst, u32 fib_index);

format_function_t format_calico_main;

#endif /* CALICO_PLUGIN_CALICO_CALICO_H_ */
