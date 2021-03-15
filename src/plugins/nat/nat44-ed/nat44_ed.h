/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
 * @file nat.c
 * NAT plugin global declarations
 */
#ifndef __included_nat44_ed_h__
#define __included_nat44_ed_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/api_errno.h>
#include <vnet/fib/fib_source.h>
#include <vppinfra/elog.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/dlist.h>
#include <vppinfra/error.h>
#include <vlibapi/api.h>

#include <nat/lib/lib.h>
#include <nat/lib/inlines.h>

/* default number of worker handoff frame queue elements */
#define NAT_FQ_NELTS_DEFAULT 64

/* NAT buffer flags */
#define SNAT_FLAG_HAIRPINNING (1 << 0)

/* NAT44 API Configuration flags */
#define foreach_nat44_config_flag  \
  _(0x00, IS_ENDPOINT_INDEPENDENT) \
  _(0x01, IS_ENDPOINT_DEPENDENT)   \
  _(0x02, IS_STATIC_MAPPING_ONLY)  \
  _(0x04, IS_CONNECTION_TRACKING)  \
  _(0x08, IS_OUT2IN_DPO)

typedef enum nat44_config_flags_t_
{
#define _(n,f) NAT44_API_##f = n,
  foreach_nat44_config_flag
#undef _
} nat44_config_flags_t;

typedef struct
{
  /* nat44 plugin features */
  u8 static_mapping_only;
  u8 connection_tracking;

  u32 inside_vrf;
  u32 outside_vrf;

  /* maximum number of sessions */
  u32 sessions;

} nat44_config_t;

typedef enum
{
  NAT_NEXT_DROP,
  NAT_NEXT_ICMP_ERROR,
  NAT_NEXT_IN2OUT_ED_FAST_PATH,
  NAT_NEXT_IN2OUT_ED_SLOW_PATH,
  NAT_NEXT_IN2OUT_ED_OUTPUT_FAST_PATH,
  NAT_NEXT_IN2OUT_ED_OUTPUT_SLOW_PATH,
  NAT_NEXT_OUT2IN_ED_FAST_PATH,
  NAT_NEXT_OUT2IN_ED_SLOW_PATH,
  NAT_NEXT_IN2OUT_CLASSIFY,
  NAT_NEXT_OUT2IN_CLASSIFY,
  NAT_N_NEXT,
} nat_next_t;

typedef struct
{
  u32 next_index;
  u32 arc_next_index;
} nat_pre_trace_t;

/* External address and port allocation modes */
#define foreach_nat_addr_and_port_alloc_alg \
  _(0, DEFAULT, "default")         \
  _(1, MAPE, "map-e")              \
  _(2, RANGE, "port-range")

typedef enum
{
#define _(v, N, s) NAT_ADDR_AND_PORT_ALLOC_ALG_##N = v,
  foreach_nat_addr_and_port_alloc_alg
#undef _
} nat_addr_and_port_alloc_alg_t;

/* Session state */
#define foreach_snat_session_state          \
  _(0, UNKNOWN, "unknown")                 \
  _(1, UDP_ACTIVE, "udp-active")           \
  _(2, TCP_SYN_SENT, "tcp-syn-sent")       \
  _(3, TCP_ESTABLISHED, "tcp-established") \
  _(4, TCP_FIN_WAIT, "tcp-fin-wait")       \
  _(5, TCP_CLOSE_WAIT, "tcp-close-wait")   \
  _(6, TCP_CLOSING, "tcp-closing")         \
  _(7, TCP_LAST_ACK, "tcp-last-ack")       \
  _(8, TCP_CLOSED, "tcp-closed")           \
  _(9, ICMP_ACTIVE, "icmp-active")

typedef enum
{
#define _(v, N, s) SNAT_SESSION_##N = v,
  foreach_snat_session_state
#undef _
} snat_session_state_t;

#define foreach_nat_in2out_ed_error                     \
_(UNSUPPORTED_PROTOCOL, "unsupported protocol")         \
_(OUT_OF_PORTS, "out of ports")                         \
_(BAD_ICMP_TYPE, "unsupported ICMP type")               \
_(MAX_SESSIONS_EXCEEDED, "maximum sessions exceeded")   \
_(NON_SYN, "non-SYN packet try to create session")      \
_(TCP_CLOSED, "drops due to TCP in transitory timeout")

typedef enum
{
#define _(sym,str) NAT_IN2OUT_ED_ERROR_##sym,
  foreach_nat_in2out_ed_error
#undef _
    NAT_IN2OUT_ED_N_ERROR,
} nat_in2out_ed_error_t;

#define foreach_nat_out2in_ed_error                                           \
  _ (UNSUPPORTED_PROTOCOL, "unsupported protocol")                            \
  _ (OUT_OF_PORTS, "out of ports")                                            \
  _ (BAD_ICMP_TYPE, "unsupported ICMP type")                                  \
  _ (NO_TRANSLATION, "no translation")                                        \
  _ (MAX_SESSIONS_EXCEEDED, "maximum sessions exceeded")                      \
  _ (NON_SYN, "non-SYN packet try to create session")                         \
  _ (TCP_CLOSED, "drops due to TCP in transitory timeout")                    \
  _ (HASH_ADD_FAILED, "hash table add failed")

typedef enum
{
#define _(sym,str) NAT_OUT2IN_ED_ERROR_##sym,
  foreach_nat_out2in_ed_error
#undef _
    NAT_OUT2IN_ED_N_ERROR,
} nat_out2in_ed_error_t;


/* Endpoint dependent TCP session state */
#define NAT44_SES_I2O_FIN 1
#define NAT44_SES_O2I_FIN 2
#define NAT44_SES_I2O_FIN_ACK 4
#define NAT44_SES_O2I_FIN_ACK 8
#define NAT44_SES_I2O_SYN 16
#define NAT44_SES_O2I_SYN 32
#define NAT44_SES_RST     64

/* Session flags */
#define SNAT_SESSION_FLAG_STATIC_MAPPING     (1 << 0)
#define SNAT_SESSION_FLAG_UNKNOWN_PROTO	     (1 << 1)
#define SNAT_SESSION_FLAG_LOAD_BALANCING     (1 << 2)
#define SNAT_SESSION_FLAG_TWICE_NAT	     (1 << 3)
#define SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT (1 << 4)
#define SNAT_SESSION_FLAG_FWD_BYPASS	     (1 << 5)
#define SNAT_SESSION_FLAG_AFFINITY	     (1 << 6)
#define SNAT_SESSION_FLAG_EXACT_ADDRESS	     (1 << 7)
#define SNAT_SESSION_FLAG_HAIRPINNING	     (1 << 8)

/* NAT interface flags */
#define NAT_INTERFACE_FLAG_IS_INSIDE 1
#define NAT_INTERFACE_FLAG_IS_OUTSIDE 2

/* Static mapping flags */
#define NAT_STATIC_MAPPING_FLAG_ADDR_ONLY      1
#define NAT_STATIC_MAPPING_FLAG_OUT2IN_ONLY    2
#define NAT_STATIC_MAPPING_FLAG_IDENTITY_NAT   4
#define NAT_STATIC_MAPPING_FLAG_LB             8
#define NAT_STATIC_MAPPING_FLAG_EXACT_ADDRESS  16

typedef CLIB_PACKED(struct
{
  // number of sessions in this vrf
  u32 ses_count;

  u32 rx_fib_index;
  u32 tx_fib_index;

  // is this vrf expired
  u8 expired;
}) per_vrf_sessions_t;

typedef union
{
  struct
  {
    ip4_address_t saddr, daddr;
    u16 sport; // ICMP id for ICMP case
    u16 dport;
    u32 fib_index : 24;
    u8 proto;
  };
  u64 as_u64[2];
  u64x2u as_u128;
} nat_6t_t;

STATIC_ASSERT_SIZEOF (nat_6t_t, 2 * sizeof (u64));

typedef struct
{
#define NAT_FLOW_OP_SADDR_REWRITE   (1 << 1)
#define NAT_FLOW_OP_SPORT_REWRITE   (1 << 2)
#define NAT_FLOW_OP_DADDR_REWRITE   (1 << 3)
#define NAT_FLOW_OP_DPORT_REWRITE   (1 << 4)
#define NAT_FLOW_OP_ICMP_ID_REWRITE (1 << 5)
#define NAT_FLOW_OP_TXFIB_REWRITE   (1 << 6)
  int ops;
  nat_6t_t match;
  struct
  {
    ip4_address_t saddr, daddr;
    u16 sport;
    u16 dport;
    u32 fib_index;
    u8 proto;
    u16 icmp_id;
  } rewrite;
  uword l3_csum_delta;
  uword l4_csum_delta;
} nat_6t_flow_t;

void nat44_ed_forwarding_enable_disable (u8 is_enable);

always_inline void
nat_6t_flow_saddr_rewrite_set (nat_6t_flow_t *f, u32 saddr)
{
  f->ops |= NAT_FLOW_OP_SADDR_REWRITE;
  f->rewrite.saddr.as_u32 = saddr;
}

always_inline void
nat_6t_flow_daddr_rewrite_set (nat_6t_flow_t *f, u32 daddr)
{
  f->ops |= NAT_FLOW_OP_DADDR_REWRITE;
  f->rewrite.daddr.as_u32 = daddr;
}

always_inline void
nat_6t_flow_sport_rewrite_set (nat_6t_flow_t *f, u32 sport)
{
  f->ops |= NAT_FLOW_OP_SPORT_REWRITE;
  f->rewrite.sport = sport;
}

always_inline void
nat_6t_flow_dport_rewrite_set (nat_6t_flow_t *f, u32 dport)
{
  f->ops |= NAT_FLOW_OP_DPORT_REWRITE;
  f->rewrite.dport = dport;
}

always_inline void
nat_6t_flow_txfib_rewrite_set (nat_6t_flow_t *f, u32 tx_fib_index)
{
  f->ops |= NAT_FLOW_OP_TXFIB_REWRITE;
  f->rewrite.fib_index = tx_fib_index;
}

always_inline void
nat_6t_flow_icmp_id_rewrite_set (nat_6t_flow_t *f, u16 id)
{
  f->ops |= NAT_FLOW_OP_ICMP_ID_REWRITE;
  f->rewrite.icmp_id = id;
}

typedef CLIB_PACKED(struct
{
  /* Outside network tuple */
  struct
  {
    ip4_address_t addr;
    u32 fib_index;
    u16 port;
  } out2in;

  /* Inside network tuple */
  struct
  {
    ip4_address_t addr;
    u32 fib_index;
    u16 port;
  } in2out;

  nat_protocol_t nat_proto;

  nat_6t_flow_t i2o;
  nat_6t_flow_t o2i;

  /* Flags */
  u32 flags;

  /* head of LRU list in which this session is tracked */
  u32 lru_head_index;
  /* index in global LRU list */
  u32 lru_index;
  f64 last_lru_update;

  /* Last heard timer */
  f64 last_heard;

  /* Last HA refresh */
  f64 ha_last_refreshed;

  /* Counters */
  u64 total_bytes;
  u32 total_pkts;

  /* External host address and port */
  ip4_address_t ext_host_addr;
  u16 ext_host_port;

  /* External host address and port after translation */
  ip4_address_t ext_host_nat_addr;
  u16 ext_host_nat_port;

  /* TCP session state */
  u8 state;
  u32 i2o_fin_seq;
  u32 o2i_fin_seq;
  u64 tcp_closed_timestamp;

  /* per vrf sessions index */
  u32 per_vrf_sessions_index;

}) snat_session_t;

typedef struct
{
  ip4_address_t addr;
  u32 fib_index;
#define _(N, i, n, s) \
  u32 busy_##n##_ports; \
  u32 * busy_##n##_ports_per_thread; \
  u32 busy_##n##_port_refcounts[65535];
  foreach_nat_protocol
#undef _
} snat_address_t;

typedef struct
{
  u32 fib_index;
  u32 ref_count;
} nat_fib_t;

typedef struct
{
  u32 fib_index;
  u32 refcount;
} nat_outside_fib_t;

typedef struct
{
  /* backend IP address */
  ip4_address_t addr;
  /* backend port number */
  u16 port;
  /* probability of the backend to be randomly matched */
  u8 probability;
  u8 prefix;
  /* backend FIB table */
  u32 vrf_id;
  u32 fib_index;
} nat44_lb_addr_port_t;

typedef enum
{
  /* twice-nat disabled */
  TWICE_NAT_DISABLED,
  /* twice-nat enabled */
  TWICE_NAT,
  /* twice-nat only when src IP equals dst IP after translation */
  TWICE_NAT_SELF,
} twice_nat_type_t;

typedef enum
{
  /* no load-balancing */
  NO_LB_NAT,
  /* load-balancing */
  LB_NAT,
  /* load-balancing with affinity */
  AFFINITY_LB_NAT,
} lb_nat_type_t;

typedef struct
{
  /* prefered pool address */
  ip4_address_t pool_addr;
  /* local IP address */
  ip4_address_t local_addr;
  /* external IP address */
  ip4_address_t external_addr;
  /* local port */
  u16 local_port;
  /* external port */
  u16 external_port;
  /* is twice-nat */
  twice_nat_type_t twice_nat;
  /* local FIB table */
  u32 vrf_id;
  u32 fib_index;
  /* protocol */
  nat_protocol_t proto;
  /* 0 = disabled, otherwise client IP affinity sticky time in seconds */
  u32 affinity;
  /* worker threads used by backends/local host */
  u32 *workers;
  /* opaque string tag */
  u8 *tag;
  /* backends for load-balancing mode */
  nat44_lb_addr_port_t *locals;
  /* affinity per service lis */
  u32 affinity_per_service_list_head_index;
  /* flags */
  u32 flags;
} snat_static_mapping_t;

typedef struct
{
  u32 sw_if_index;
  u8 flags;
} snat_interface_t;

typedef struct
{
  ip4_address_t l_addr;
  ip4_address_t pool_addr;
  u16 l_port;
  u16 e_port;
  u32 sw_if_index;
  u32 vrf_id;
  nat_protocol_t proto;
  u32 flags;
  int addr_only;
  int twice_nat;
  int out2in_only;
  int identity_nat;
  int exact;
  u8 *tag;
} snat_static_map_resolve_t;

typedef struct
{
  /* Session pool */
  snat_session_t *sessions;

  /* Pool of doubly-linked list elements */
  dlist_elt_t *list_pool;

  /* LRU session list - head is stale, tail is fresh */
  dlist_elt_t *lru_pool;
  u32 tcp_trans_lru_head_index;
  u32 tcp_estab_lru_head_index;
  u32 udp_lru_head_index;
  u32 icmp_lru_head_index;
  u32 unk_proto_lru_head_index;

  /* NAT thread index */
  u32 snat_thread_index;

  /* real thread index */
  u32 thread_index;

  per_vrf_sessions_t *per_vrf_sessions_vec;

} snat_main_per_thread_data_t;

struct snat_main_s;

u32 nat44_ed_get_in2out_worker_index (vlib_buffer_t *b, ip4_header_t *ip,
				      u32 rx_fib_index, u8 is_output);
u32 nat44_ed_get_out2in_worker_index (vlib_buffer_t *b, ip4_header_t *ip,
				      u32 rx_fib_index, u8 is_output);

/* Return worker thread index for given packet */
/* NAT address and port allocation function */
typedef int (nat_alloc_out_addr_and_port_function_t) (snat_address_t *
						      addresses,
						      u32 fib_index,
						      u32 thread_index,
						      nat_protocol_t proto,
						      ip4_address_t * addr,
						      u16 * port,
						      u16 port_per_thread,
						      u32 snat_thread_index);

typedef struct snat_main_s
{
  /* Thread settings */
  u32 num_workers;
  u32 first_worker_index;
  u32 *workers;
  u16 port_per_thread;

  /* Per thread data */
  snat_main_per_thread_data_t *per_thread_data;

  /* Find a static mapping by local */
  clib_bihash_8_8_t static_mapping_by_local;

  /* Find a static mapping by external */
  clib_bihash_8_8_t static_mapping_by_external;

  /* Static mapping pool */
  snat_static_mapping_t *static_mappings;

  /* Endpoint independent lookup tables */
  clib_bihash_8_8_t in2out;
  clib_bihash_8_8_t out2in;

  /* Endpoint dependent lookup table */
  clib_bihash_16_8_t flow_hash;

  /* Interface pool */
  snat_interface_t *interfaces;
  snat_interface_t *output_feature_interfaces;

  /* Vector of outside addresses */
  snat_address_t *addresses;
  /* Address and port allocation function */
  nat_alloc_out_addr_and_port_function_t *alloc_addr_and_port;
  /* Address and port allocation type */
  nat_addr_and_port_alloc_alg_t addr_and_port_alloc_alg;
  /* Port set parameters (MAP-E) */
  u8 psid_offset;
  u8 psid_length;
  u16 psid;
  /* Port range parameters */
  u16 start_port;
  u16 end_port;

  /* vector of fibs */
  nat_fib_t *fibs;

  /* vector of outside fibs */
  nat_outside_fib_t *outside_fibs;

  /* Vector of twice NAT addresses for external hosts */
  snat_address_t *twice_nat_addresses;

  /* sw_if_indices whose intfc addresses should be auto-added */
  u32 *auto_add_sw_if_indices;
  u32 *auto_add_sw_if_indices_twice_nat;

  /* vector of interface address static mappings to resolve. */
  snat_static_map_resolve_t *to_resolve;

  /* Randomize port allocation order */
  u32 random_seed;

  /* Worker handoff frame-queue index */
  u32 fq_in2out_index;
  u32 fq_in2out_output_index;
  u32 fq_out2in_index;

  u32 out2in_node_index;
  u32 in2out_node_index;
  u32 in2out_output_node_index;

  nat44_config_t rconfig;
  //nat44_config_t cconfig;

  /* If forwarding is enabled */
  u8 forwarding_enabled;

  /* static mapping config */
  u8 static_mapping_only;
  u8 static_mapping_connection_tracking;

  /* Is translation memory size calculated or user defined */
  u8 translation_memory_size_set;

  u32 translation_buckets;
  u32 max_translations_per_thread;
  u32 *max_translations_per_fib;

  u32 outside_vrf_id;
  u32 outside_fib_index;
  u32 inside_vrf_id;
  u32 inside_fib_index;

  nat_timeouts_t timeouts;

  /* TCP MSS clamping */
  u16 mss_clamping;

  /* counters */
  vlib_simple_counter_main_t total_sessions;

#define _(x) vlib_simple_counter_main_t x;
  struct
  {
    struct
    {
      struct
      {
	foreach_nat_counter;
      } in2out;

      struct
      {
	foreach_nat_counter;
      } out2in;
    } fastpath;

    struct
    {
      struct
      {
	foreach_nat_counter;
      } in2out;

      struct
      {
	foreach_nat_counter;
      } out2in;
    } slowpath;

    vlib_simple_counter_main_t hairpinning;
  } counters;
#undef _

  /* API message ID base */
  u16 msg_id_base;

  /* log class */
  vlib_log_class_t log_class;
  /* logging level */
  u8 log_level;

  /* convenience */
  api_main_t *api_main;
  ip4_main_t *ip4_main;
  ip_lookup_main_t *ip4_lookup_main;

  fib_source_t fib_src_hi;
  fib_source_t fib_src_low;

  /* pat - dynamic mapping enabled or conneciton tracking */
  u8 pat;

  /* number of worker handoff frame queue elements */
  u32 frame_queue_nelts;

  /* nat44 plugin enabled */
  u8 enabled;

  vnet_main_t *vnet_main;

} snat_main_t;

typedef struct
{
  u32 thread_index;
  f64 now;
} nat44_is_idle_session_ctx_t;

typedef struct
{
  u32 cached_sw_if_index;
  u32 cached_ip4_address;
} snat_runtime_t;

extern snat_main_t snat_main;

// nat pre ed next_node feature classification
extern vlib_node_registration_t nat_default_node;
extern vlib_node_registration_t nat_pre_in2out_node;
extern vlib_node_registration_t nat_pre_out2in_node;

extern vlib_node_registration_t snat_in2out_node;
extern vlib_node_registration_t snat_in2out_output_node;
extern vlib_node_registration_t snat_out2in_node;
extern vlib_node_registration_t snat_in2out_worker_handoff_node;
extern vlib_node_registration_t snat_in2out_output_worker_handoff_node;
extern vlib_node_registration_t snat_out2in_worker_handoff_node;
extern vlib_node_registration_t nat44_ed_in2out_node;
extern vlib_node_registration_t nat44_ed_in2out_output_node;
extern vlib_node_registration_t nat44_ed_out2in_node;

extern fib_source_t nat_fib_src_hi;
extern fib_source_t nat_fib_src_low;

/* format functions */
format_function_t format_snat_static_mapping;
format_function_t format_snat_static_map_to_resolve;
format_function_t format_snat_session;
format_function_t format_snat_key;
format_function_t format_static_mapping_key;
format_function_t format_nat_protocol;
format_function_t format_nat_addr_and_port_alloc_alg;
/* unformat functions */
unformat_function_t unformat_nat_protocol;

/** \brief Check if SNAT session is created from static mapping.
    @param s SNAT session
    @return 1 if SNAT session is created from static mapping otherwise 0
*/
#define snat_is_session_static(s) (s->flags & SNAT_SESSION_FLAG_STATIC_MAPPING)

/** \brief Check if SNAT session for unknown protocol.
    @param s SNAT session
    @return 1 if SNAT session for unknown protocol otherwise 0
*/
#define snat_is_unk_proto_session(s) (s->flags & SNAT_SESSION_FLAG_UNKNOWN_PROTO)

/** \brief Check if NAT session is twice NAT.
    @param s NAT session
    @return 1 if NAT session is twice NAT
*/
#define is_twice_nat_session(s) (s->flags & SNAT_SESSION_FLAG_TWICE_NAT)

/** \brief Check if NAT session is load-balancing.
    @param s NAT session
    @return 1 if NAT session is load-balancing
*/
#define is_lb_session(s) (s->flags & SNAT_SESSION_FLAG_LOAD_BALANCING)

/** \brief Check if NAT session is forwarding bypass.
    @param s NAT session
    @return 1 if NAT session is load-balancing
*/
#define is_fwd_bypass_session(s) (s->flags & SNAT_SESSION_FLAG_FWD_BYPASS)

/** \brief Check if NAT session is endpoint dependent.
    @param s NAT session
    @return 1 if NAT session is endpoint dependent
*/
#define is_ed_session(s) (s->flags & SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT)

/** \brief Check if NAT session has affinity record.
    @param s NAT session
    @return 1 if NAT session has affinity record
*/
#define is_affinity_sessions(s) (s->flags & SNAT_SESSION_FLAG_AFFINITY)

/** \brief Check if exact pool address should be used.
    @param s SNAT session
    @return 1 if exact pool address or 0
*/
#define is_exact_address_session(s) (s->flags & SNAT_SESSION_FLAG_EXACT_ADDRESS)

/** \brief Check if NAT interface is inside.
    @param i NAT interface
    @return 1 if inside interface
*/
#define nat_interface_is_inside(i) i->flags & NAT_INTERFACE_FLAG_IS_INSIDE

/** \brief Check if NAT interface is outside.
    @param i NAT interface
    @return 1 if outside interface
*/
#define nat_interface_is_outside(i) i->flags & NAT_INTERFACE_FLAG_IS_OUTSIDE

/** \brief Check if NAT44 endpoint-dependent TCP session is closed.
    @param s NAT session
    @return 1 if session is closed
*/
#define nat44_is_ses_closed(s) s->state == 0xf

/** \brief Check if NAT static mapping is address only (1:1NAT).
    @param sm NAT static mapping
    @return 1 if 1:1NAT, 0 if 1:1NAPT
*/
#define is_addr_only_static_mapping(sm) (sm->flags & NAT_STATIC_MAPPING_FLAG_ADDR_ONLY)

/** \brief Check if NAT static mapping match only out2in direction.
    @param sm NAT static mapping
    @return 1 if rule match only out2in direction
*/
#define is_out2in_only_static_mapping(sm) (sm->flags & NAT_STATIC_MAPPING_FLAG_OUT2IN_ONLY)

/** \brief Check if NAT static mapping is identity NAT.
    @param sm NAT static mapping
    @return 1 if identity NAT
*/
#define is_identity_static_mapping(sm) (sm->flags & NAT_STATIC_MAPPING_FLAG_IDENTITY_NAT)

/** \brief Check if NAT static mapping is load-balancing.
    @param sm NAT static mapping
    @return 1 if load-balancing
*/
#define is_lb_static_mapping(sm) (sm->flags & NAT_STATIC_MAPPING_FLAG_LB)

/** \brief Check if exact pool address should be used.
    @param s SNAT session
    @return 1 if exact pool address or 0
*/
#define is_exact_address(s) (s->flags & NAT_STATIC_MAPPING_FLAG_EXACT_ADDRESS)

/** \brief Check if client initiating TCP connection (received SYN from client)
    @param t TCP header
    @return 1 if client initiating TCP connection
*/
always_inline bool
tcp_flags_is_init (u8 f)
{
  return (f & TCP_FLAG_SYN) && !(f & TCP_FLAG_ACK);
}

/* logging */
#define nat_log_err(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, snat_main.log_class, __VA_ARGS__)
#define nat_log_warn(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, snat_main.log_class, __VA_ARGS__)
#define nat_log_notice(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, snat_main.log_class, __VA_ARGS__)
#define nat_log_info(...) \
  vlib_log(VLIB_LOG_LEVEL_INFO, snat_main.log_class, __VA_ARGS__)
#define nat_log_debug(...)\
  vlib_log(VLIB_LOG_LEVEL_DEBUG, snat_main.log_class, __VA_ARGS__)

/**
 * @brief Enable NAT44 plugin
 *
 * @param c         nat44_config_t
 *
 * @return 0 on success, non-zero value otherwise
 */
int nat44_plugin_enable (nat44_config_t c);

/**
 * @brief Disable NAT44 plugin
 *
 * @return 0 on success, non-zero value otherwise
 */
int nat44_plugin_disable ();

/**
 * @brief Add external address to NAT44 pool
 *
 * @param sm        snat global configuration data
 * @param addr      IPv4 address
 * @param vrf_id    VRF id of tenant, ~0 means independent of VRF
 * @param twice_nat 1 if twice NAT address
 *
 * @return 0 on success, non-zero value otherwise
 */
int snat_add_address (snat_main_t * sm, ip4_address_t * addr, u32 vrf_id,
		      u8 twice_nat);

/**
 * @brief Delete external address from NAT44 pool
 *
 * @param sm        snat global configuration data
 * @param addr      IPv4 address
 * @param delete_sm 1 if delete static mapping using address
 * @param twice_nat 1 if twice NAT address
 *
 * @return 0 on success, non-zero value otherwise
 */
int snat_del_address (snat_main_t * sm, ip4_address_t addr, u8 delete_sm,
		      u8 twice_nat);

/**
 * @brief Add/delete external address to FIB DPO (out2in DPO mode)
 *
 * @param addr   IPv4 address
 * @param is_add 1 = add, 0 = delete
 *
 * @return 0 on success, non-zero value otherwise
 */
void nat44_add_del_address_dpo (ip4_address_t addr, u8 is_add);

/**
 * @brief Add/delete NAT44 static mapping
 *
 * @param l_addr       local IPv4 address
 * @param e_addr       external IPv4 address
 * @param l_port       local port number
 * @param e_port       external port number
 * @param vrf_id       local VRF ID
 * @param addr_only    1 = 1:1NAT, 0 = 1:1NAPT
 * @param sw_if_index  use interface address as external IPv4 address
 * @param proto        L4 protocol
 * @param is_add       1 = add, 0 = delete
 * @param twice_nat    twice-nat mode
 * @param out2in_only  if 1 rule match only out2in direction
 * @param tag          opaque string tag
 * @param identity_nat identity NAT
 * @param pool_addr    pool IPv4 address
 * @param exact        1 = exact pool address
 *
 * @return 0 on success, non-zero value otherwise
 */
int snat_add_static_mapping (ip4_address_t l_addr, ip4_address_t e_addr,
			     u16 l_port, u16 e_port, u32 vrf_id,
			     int addr_only, u32 sw_if_index,
			     nat_protocol_t proto, int is_add,
			     twice_nat_type_t twice_nat, u8 out2in_only,
			     u8 * tag, u8 identity_nat,
			     ip4_address_t pool_addr, int exact);

/**
 * @brief Add/delete static mapping with load-balancing (multiple backends)
 *
 * @param e_addr      external IPv4 address
 * @param e_port      external port number
 * @param proto       L4 protocol
 * @param locals      list of local backends
 * @param is_add      1 = add, 0 = delete
 * @param twice_nat   twice-nat mode
 * @param out2in_only if 1 rule match only out2in direction
 * @param tag         opaque string tag
 * @param affinity    0 = disabled, otherwise client IP affinity sticky time
 *
 * @return 0 on success, non-zero value otherwise
 */
int nat44_add_del_lb_static_mapping (ip4_address_t e_addr, u16 e_port,
				     nat_protocol_t proto,
				     nat44_lb_addr_port_t * locals, u8 is_add,
				     twice_nat_type_t twice_nat,
				     u8 out2in_only, u8 * tag, u32 affinity);

int nat44_lb_static_mapping_add_del_local (ip4_address_t e_addr, u16 e_port,
					   ip4_address_t l_addr, u16 l_port,
					   nat_protocol_t proto, u32 vrf_id,
					   u8 probability, u8 is_add);

clib_error_t *nat44_api_hookup (vlib_main_t * vm);

/**
 * @brief Set NAT plugin workers
 *
 * @param bitmap NAT workers bitmap
 *
 * @return 0 on success, non-zero value otherwise
 */
int snat_set_workers (uword * bitmap);

/**
 * @brief Set NAT plugin number of frame queue elements
 *
 * @param frame_queue_nelts number of worker handoff frame queue elements
 *
 * @return 0 on success, non-zero value otherwise
 */
int snat_set_frame_queue_nelts (u32 frame_queue_nelts);

/**
 * @brief Enable/disable NAT44 feature on the interface
 *
 * @param sw_if_index software index of the interface
 * @param is_inside   1 = inside, 0 = outside
 * @param is_del      1 = delete, 0 = add
 *
 * @return 0 on success, non-zero value otherwise
 */
int snat_interface_add_del (u32 sw_if_index, u8 is_inside, int is_del);

/**
 * @brief Enable/disable NAT44 output feature on the interface (postrouting NAT)
 *
 * @param sw_if_index software index of the interface
 * @param is_inside   1 = inside, 0 = outside
 * @param is_del      1 = delete, 0 = add
 *
 * @return 0 on success, non-zero value otherwise
 */
int snat_interface_add_del_output_feature (u32 sw_if_index, u8 is_inside,
					   int is_del);

/**
 * @brief Add/delete NAT44 pool address from specific interface
 *
 * @param sw_if_index software index of the interface
 * @param is_del      1 = delete, 0 = add
 * @param twice_nat   1 = twice NAT address for external hosts
 *
 * @return 0 on success, non-zero value otherwise
 */
int snat_add_interface_address (snat_main_t * sm, u32 sw_if_index, int is_del,
				u8 twice_nat);

/**
 * @brief Delete NAT44 endpoint-dependent session
 *
 * @param sm     snat global configuration data
 * @param addr   IPv4 address
 * @param port   L4 port number
 * @param proto  L4 protocol
 * @param vrf_id VRF ID
 * @param is_in  1 = inside network address and port pair, 0 = outside
 *
 * @return 0 on success, non-zero value otherwise
 */
int nat44_del_ed_session (snat_main_t * sm, ip4_address_t * addr, u16 port,
			  ip4_address_t * eh_addr, u16 eh_port, u8 proto,
			  u32 vrf_id, int is_in);

/**
 * @brief Free NAT44 session data (lookup keys, external address port)
 *
 * @param sm           snat global configuration data
 * @param s            NAT session
 * @param thread_index thread index
 * @param is_ha        is HA event
 */
void nat_free_session_data (snat_main_t * sm, snat_session_t * s,
			    u32 thread_index, u8 is_ha);

/**
 * @brief Set NAT44 session limit (session limit, vrf id)
 *
 * @param session_limit Session limit
 * @param vrf_id        VRF id
 * @return 0 on success, non-zero value otherwise
 */
int nat44_set_session_limit (u32 session_limit, u32 vrf_id);

/**
 * @brief Update NAT44 session limit flushing all data (session limit, vrf id)
 *
 * @param session_limit Session limit
 * @param vrf_id        VRF id
 * @return 0 on success, non-zero value otherwise
 */
int nat44_update_session_limit (u32 session_limit, u32 vrf_id);

/**
 * @brief Free outside address and port pair
 *
 * @param addresses    vector of outside addresses
 * @param thread_index thread index
 * @param key          address, port and protocol
 */
void
snat_free_outside_address_and_port (snat_address_t * addresses,
				    u32 thread_index,
				    ip4_address_t * addr,
				    u16 port, nat_protocol_t protocol);

void expire_per_vrf_sessions (u32 fib_index);

/**
 * @brief Match NAT44 static mapping.
 *
 * @param key             address and port to match
 * @param addr            external/local address of the matched mapping
 * @param port            port of the matched mapping
 * @param fib_index       fib index of the matched mapping
 * @param by_external     if 0 match by local address otherwise match by external
 *                        address
 * @param is_addr_only    1 if matched mapping is address only
 * @param twice_nat       matched mapping is twice NAT type
 * @param lb              1 if matched mapping is load-balanced
 * @param ext_host_addr   external host address
 * @param is_identity_nat 1 if indentity mapping
 * @param out             if !=0 set to pointer of the mapping structure
 *
 * @returns 0 if match found otherwise 1.
 */
int snat_static_mapping_match (
  vlib_main_t *vm, snat_main_t *sm, ip4_address_t match_addr, u16 match_port,
  u32 match_fib_index, nat_protocol_t match_protocol,
  ip4_address_t *mapping_addr, u16 *mapping_port, u32 *mapping_fib_index,
  u8 by_external, u8 *is_addr_only, twice_nat_type_t *twice_nat,
  lb_nat_type_t *lb, ip4_address_t *ext_host_addr, u8 *is_identity_nat,
  snat_static_mapping_t **out);

/**
 * @brief Add/del NAT address to FIB.
 *
 * Add the external NAT address to the FIB as receive entries. This ensures
 * that VPP will reply to ARP for this address and we don't need to enable
 * proxy ARP on the outside interface.
 *
 * @param addr        IPv4 address
 * @param plen        address prefix length
 * @param sw_if_index software index of the outside interface
 * @param is_add      0 = delete, 1 = add.
 */
void snat_add_del_addr_to_fib (ip4_address_t * addr,
			       u8 p_len, u32 sw_if_index, int is_add);

#if 0
void
nat_ha_sadd_ed_cb (ip4_address_t * in_addr, u16 in_port,
		   ip4_address_t * out_addr, u16 out_port,
		   ip4_address_t * eh_addr, u16 eh_port,
		   ip4_address_t * ehn_addr, u16 ehn_port, u8 proto,
		   u32 fib_index, u16 flags, u32 thread_index);

void
nat_ha_sdel_ed_cb (ip4_address_t * out_addr, u16 out_port,
		   ip4_address_t * eh_addr, u16 eh_port, u8 proto,
		   u32 fib_index, u32 ti);

void
nat_ha_sref_ed_cb (ip4_address_t * out_addr, u16 out_port,
		   ip4_address_t * eh_addr, u16 eh_port, u8 proto,
		   u32 fib_index, u32 total_pkts, u64 total_bytes,
		   u32 thread_index);
#endif

int nat_set_outside_address_and_port (snat_address_t *addresses,
				      u32 thread_index, ip4_address_t addr,
				      u16 port, nat_protocol_t protocol);

/*
 * Why is this here? Because we don't need to touch this layer to
 * simply reply to an icmp. We need to change id to a unique
 * value to NAT an echo request/reply.
 */

typedef struct
{
  u16 identifier;
  u16 sequence;
} icmp_echo_header_t;

typedef struct
{
  u16 src_port, dst_port;
} tcp_udp_header_t;

u32 get_thread_idx_by_port (u16 e_port);

u8 *format_static_mapping_kvp (u8 *s, va_list *args);

u8 *format_session_kvp (u8 *s, va_list *args);

u32 nat_calc_bihash_buckets (u32 n_elts);

void nat44_addresses_free (snat_address_t **addresses);

void nat44_ed_sessions_clear ();

int nat44_ed_set_frame_queue_nelts (u32 frame_queue_nelts);

typedef enum
{
  NAT_ED_TRNSL_ERR_SUCCESS = 0,
  NAT_ED_TRNSL_ERR_TRANSLATION_FAILED = 1,
  NAT_ED_TRNSL_ERR_FLOW_MISMATCH = 2,
} nat_translation_error_e;

nat_translation_error_e
nat_6t_flow_buf_translate (snat_main_t *sm, vlib_buffer_t *b, ip4_header_t *ip,
			   nat_6t_flow_t *f, nat_protocol_t proto,
			   int is_output_feature);

void nat_6t_l3_l4_csum_calc (nat_6t_flow_t *f);

format_function_t format_nat_ed_translation_error;
format_function_t format_nat_6t_flow;
format_function_t format_ed_session_kvp;

#endif /* __included_nat44_ed_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
