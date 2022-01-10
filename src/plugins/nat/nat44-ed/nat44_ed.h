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
#include <vppinfra/hash.h>
#include <vppinfra/dlist.h>
#include <vppinfra/error.h>
#include <vlibapi/api.h>

#include <nat/lib/lib.h>
#include <nat/lib/inlines.h>

/* default number of worker handoff frame queue elements */
#define NAT_FQ_NELTS_DEFAULT 64

/* number of attempts to get a port for ED overloading algorithm, if rolling
 * a dice this many times doesn't produce a free port, it's treated
 * as if there were no free ports available to conserve resources */
#define ED_PORT_ALLOC_ATTEMPTS (10)

/* NAT buffer flags */
#define SNAT_FLAG_HAIRPINNING (1 << 0)

/* NAT44 API Configuration flags */
#define foreach_nat44_config_flag                                             \
  _ (0x00, IS_ENDPOINT_INDEPENDENT)                                           \
  _ (0x01, IS_ENDPOINT_DEPENDENT)                                             \
  _ (0x02, IS_STATIC_MAPPING_ONLY)                                            \
  _ (0x04, IS_CONNECTION_TRACKING)

typedef enum nat44_config_flags_t_
{
#define _(n,f) NAT44_API_##f = n,
  foreach_nat44_config_flag
#undef _
} nat44_config_flags_t;

typedef struct
{
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

#define foreach_nat_in2out_ed_error                                           \
  _ (UNSUPPORTED_PROTOCOL, "unsupported protocol")                            \
  _ (OUT_OF_PORTS, "out of ports")                                            \
  _ (BAD_ICMP_TYPE, "unsupported ICMP type")                                  \
  _ (MAX_SESSIONS_EXCEEDED, "maximum sessions exceeded")                      \
  _ (NON_SYN, "non-SYN packet try to create session")                         \
  _ (TRNSL_FAILED, "couldn't translate packet")

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
  _ (HASH_ADD_FAILED, "hash table add failed")                                \
  _ (TRNSL_FAILED, "couldn't translate packet")

typedef enum
{
#define _(sym,str) NAT_OUT2IN_ED_ERROR_##sym,
  foreach_nat_out2in_ed_error
#undef _
    NAT_OUT2IN_ED_N_ERROR,
} nat_out2in_ed_error_t;


/* Endpoint dependent TCP session state */
typedef enum
{
  NAT44_ED_TCP_CLOSED = 0,
  NAT44_ED_TCP_SYN_I2O,
  NAT44_ED_TCP_SYN_O2I,
  NAT44_ED_TCP_ESTABLISHED,
  NAT44_ED_TCP_FIN_I2O,
  NAT44_ED_TCP_FIN_O2I,
  NAT44_ED_TCP_RST_TRANS,
  NAT44_ED_TCP_FIN_TRANS,
  NAT44_ED_TCP_FIN_REOPEN_SYN_I2O,
  NAT44_ED_TCP_FIN_REOPEN_SYN_O2I,
} nat44_ed_tcp_state_e;

format_function_t format_nat44_ed_tcp_state;

/* Session flags */
#define SNAT_SESSION_FLAG_STATIC_MAPPING     (1 << 0)
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
#define NAT_SM_FLAG_SELF_TWICE_NAT (1 << 1)
#define NAT_SM_FLAG_TWICE_NAT	   (1 << 2)
#define NAT_SM_FLAG_IDENTITY_NAT   (1 << 3)
#define NAT_SM_FLAG_ADDR_ONLY	   (1 << 4)
#define NAT_SM_FLAG_EXACT_ADDRESS  (1 << 5)
#define NAT_SM_FLAG_OUT2IN_ONLY	   (1 << 6)
#define NAT_SM_FLAG_LB		   (1 << 7)
#define NAT_SM_FLAG_SWITCH_ADDRESS (1 << 8)

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

  ip_protocol_t proto;

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
  nat44_ed_tcp_state_e tcp_state;

  /* per vrf sessions index */
  u32 per_vrf_sessions_index;

  u32 thread_index;
}) snat_session_t;

typedef struct
{
  ip4_address_t addr;
  ip4_address_t net;
  u32 sw_if_index;
  u32 fib_index;
  u32 addr_len;
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
  /* preferred pool address */
  ip4_address_t pool_addr;
  /* local IP address */
  ip4_address_t local_addr;
  /* external IP address */
  ip4_address_t external_addr;
  /* local port */
  u16 local_port;
  /* external port */
  u16 external_port;
  /* local FIB table */
  u32 vrf_id;
  u32 fib_index;
  /* protocol */
  ip_protocol_t proto;
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
  u8 is_resolved;
  ip4_address_t l_addr;
  ip4_address_t pool_addr;
  u16 l_port;
  u16 e_port;
  u32 sw_if_index;
  u32 vrf_id;
  ip_protocol_t proto;
  u32 flags;
  u8 *tag;
} snat_static_mapping_resolve_t;

typedef struct
{
  u8 is_resolved;
  u8 is_twice_nat;
  u32 sw_if_index;
} snat_address_resolve_t;

typedef struct
{
  u32 count;
  u32 sw_if_index;
  ip4_address_t addr;
} snat_fib_entry_reg_t;

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
typedef int (nat_alloc_out_addr_and_port_function_t) (
  snat_address_t *addresses, u32 fib_index, u32 thread_index,
  ip_protocol_t proto, ip4_address_t *addr, u16 *port, u16 port_per_thread,
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
  // broken api backward compatibility
  snat_interface_t *output_feature_dummy_interfaces;

  /* Vector of outside addresses */
  snat_address_t *addresses;
  /* Vector of twice NAT addresses for external hosts */
  snat_address_t *twice_nat_addresses;

  /* first interface address should be auto-added */
  snat_address_resolve_t *addr_to_resolve;

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

  /* vector of fib entries */
  snat_fib_entry_reg_t *fib_entry_reg;

  /* vector of interface address static mappings to resolve. */
  snat_static_mapping_resolve_t *sm_to_resolve;

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
  u32 max_cfg_sessions_gauge; /* Index of max configured sessions gauge in
				 stats */

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
  uword *cached_presence_by_ip4_address;
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
format_function_t format_static_mapping_key;
format_function_t format_nat_addr_and_port_alloc_alg;

/** \brief Check if SNAT session is created from static mapping.
    @param s SNAT session
    @return true if SNAT session is created from static mapping otherwise 0
*/
always_inline bool
nat44_ed_is_session_static (snat_session_t *s)
{
  return s->flags & SNAT_SESSION_FLAG_STATIC_MAPPING;
}

/** \brief Check if NAT session is twice NAT.
    @param s NAT session
    @return true if NAT session is twice NAT
*/
always_inline bool
nat44_ed_is_twice_nat_session (snat_session_t *s)
{
  return s->flags & SNAT_SESSION_FLAG_TWICE_NAT;
}

/** \brief Check if NAT session is load-balancing.
    @param s NAT session
    @return true if NAT session is load-balancing
*/
always_inline bool
nat44_ed_is_lb_session (snat_session_t *s)
{
  return s->flags & SNAT_SESSION_FLAG_LOAD_BALANCING;
}

/** \brief Check if NAT session is forwarding bypass.
    @param s NAT session
    @return true if NAT session is load-balancing
*/
always_inline bool
na44_ed_is_fwd_bypass_session (snat_session_t *s)
{
  return s->flags & SNAT_SESSION_FLAG_FWD_BYPASS;
}

/** \brief Check if NAT session has affinity record.
    @param s NAT session
    @return true if NAT session has affinity record
*/
always_inline bool
nat44_ed_is_affinity_session (snat_session_t *s)
{
  return s->flags & SNAT_SESSION_FLAG_AFFINITY;
}

/** \brief Check if exact pool address should be used.
    @param s SNAT session
    @return true if exact pool address
*/
always_inline bool
nat44_ed_is_exact_address_session (snat_session_t *s)
{
  return s->flags & SNAT_SESSION_FLAG_EXACT_ADDRESS;
}

/** \brief Check if NAT interface is inside.
    @param i NAT interface
    @return true if inside interface
*/
always_inline bool
nat44_ed_is_interface_inside (snat_interface_t *i)
{
  return i->flags & NAT_INTERFACE_FLAG_IS_INSIDE;
}

/** \brief Check if NAT interface is outside.
    @param i NAT interface
    @return true if outside interface
*/
always_inline bool
nat44_ed_is_interface_outside (snat_interface_t *i)
{
  return i->flags & NAT_INTERFACE_FLAG_IS_OUTSIDE;
}

/** \brief Check if client initiating TCP connection (received SYN from client)
    @param t TCP header
    @return true if client initiating TCP connection
*/
always_inline bool
tcp_flags_is_init (u8 f)
{
  return (f & TCP_FLAG_SYN) && !(f & TCP_FLAG_ACK);
}

always_inline bool
is_sm_addr_only (u32 f)
{
  return (f & NAT_SM_FLAG_ADDR_ONLY);
}

always_inline bool
is_sm_out2in_only (u32 f)
{
  return (f & NAT_SM_FLAG_OUT2IN_ONLY);
}

always_inline bool
is_sm_identity_nat (u32 f)
{
  return (f & NAT_SM_FLAG_IDENTITY_NAT);
}

always_inline bool
is_sm_lb (u32 f)
{
  return (f & NAT_SM_FLAG_LB);
}

always_inline bool
is_sm_exact_address (u32 f)
{
  return (f & NAT_SM_FLAG_EXACT_ADDRESS);
}

always_inline bool
is_sm_self_twice_nat (u32 f)
{
  return (f & NAT_SM_FLAG_SELF_TWICE_NAT);
}

always_inline bool
is_sm_twice_nat (u32 f)
{
  return (f & NAT_SM_FLAG_TWICE_NAT);
}

always_inline bool
is_sm_switch_address (u32 f)
{
  return (f & NAT_SM_FLAG_SWITCH_ADDRESS);
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

clib_error_t *nat44_api_hookup (vlib_main_t *vm);

int snat_set_workers (uword *bitmap);

int nat44_plugin_enable (nat44_config_t c);
int nat44_plugin_disable ();

int nat44_ed_add_interface (u32 sw_if_index, u8 is_inside);
int nat44_ed_del_interface (u32 sw_if_index, u8 is_inside);
int nat44_ed_add_output_interface (u32 sw_if_index);
int nat44_ed_del_output_interface (u32 sw_if_index);

int nat44_ed_add_address (ip4_address_t *addr, u32 vrf_id, u8 twice_nat);
int nat44_ed_del_address (ip4_address_t addr, u8 twice_nat);
int nat44_ed_add_interface_address (u32 sw_if_index, u8 twice_nat);
int nat44_ed_del_interface_address (u32 sw_if_index, u8 twice_nat);

int nat44_ed_add_static_mapping (ip4_address_t l_addr, ip4_address_t e_addr,
				 u16 l_port, u16 e_port, ip_protocol_t proto,
				 u32 vrf_id, u32 sw_if_index, u32 flags,
				 ip4_address_t pool_addr, u8 *tag);

int nat44_ed_del_static_mapping (ip4_address_t l_addr, ip4_address_t e_addr,
				 u16 l_port, u16 e_port, ip_protocol_t proto,
				 u32 vrf_id, u32 sw_if_index, u32 flags);

int nat44_ed_add_lb_static_mapping (ip4_address_t e_addr, u16 e_port,
				    ip_protocol_t proto,
				    nat44_lb_addr_port_t *locals, u32 flags,
				    u8 *tag, u32 affinity);

int nat44_ed_del_lb_static_mapping (ip4_address_t e_addr, u16 e_port,
				    ip_protocol_t proto, u32 flags);

int nat44_ed_add_del_lb_static_mapping_local (ip4_address_t e_addr, u16 e_port,
					      ip4_address_t l_addr, u16 l_port,
					      ip_protocol_t proto, u32 vrf_id,
					      u8 probability, u8 is_add);

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
int nat44_ed_del_session (snat_main_t *sm, ip4_address_t *addr, u16 port,
			  ip4_address_t *eh_addr, u16 eh_port, u8 proto,
			  u32 vrf_id, int is_in);

void nat44_ed_free_session_data (snat_main_t *sm, snat_session_t *s,
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
  u32 match_fib_index, ip_protocol_t match_protocol,
  ip4_address_t *mapping_addr, u16 *mapping_port, u32 *mapping_fib_index,
  int by_external, u8 *is_addr_only, twice_nat_type_t *twice_nat,
  lb_nat_type_t *lb, ip4_address_t *ext_host_addr, u8 *is_identity_nat,
  snat_static_mapping_t **out);

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
  NAT_ED_TRNSL_ERR_PACKET_TRUNCATED = 3,
  NAT_ED_TRNSL_ERR_INNER_IP_CORRUPT = 4,
  NAT_ED_TRNSL_ERR_INVALID_CSUM = 5,
} nat_translation_error_e;

nat_translation_error_e nat_6t_flow_buf_translate_i2o (
  vlib_main_t *vm, snat_main_t *sm, vlib_buffer_t *b, ip4_header_t *ip,
  nat_6t_flow_t *f, ip_protocol_t proto, int is_output_feature);

nat_translation_error_e nat_6t_flow_buf_translate_o2i (
  vlib_main_t *vm, snat_main_t *sm, vlib_buffer_t *b, ip4_header_t *ip,
  nat_6t_flow_t *f, ip_protocol_t proto, int is_output_feature);

void nat_6t_l3_l4_csum_calc (nat_6t_flow_t *f);

format_function_t format_nat_ed_translation_error;
format_function_t format_nat_6t_flow;
format_function_t format_ed_session_kvp;

snat_static_mapping_t *nat44_ed_sm_i2o_lookup (snat_main_t *sm,
					       ip4_address_t addr, u16 port,
					       u32 fib_index, u8 proto);

snat_static_mapping_t *nat44_ed_sm_o2i_lookup (snat_main_t *sm,
					       ip4_address_t addr, u16 port,
					       u32 fib_index, u8 proto);

void nat_syslog_nat44_sadd (u32 ssubix, u32 sfibix, ip4_address_t *isaddr,
			    u16 isport, ip4_address_t *idaddr, u16 idport,
			    ip4_address_t *xsaddr, u16 xsport,
			    ip4_address_t *xdaddr, u16 xdport, u8 proto,
			    u8 is_twicenat);

void nat_syslog_nat44_sdel (u32 ssubix, u32 sfibix, ip4_address_t *isaddr,
			    u16 isport, ip4_address_t *idaddr, u16 idport,
			    ip4_address_t *xsaddr, u16 xsport,
			    ip4_address_t *xdaddr, u16 xdport, u8 proto,
			    u8 is_twicenat);

#endif /* __included_nat44_ed_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
