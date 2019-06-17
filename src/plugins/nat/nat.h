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
 * @file NAT plugin global declarations
 */
#ifndef __included_nat_h__
#define __included_nat_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/api_errno.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/dlist.h>
#include <vppinfra/error.h>
#include <vlibapi/api.h>
#include <vlib/log.h>

/* default session timeouts */
#define SNAT_UDP_TIMEOUT 300
#define SNAT_TCP_TRANSITORY_TIMEOUT 240
#define SNAT_TCP_ESTABLISHED_TIMEOUT 7440
#define SNAT_ICMP_TIMEOUT 60

/* number of worker handoff frame queue elements */
#define NAT_FQ_NELTS 64

/* NAT buffer flags */
#define SNAT_FLAG_HAIRPINNING (1 << 0)

/* session key (4-tuple) */
typedef struct
{
  union
  {
    struct
    {
      ip4_address_t addr;
      u16 port;
      u16 protocol:3, fib_index:13;
    };
    u64 as_u64;
  };
} snat_session_key_t;

/* endpoint-dependent session key (6-tuple) */
typedef struct
{
  union
  {
    struct
    {
      ip4_address_t l_addr;
      ip4_address_t r_addr;
      u32 proto:8, fib_index:24;
      u16 l_port;
      u16 r_port;
    };
    u64 as_u64[2];
  };
} nat_ed_ses_key_t;

/* deterministic session outside key */
typedef struct
{
  union
  {
    struct
    {
      ip4_address_t ext_host_addr;
      u16 ext_host_port;
      u16 out_port;
    };
    u64 as_u64;
  };
} snat_det_out_key_t;

/* user (internal host) key */
typedef struct
{
  union
  {
    struct
    {
      ip4_address_t addr;
      u32 fib_index;
    };
    u64 as_u64;
  };
} snat_user_key_t;

typedef struct
{
  u32 sw_if_index;
  u32 next_index;
  u8 cached;
} nat44_reass_trace_t;

/* NAT API Configuration flags */
#define foreach_nat_config_flag \
  _(0x01, IS_TWICE_NAT)         \
  _(0x02, IS_SELF_TWICE_NAT)    \
  _(0x04, IS_OUT2IN_ONLY)       \
  _(0x08, IS_ADDR_ONLY)         \
  _(0x10, IS_OUTSIDE)           \
  _(0x20, IS_INSIDE)            \
  _(0x40, IS_STATIC)            \
  _(0x80, IS_EXT_HOST_VALID)    \

typedef enum nat_config_flags_t_
{
#define _(n,f) NAT_API_##f = n,
  foreach_nat_config_flag
#undef _
} nat_config_flags_t;

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


/* Supported L4 protocols */
#define foreach_snat_protocol \
  _(UDP, 0, udp, "udp")       \
  _(TCP, 1, tcp, "tcp")       \
  _(ICMP, 2, icmp, "icmp")

typedef enum
{
#define _(N, i, n, s) SNAT_PROTOCOL_##N = i,
  foreach_snat_protocol
#undef _
} snat_protocol_t;


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

/* Endpoint dependent TCP session state */
#define NAT44_SES_I2O_FIN 1
#define NAT44_SES_O2I_FIN 2
#define NAT44_SES_I2O_FIN_ACK 4
#define NAT44_SES_O2I_FIN_ACK 8
#define NAT44_SES_I2O_SYN 16
#define NAT44_SES_O2I_SYN 32
#define NAT44_SES_RST     64

/* Session flags */
#define SNAT_SESSION_FLAG_STATIC_MAPPING       1
#define SNAT_SESSION_FLAG_UNKNOWN_PROTO        2
#define SNAT_SESSION_FLAG_LOAD_BALANCING       4
#define SNAT_SESSION_FLAG_TWICE_NAT            8
#define SNAT_SESSION_FLAG_ENDPOINT_DEPENDENT   16
#define SNAT_SESSION_FLAG_FWD_BYPASS           32
#define SNAT_SESSION_FLAG_AFFINITY             64
#define SNAT_SESSION_FLAG_OUTPUT_FEATURE       128

/* NAT interface flags */
#define NAT_INTERFACE_FLAG_IS_INSIDE 1
#define NAT_INTERFACE_FLAG_IS_OUTSIDE 2

/* Static mapping flags */
#define NAT_STATIC_MAPPING_FLAG_ADDR_ONLY    1
#define NAT_STATIC_MAPPING_FLAG_OUT2IN_ONLY  2
#define NAT_STATIC_MAPPING_FLAG_IDENTITY_NAT 4
#define NAT_STATIC_MAPPING_FLAG_LB           8

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  /* Outside network key */
  snat_session_key_t out2in;

  /* Inside network key */
  snat_session_key_t in2out;

  /* Flags */
  u32 flags;

  /* Per-user translations */
  u32 per_user_index;
  u32 per_user_list_head_index;

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

  /* user index */
  u32 user_index;
}) snat_session_t;
/* *INDENT-ON* */


typedef struct
{
  ip4_address_t addr;
  u32 fib_index;
  u32 sessions_per_user_list_head_index;
  u32 nsessions;
  u32 nstaticsessions;
} snat_user_t;

typedef struct
{
  ip4_address_t addr;
  u32 fib_index;
/* *INDENT-OFF* */
#define _(N, i, n, s) \
  u16 busy_##n##_ports; \
  u16 * busy_##n##_ports_per_thread; \
  uword * busy_##n##_port_bitmap;
  foreach_snat_protocol
#undef _
/* *INDENT-ON* */
} snat_address_t;

typedef struct
{
  u32 fib_index;
  u32 refcount;
} nat_outside_fib_t;

typedef struct
{
  /* Inside network port */
  u16 in_port;
  /* Outside network address and port */
  snat_det_out_key_t out;
  /* Session state */
  u8 state;
  /* Expire timeout */
  u32 expire;
} snat_det_session_t;

typedef struct
{
  /* inside IP address range */
  ip4_address_t in_addr;
  u8 in_plen;
  /* outside IP address range */
  ip4_address_t out_addr;
  u8 out_plen;
  /* inside IP addresses / outside IP addresses */
  u32 sharing_ratio;
  /* number of ports available to internal host */
  u16 ports_per_host;
  /* session counter */
  u32 ses_num;
  /* vector of sessions */
  snat_det_session_t *sessions;
} snat_det_map_t;

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
  snat_protocol_t proto;
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
  u16 l_port;
  u16 e_port;
  u32 sw_if_index;
  u32 vrf_id;
  snat_protocol_t proto;
  u32 flags;
  int addr_only;
  int twice_nat;
  int is_add;
  int out2in_only;
  int identity_nat;
  u8 *tag;
} snat_static_map_resolve_t;

typedef struct
{
  /* Main lookup tables */
  clib_bihash_8_8_t out2in;
  clib_bihash_8_8_t in2out;

  /* Endpoint dependent sessions lookup tables */
  clib_bihash_16_8_t out2in_ed;
  clib_bihash_16_8_t in2out_ed;

  /* Find-a-user => src address lookup */
  clib_bihash_8_8_t user_hash;

  /* User pool */
  snat_user_t *users;

  /* Session pool */
  snat_session_t *sessions;

  /* Pool of doubly-linked list elements */
  dlist_elt_t *list_pool;

  /* NAT thread index */
  u32 snat_thread_index;
} snat_main_per_thread_data_t;

struct snat_main_s;

/* ICMP session match function */
typedef u32 (snat_icmp_match_function_t) (struct snat_main_s * sm,
					  vlib_node_runtime_t * node,
					  u32 thread_index,
					  vlib_buffer_t * b0,
					  ip4_header_t * ip0, u8 * p_proto,
					  snat_session_key_t * p_value,
					  u8 * p_dont_translate, void *d,
					  void *e);

/* Return worker thread index for given packet */
typedef u32 (snat_get_worker_function_t) (ip4_header_t * ip,
					  u32 rx_fib_index);

/* NAT address and port allacotaion function */
typedef int (nat_alloc_out_addr_and_port_function_t) (snat_address_t *
						      addresses,
						      u32 fib_index,
						      u32 thread_index,
						      snat_session_key_t * k,
						      u16 port_per_thread,
						      u32 snat_thread_index);

typedef struct snat_main_s
{
  /* ICMP session match functions */
  snat_icmp_match_function_t *icmp_match_in2out_cb;
  snat_icmp_match_function_t *icmp_match_out2in_cb;

  /* Thread settings */
  u32 num_workers;
  u32 first_worker_index;
  u32 *workers;
  snat_get_worker_function_t *worker_in2out_cb;
  snat_get_worker_function_t *worker_out2in_cb;
  u16 port_per_thread;
  u32 num_snat_thread;

  /* Per thread data */
  snat_main_per_thread_data_t *per_thread_data;

  /* Find a static mapping by local */
  clib_bihash_8_8_t static_mapping_by_local;

  /* Find a static mapping by external */
  clib_bihash_8_8_t static_mapping_by_external;

  /* Static mapping pool */
  snat_static_mapping_t *static_mappings;

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

  /* vector of outside fibs */
  nat_outside_fib_t *outside_fibs;

  /* Vector of twice NAT addresses for extenal hosts */
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

  /* node indexes */
  u32 error_node_index;

  u32 in2out_node_index;
  u32 in2out_output_node_index;
  u32 in2out_fast_node_index;
  u32 in2out_slowpath_node_index;
  u32 in2out_slowpath_output_node_index;
  u32 in2out_reass_node_index;
  u32 ed_in2out_node_index;
  u32 ed_in2out_slowpath_node_index;
  u32 ed_in2out_reass_node_index;
  u32 out2in_node_index;
  u32 out2in_fast_node_index;
  u32 out2in_reass_node_index;
  u32 ed_out2in_node_index;
  u32 ed_out2in_slowpath_node_index;
  u32 ed_out2in_reass_node_index;
  u32 det_in2out_node_index;
  u32 det_out2in_node_index;

  u32 hairpinning_node_index;
  u32 hairpin_dst_node_index;
  u32 hairpin_src_node_index;
  u32 ed_hairpinning_node_index;
  u32 ed_hairpin_dst_node_index;
  u32 ed_hairpin_src_node_index;


  /* Deterministic NAT mappings */
  snat_det_map_t *det_maps;

  /* If forwarding is enabled */
  u8 forwarding_enabled;

  /* Config parameters */
  u8 static_mapping_only;
  u8 static_mapping_connection_tracking;
  u8 deterministic;
  u8 out2in_dpo;
  u8 endpoint_dependent;
  u32 translation_buckets;
  u32 translation_memory_size;
  u32 max_translations;
  u32 user_buckets;
  u32 user_memory_size;
  u32 max_translations_per_user;
  u32 outside_vrf_id;
  u32 outside_fib_index;
  u32 inside_vrf_id;
  u32 inside_fib_index;

  /* values of various timeouts */
  u32 udp_timeout;
  u32 tcp_established_timeout;
  u32 tcp_transitory_timeout;
  u32 icmp_timeout;

  /* TCP MSS clamping */
  u16 mss_clamping;
  u16 mss_value_net;

  /* counters/gauges */
  vlib_simple_counter_main_t total_users;
  vlib_simple_counter_main_t total_sessions;

  /* API message ID base */
  u16 msg_id_base;

  /* log class */
  vlib_log_class_t log_class;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
  ip4_main_t *ip4_main;
  ip_lookup_main_t *ip4_lookup_main;
  api_main_t *api_main;
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
extern vlib_node_registration_t snat_in2out_node;
extern vlib_node_registration_t snat_in2out_output_node;
extern vlib_node_registration_t snat_out2in_node;
extern vlib_node_registration_t snat_in2out_fast_node;
extern vlib_node_registration_t snat_out2in_fast_node;
extern vlib_node_registration_t snat_in2out_worker_handoff_node;
extern vlib_node_registration_t snat_in2out_output_worker_handoff_node;
extern vlib_node_registration_t snat_out2in_worker_handoff_node;
extern vlib_node_registration_t snat_det_in2out_node;
extern vlib_node_registration_t snat_det_out2in_node;
extern vlib_node_registration_t snat_hairpin_dst_node;
extern vlib_node_registration_t snat_hairpin_src_node;
extern vlib_node_registration_t nat44_ed_in2out_node;
extern vlib_node_registration_t nat44_ed_in2out_output_node;
extern vlib_node_registration_t nat44_ed_out2in_node;
extern vlib_node_registration_t nat44_ed_hairpin_dst_node;
extern vlib_node_registration_t nat44_ed_hairpin_src_node;
extern vlib_node_registration_t nat44_ed_in2out_worker_handoff_node;
extern vlib_node_registration_t nat44_ed_in2out_output_worker_handoff_node;
extern vlib_node_registration_t nat44_ed_out2in_worker_handoff_node;

/* format functions */
format_function_t format_snat_user;
format_function_t format_snat_static_mapping;
format_function_t format_snat_static_map_to_resolve;
format_function_t format_snat_session;
format_function_t format_det_map_ses;
format_function_t format_snat_key;
format_function_t format_static_mapping_key;
format_function_t format_snat_protocol;
format_function_t format_nat_addr_and_port_alloc_alg;
format_function_t format_nat44_reass_trace;
/* unformat functions */
unformat_function_t unformat_snat_protocol;

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

/** \brief Check if NAT interface is inside.
    @param i NAT interfce
    @return 1 if inside interface
*/
#define nat_interface_is_inside(i) i->flags & NAT_INTERFACE_FLAG_IS_INSIDE

/** \brief Check if NAT interface is outside.
    @param i NAT interfce
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

/** \brief Check if client initiating TCP connection (received SYN from client)
    @param t TCP header
    @return 1 if client initiating TCP connection
*/
#define tcp_is_init(t) ((t->flags & TCP_FLAG_SYN) && !(t->flags & TCP_FLAG_ACK))

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

/* ICMP session match functions */
u32 icmp_match_in2out_fast (snat_main_t * sm, vlib_node_runtime_t * node,
			    u32 thread_index, vlib_buffer_t * b0,
			    ip4_header_t * ip0, u8 * p_proto,
			    snat_session_key_t * p_value,
			    u8 * p_dont_translate, void *d, void *e);
u32 icmp_match_in2out_slow (snat_main_t * sm, vlib_node_runtime_t * node,
			    u32 thread_index, vlib_buffer_t * b0,
			    ip4_header_t * ip0, u8 * p_proto,
			    snat_session_key_t * p_value,
			    u8 * p_dont_translate, void *d, void *e);
u32 icmp_match_out2in_fast (snat_main_t * sm, vlib_node_runtime_t * node,
			    u32 thread_index, vlib_buffer_t * b0,
			    ip4_header_t * ip0, u8 * p_proto,
			    snat_session_key_t * p_value,
			    u8 * p_dont_translate, void *d, void *e);
u32 icmp_match_out2in_slow (snat_main_t * sm, vlib_node_runtime_t * node,
			    u32 thread_index, vlib_buffer_t * b0,
			    ip4_header_t * ip0, u8 * p_proto,
			    snat_session_key_t * p_value,
			    u8 * p_dont_translate, void *d, void *e);

/* ICMP deterministic NAT session match functions */
u32 icmp_match_out2in_det (snat_main_t * sm, vlib_node_runtime_t * node,
			   u32 thread_index, vlib_buffer_t * b0,
			   ip4_header_t * ip0, u8 * p_proto,
			   snat_session_key_t * p_value,
			   u8 * p_dont_translate, void *d, void *e);
u32 icmp_match_in2out_det (snat_main_t * sm, vlib_node_runtime_t * node,
			   u32 thread_index, vlib_buffer_t * b0,
			   ip4_header_t * ip0, u8 * p_proto,
			   snat_session_key_t * p_value,
			   u8 * p_dont_translate, void *d, void *e);

/* ICMP endpoint-dependent session match functions */
u32 icmp_match_out2in_ed (snat_main_t * sm, vlib_node_runtime_t * node,
			  u32 thread_index, vlib_buffer_t * b0,
			  ip4_header_t * ip0, u8 * p_proto,
			  snat_session_key_t * p_value,
			  u8 * p_dont_translate, void *d, void *e);
u32 icmp_match_in2out_ed (snat_main_t * sm, vlib_node_runtime_t * node,
			  u32 thread_index, vlib_buffer_t * b0,
			  ip4_header_t * ip0, u8 * p_proto,
			  snat_session_key_t * p_value,
			  u8 * p_dont_translate, void *d, void *e);

u32 icmp_in2out (snat_main_t * sm, vlib_buffer_t * b0, ip4_header_t * ip0,
		 icmp46_header_t * icmp0, u32 sw_if_index0, u32 rx_fib_index0,
		 vlib_node_runtime_t * node, u32 next0, u32 thread_index,
		 void *d, void *e);

u32 icmp_out2in (snat_main_t * sm, vlib_buffer_t * b0, ip4_header_t * ip0,
		 icmp46_header_t * icmp0, u32 sw_if_index0, u32 rx_fib_index0,
		 vlib_node_runtime_t * node, u32 next0, u32 thread_index,
		 void *d, void *e);

/* hairpinning functions */
u32 snat_icmp_hairpinning (snat_main_t * sm, vlib_buffer_t * b0,
			   ip4_header_t * ip0, icmp46_header_t * icmp0,
			   int is_ed);
void nat_hairpinning_sm_unknown_proto (snat_main_t * sm, vlib_buffer_t * b,
				       ip4_header_t * ip);
void nat44_ed_hairpinning_unknown_proto (snat_main_t * sm, vlib_buffer_t * b,
					 ip4_header_t * ip);
int snat_hairpinning (snat_main_t * sm, vlib_buffer_t * b0,
		      ip4_header_t * ip0, udp_header_t * udp0,
		      tcp_header_t * tcp0, u32 proto0, int is_ed);
void nat44_reass_hairpinning (snat_main_t * sm, vlib_buffer_t * b0,
			      ip4_header_t * ip0, u16 sport, u16 dport,
			      u32 proto0, int is_ed);

/* Call back functions for clib_bihash_add_or_overwrite_stale */
int nat44_i2o_ed_is_idle_session_cb (clib_bihash_kv_16_8_t * kv, void *arg);
int nat44_o2i_ed_is_idle_session_cb (clib_bihash_kv_16_8_t * kv, void *arg);
int nat44_i2o_is_idle_session_cb (clib_bihash_kv_8_8_t * kv, void *arg);
int nat44_o2i_is_idle_session_cb (clib_bihash_kv_8_8_t * kv, void *arg);

/**
 * @brief Increment IPv4 address
 */
void increment_v4_address (ip4_address_t * a);

/**
 * @brief Add external address to NAT44 pool
 *
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
 *
 * @return 0 on success, non-zero value otherwise
 */
int snat_add_static_mapping (ip4_address_t l_addr, ip4_address_t e_addr,
			     u16 l_port, u16 e_port, u32 vrf_id,
			     int addr_only, u32 sw_if_index,
			     snat_protocol_t proto, int is_add,
			     twice_nat_type_t twice_nat, u8 out2in_only,
			     u8 * tag, u8 identity_nat);

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
				     snat_protocol_t proto,
				     nat44_lb_addr_port_t * locals, u8 is_add,
				     twice_nat_type_t twice_nat,
				     u8 out2in_only, u8 * tag, u32 affinity);

int nat44_lb_static_mapping_add_del_local (ip4_address_t e_addr, u16 e_port,
					   ip4_address_t l_addr, u16 l_port,
					   snat_protocol_t proto, u32 vrf_id,
					   u8 probability, u8 is_add);

clib_error_t *snat_api_init (vlib_main_t * vm, snat_main_t * sm);

/**
 * @brief Set NAT plugin workers
 *
 * @param bitmap NAT workers bitmap
 *
 * @return 0 on success, non-zero value otherwise
 */
int snat_set_workers (uword * bitmap);

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
 * @brief Add/delete NAT44 pool address from specific interfce
 *
 * @param sw_if_index software index of the interface
 * @param is_del      1 = delete, 0 = add
 * @param twice_nat   1 = twice NAT address for extenal hosts
 *
 * @return 0 on success, non-zero value otherwise
 */
int snat_add_interface_address (snat_main_t * sm, u32 sw_if_index, int is_del,
				u8 twice_nat);

/**
 * @brief Delete NAT44 session
 *
 * @param addr   IPv4 address
 * @param port   L4 port number
 * @param proto  L4 protocol
 * @param vrf_id VRF ID
 * @param is_in  1 = inside network address and port pair, 0 = outside
 *
 * @return 0 on success, non-zero value otherwise
 */
int nat44_del_session (snat_main_t * sm, ip4_address_t * addr, u16 port,
		       snat_protocol_t proto, u32 vrf_id, int is_in);

/**
 * @brief Delete NAT44 endpoint-dependent session
 *
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
 * @brief Free NAT44 session data (lookup keys, external addrres port)
 *
 * @param s            NAT session
 * @param thread_index thread index
 * @param is_ha        is HA event
 */
void nat_free_session_data (snat_main_t * sm, snat_session_t * s,
			    u32 thread_index, u8 is_ha);

/**
 * @brief Find or create NAT user
 *
 * @param addr         IPv4 address
 * @param fib_index    FIB table index
 * @param thread_index thread index
 *
 * @return NAT user data structure on success otherwise zero value
 */
snat_user_t *nat_user_get_or_create (snat_main_t * sm, ip4_address_t * addr,
				     u32 fib_index, u32 thread_index);

/**
 * @brief Allocate new NAT session or recycle last used
 *
 * @param u            NAT user
 * @param thread_index thread index
 *
 * @return session data structure on success otherwise zero value
 */
snat_session_t *nat_session_alloc_or_recycle (snat_main_t * sm,
					      snat_user_t * u,
					      u32 thread_index, f64 now);

/**
 * @brief Allocate NAT endpoint-dependent session
 *
 * @param u            NAT user
 * @param thread_index thread index
 *
 * @return session data structure on success otherwise zero value
 */
snat_session_t *nat_ed_session_alloc (snat_main_t * sm, snat_user_t * u,
				      u32 thread_index, f64 now);

/**
 * @brief Set address and port assignment algorithm for MAP-E CE
 *
 * @param psid        Port Set Identifier value
 * @param psid_offset number of offset bits
 * @param psid_length length of PSID
 */
void nat_set_alloc_addr_and_port_mape (u16 psid, u16 psid_offset,
				       u16 psid_length);

/**
 * @brief Set address and port assignment algorithm for port range
 *
 * @param start_port beginning of the port range
 * @param end_port   end of the port range
 */
void nat_set_alloc_addr_and_port_range (u16 start_port, u16 end_port);

/**
 * @brief Set address and port assignment algorithm to default/standard
 */
void nat_set_alloc_addr_and_port_default (void);

/**
 * @brief Free outside address and port pair
 *
 * @param addresses    vector of outside addresses
 * @param thread_index thread index
 * @param k            address, port and protocol
 */
void snat_free_outside_address_and_port (snat_address_t * addresses,
					 u32 thread_index,
					 snat_session_key_t * k);

/**
 * @brief Alloc outside address and port
 *
 * @param addresses         vector of outside addresses
 * @param fib_index         FIB table index
 * @param thread_index      thread index
 * @param k                 allocated address and port pair
 * @param port_per_thread   number of ports per threead
 * @param snat_thread_index NAT thread index
 *
 * @return 0 on success, non-zero value otherwise
 */
int snat_alloc_outside_address_and_port (snat_address_t * addresses,
					 u32 fib_index,
					 u32 thread_index,
					 snat_session_key_t * k,
					 u16 port_per_thread,
					 u32 snat_thread_index);

/**
 * @brief Match NAT44 static mapping.
 *
 * @param match         address and port to match
 * @param mapping       external/local address and port of the matched mapping
 * @param by_external   if 0 match by local address otherwise match by external
 *                      address
 * @param is_addr_only  1 if matched mapping is address only
 * @param twice_nat     matched mapping is twice NAT type
 * @param lb            1 if matched mapping is load-balanced
 * @param ext_host_addr external host address
 *
 * @returns 0 if match found otherwise 1.
 */
int snat_static_mapping_match (snat_main_t * sm,
			       snat_session_key_t match,
			       snat_session_key_t * mapping,
			       u8 by_external,
			       u8 * is_addr_only,
			       twice_nat_type_t * twice_nat,
			       lb_nat_type_t * lb,
			       ip4_address_t * ext_host_addr,
			       u8 * is_identity_nat);

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

#endif /* __included_nat_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
