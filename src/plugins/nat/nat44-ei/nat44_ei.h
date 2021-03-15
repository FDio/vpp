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
 * @file nat44_ei.h
 * NAT44 endpoint independent plugin declarations
 */
#ifndef __included_nat44_ei_h__
#define __included_nat44_ei_h__

#include <vlib/log.h>
#include <vlibapi/api.h>

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/api_errno.h>
#include <vnet/fib/fib_source.h>

#include <vppinfra/dlist.h>
#include <vppinfra/error.h>
#include <vppinfra/bihash_8_8.h>

#include <nat/lib/lib.h>
#include <nat/lib/inlines.h>

/* default number of worker handoff frame queue elements */
#define NAT_FQ_NELTS_DEFAULT 64

/* External address and port allocation modes */
#define foreach_nat44_ei_addr_and_port_alloc_alg                              \
  _ (0, DEFAULT, "default")                                                   \
  _ (1, MAPE, "map-e")                                                        \
  _ (2, RANGE, "port-range")

typedef enum
{
#define _(v, N, s) NAT44_EI_ADDR_AND_PORT_ALLOC_ALG_##N = v,
  foreach_nat44_ei_addr_and_port_alloc_alg
#undef _
} nat44_ei_addr_and_port_alloc_alg_t;

/* Interface flags */
#define NAT44_EI_INTERFACE_FLAG_IS_INSIDE  (1 << 0)
#define NAT44_EI_INTERFACE_FLAG_IS_OUTSIDE (1 << 1)

/* Session flags */
#define NAT44_EI_SESSION_FLAG_STATIC_MAPPING (1 << 0)
#define NAT44_EI_SESSION_FLAG_UNKNOWN_PROTO  (1 << 1)

/* Static mapping flags */
#define NAT44_EI_STATIC_MAPPING_FLAG_ADDR_ONLY	  (1 << 0)
#define NAT44_EI_STATIC_MAPPING_FLAG_IDENTITY_NAT (1 << 1)

typedef struct
{
  ip4_address_t addr;
  u32 fib_index;
#define _(N, i, n, s)                                                         \
  u32 busy_##n##_ports;                                                       \
  u32 *busy_##n##_ports_per_thread;                                           \
  u32 busy_##n##_port_refcounts[65535];
  foreach_nat_protocol
#undef _
} nat44_ei_address_t;

clib_error_t *nat44_ei_api_hookup (vlib_main_t *vm);

/* NAT address and port allocation function */
typedef int (nat44_ei_alloc_out_addr_and_port_function_t) (
  nat44_ei_address_t *addresses, u32 fib_index, u32 thread_index,
  nat_protocol_t proto, ip4_address_t s_addr, ip4_address_t *addr, u16 *port,
  u16 port_per_thread, u32 snat_thread_index);

typedef struct
{
  u16 identifier;
  u16 sequence;
} icmp_echo_header_t;

typedef struct
{
  u16 src_port, dst_port;
} tcp_udp_header_t;

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
} nat44_ei_user_key_t;

typedef struct
{
  /* maximum number of users */
  u32 users;
  /* maximum number of sessions */
  u32 sessions;
  /* maximum number of ssessions per user */
  u32 user_sessions;

  /* plugin features */
  u8 static_mapping_only;
  u8 connection_tracking;
  u8 out2in_dpo;

  u32 inside_vrf;
  u32 outside_vrf;

} nat44_ei_config_t;

typedef struct
{
  ip4_address_t l_addr;
  ip4_address_t pool_addr;
  u16 l_port;
  u16 e_port;
  u32 sw_if_index;
  u32 vrf_id;
  u32 flags;
  nat_protocol_t proto;
  u8 addr_only;
  u8 identity_nat;
  u8 exact;
  u8 *tag;
} nat44_ei_static_map_resolve_t;

// TODO: cleanup/redo (there is no lb in EI nat)
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
} nat44_ei_lb_addr_port_t;

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
  /* local FIB table */
  u32 vrf_id;
  u32 fib_index;
  /* protocol */
  nat_protocol_t proto;
  /* worker threads used by backends/local host */
  u32 *workers;
  /* opaque string tag */
  u8 *tag;
  /* backends for load-balancing mode */
  nat44_ei_lb_addr_port_t *locals;
  /* flags */
  u32 flags;
} nat44_ei_static_mapping_t;

typedef struct
{
  u32 sw_if_index;
  u8 flags;
} nat44_ei_interface_t;

typedef struct
{
  u32 fib_index;
  u32 ref_count;
} nat44_ei_fib_t;

typedef struct
{
  u32 fib_index;
  u32 refcount;
} nat44_ei_outside_fib_t;

typedef CLIB_PACKED (struct {
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

  /* Flags */
  u32 flags;

  /* Per-user translations */
  u32 per_user_index;
  u32 per_user_list_head_index;

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

  /* user index */
  u32 user_index;
}) nat44_ei_session_t;

typedef CLIB_PACKED (struct {
  ip4_address_t addr;
  u32 fib_index;
  u32 sessions_per_user_list_head_index;
  u32 nsessions;
  u32 nstaticsessions;
}) nat44_ei_user_t;

typedef struct
{
  /* Find-a-user => src address lookup */
  clib_bihash_8_8_t user_hash;

  /* User pool */
  nat44_ei_user_t *users;

  /* Session pool */
  nat44_ei_session_t *sessions;

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

} nat44_ei_main_per_thread_data_t;

typedef struct
{
  u32 cached_sw_if_index;
  u32 cached_ip4_address;
} nat44_ei_runtime_t;

typedef struct
{
  u32 thread_index;
  f64 now;
} nat44_ei_is_idle_session_ctx_t;

typedef struct nat44_ei_main_s
{
  u32 translations;
  u32 translation_buckets;
  u32 user_buckets;

  u8 out2in_dpo;
  u8 forwarding_enabled;
  u8 static_mapping_only;
  u8 static_mapping_connection_tracking;

  u16 mss_clamping;

  /* Find a static mapping by local */
  clib_bihash_8_8_t static_mapping_by_local;

  /* Find a static mapping by external */
  clib_bihash_8_8_t static_mapping_by_external;

  /* Static mapping pool */
  nat44_ei_static_mapping_t *static_mappings;

  /* Interface pool */
  nat44_ei_interface_t *interfaces;
  nat44_ei_interface_t *output_feature_interfaces;

  /* Is translation memory size calculated or user defined */
  u8 translation_memory_size_set;

  u32 max_users_per_thread;
  u32 max_translations_per_thread;
  u32 max_translations_per_user;

  u32 inside_vrf_id;
  u32 inside_fib_index;

  u32 outside_vrf_id;
  u32 outside_fib_index;

  /* Thread settings */
  u32 num_workers;
  u32 first_worker_index;
  u32 *workers;
  u16 port_per_thread;

  /* Main lookup tables */
  clib_bihash_8_8_t out2in;
  clib_bihash_8_8_t in2out;

  /* Per thread data */
  nat44_ei_main_per_thread_data_t *per_thread_data;

  /* Vector of outside addresses */
  nat44_ei_address_t *addresses;

  nat44_ei_alloc_out_addr_and_port_function_t *alloc_addr_and_port;
  /* Address and port allocation type */
  nat44_ei_addr_and_port_alloc_alg_t addr_and_port_alloc_alg;
  /* Port set parameters (MAP-E) */
  u8 psid_offset;
  u8 psid_length;
  u16 psid;
  /* Port range parameters */
  u16 start_port;
  u16 end_port;

  /* vector of fibs */
  nat44_ei_fib_t *fibs;

  /* vector of outside fibs */
  nat44_ei_outside_fib_t *outside_fibs;

  /* sw_if_indices whose intfc addresses should be auto-added */
  u32 *auto_add_sw_if_indices;

  /* vector of interface address static mappings to resolve. */
  nat44_ei_static_map_resolve_t *to_resolve;

  u32 in2out_node_index;
  u32 out2in_node_index;
  u32 in2out_output_node_index;

  u32 fq_in2out_index;
  u32 fq_in2out_output_index;
  u32 fq_out2in_index;

  /* Randomize port allocation order */
  u32 random_seed;

  nat_timeouts_t timeouts;

  /* counters */
  vlib_simple_counter_main_t total_users;
  vlib_simple_counter_main_t total_sessions;
  vlib_simple_counter_main_t user_limit_reached;

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

  /* pat (port address translation)
   * dynamic mapping enabled or conneciton tracking */
  u8 pat;

  /* number of worker handoff frame queue elements */
  u32 frame_queue_nelts;

  /* nat44 plugin enabled */
  u8 enabled;

  nat44_ei_config_t rconfig;

  u32 in2out_hairpinning_finish_ip4_lookup_node_fq_index;
  u32 in2out_hairpinning_finish_interface_output_node_fq_index;
  u32 hairpinning_fq_index;
  u32 hairpin_dst_fq_index;

  vnet_main_t *vnet_main;
} nat44_ei_main_t;

extern nat44_ei_main_t nat44_ei_main;

int nat44_ei_plugin_enable (nat44_ei_config_t c);

int nat44_ei_plugin_disable ();

/**
 * @brief Delete specific NAT44 EI user and his sessions
 *
 * @param addr         IPv4 address
 * @param fib_index    FIB table index
 */
int nat44_ei_user_del (ip4_address_t *addr, u32 fib_index);

/**
 * @brief Delete session for static mapping
 *
 * @param addr         IPv4 address
 * @param fib_index    FIB table index
 */
void nat44_ei_static_mapping_del_sessions (
  nat44_ei_main_t *nm, nat44_ei_main_per_thread_data_t *tnm,
  nat44_ei_user_key_t u_key, int addr_only, ip4_address_t e_addr, u16 e_port);

u32 nat44_ei_get_in2out_worker_index (ip4_header_t *ip0, u32 rx_fib_index0,
				      u8 is_output);

u32 nat44_ei_get_out2in_worker_index (vlib_buffer_t *b, ip4_header_t *ip0,
				      u32 rx_fib_index0, u8 is_output);

/**
 * @brief Set address and port assignment algorithm to default/standard
 */
void nat44_ei_set_alloc_default (void);

/**
 * @brief Set address and port assignment algorithm for MAP-E CE
 *
 * @param psid        Port Set Identifier value
 * @param psid_offset number of offset bits
 * @param psid_length length of PSID
 */
void nat44_ei_set_alloc_mape (u16 psid, u16 psid_offset, u16 psid_length);

/**
 * @brief Set address and port assignment algorithm for port range
 *
 * @param start_port beginning of the port range
 * @param end_port   end of the port range
 */
void nat44_ei_set_alloc_range (u16 start_port, u16 end_port);

/**
 * @brief Add/delete NAT44-EI static mapping
 *
 * @param l_addr       local IPv4 address
 * @param e_addr       external IPv4 address
 * @param l_port       local port number
 * @param e_port       external port number
 * @param proto        L4 protocol
 * @param sw_if_index  use interface address as external IPv4 address
 * @param vrf_id       local VRF ID
 * @param addr_only    1 = 1:1NAT, 0 = 1:1NAPT
 * @param identity_nat identity NAT
 * @param tag opaque   string tag
 * @param is_add       1 = add, 0 = delete
 *
 * @return 0 on success, non-zero value otherwise

 */
int nat44_ei_add_del_static_mapping (ip4_address_t l_addr,
				     ip4_address_t e_addr, u16 l_port,
				     u16 e_port, nat_protocol_t proto,
				     u32 sw_if_index, u32 vrf_id, u8 addr_only,
				     u8 identity_nat, u8 *tag, u8 is_add);

/**
 * @brief Delete NAT44-EI session
 *
 * @param addr   IPv4 address
 * @param port   L4 port number
 * @param proto  L4 protocol
 * @param vrf_id VRF ID
 * @param is_in  1 = inside network address and port pair, 0 = outside
 *
 * @return 0 on success, non-zero value otherwise
 */
int nat44_ei_del_session (nat44_ei_main_t *nm, ip4_address_t *addr, u16 port,
			  nat_protocol_t proto, u32 vrf_id, int is_in);

/**
 * @brief Match NAT44-EI static mapping.
 *
 * @param key             address and port to match
 * @param addr            external/local address of the matched mapping
 * @param port            port of the matched mapping
 * @param fib_index       fib index of the matched mapping
 * @param by_external     if 0 match by local address otherwise match by
 * external address
 * @param is_addr_only    1 if matched mapping is address only
 * @param is_identity_nat 1 if indentity mapping
 *
 * @returns 0 if match found otherwise 1.
 */
int nat44_ei_static_mapping_match (ip4_address_t match_addr, u16 match_port,
				   u32 match_fib_index,
				   nat_protocol_t match_protocol,
				   ip4_address_t *mapping_addr,
				   u16 *mapping_port, u32 *mapping_fib_index,
				   u8 by_external, u8 *is_addr_only,
				   u8 *is_identity_nat);

/**
 * @brief Clear all active NAT44-EI sessions.
 */
void nat44_ei_sessions_clear ();

nat44_ei_user_t *nat44_ei_user_get_or_create (nat44_ei_main_t *nm,
					      ip4_address_t *addr,
					      u32 fib_index, u32 thread_index);

nat44_ei_session_t *nat44_ei_session_alloc_or_recycle (nat44_ei_main_t *nm,
						       nat44_ei_user_t *u,
						       u32 thread_index,
						       f64 now);

void nat44_ei_free_session_data_v2 (nat44_ei_main_t *nm, nat44_ei_session_t *s,
				    u32 thread_index, u8 is_ha);

void nat44_ei_free_outside_address_and_port (nat44_ei_address_t *addresses,
					     u32 thread_index,
					     ip4_address_t *addr, u16 port,
					     nat_protocol_t protocol);

int nat44_ei_set_outside_address_and_port (nat44_ei_address_t *addresses,
					   u32 thread_index,
					   ip4_address_t addr, u16 port,
					   nat_protocol_t protocol);

int nat44_ei_del_address (nat44_ei_main_t *nm, ip4_address_t addr,
			  u8 delete_sm);

void nat44_ei_free_session_data (nat44_ei_main_t *nm, nat44_ei_session_t *s,
				 u32 thread_index, u8 is_ha);

int nat44_ei_set_workers (uword *bitmap);

void nat44_ei_add_del_address_dpo (ip4_address_t addr, u8 is_add);

int nat44_ei_add_address (nat44_ei_main_t *nm, ip4_address_t *addr,
			  u32 vrf_id);

void nat44_ei_delete_session (nat44_ei_main_t *nm, nat44_ei_session_t *ses,
			      u32 thread_index);

int nat44_ei_interface_add_del (u32 sw_if_index, u8 is_inside, int is_del);

int nat44_ei_interface_add_del_output_feature (u32 sw_if_index, u8 is_inside,
					       int is_del);

int nat44_ei_add_interface_address (nat44_ei_main_t *nm, u32 sw_if_index,
				    int is_del);

/* Call back functions for clib_bihash_add_or_overwrite_stale */
int nat44_i2o_is_idle_session_cb (clib_bihash_kv_8_8_t *kv, void *arg);
int nat44_o2i_is_idle_session_cb (clib_bihash_kv_8_8_t *kv, void *arg);

int nat44_ei_hairpinning (vlib_main_t *vm, vlib_node_runtime_t *node,
			  nat44_ei_main_t *nm, u32 thread_index,
			  vlib_buffer_t *b0, ip4_header_t *ip0,
			  udp_header_t *udp0, tcp_header_t *tcp0, u32 proto0,
			  int do_trace, u32 *required_thread_index);

void nat44_ei_hairpinning_sm_unknown_proto (nat44_ei_main_t *nm,
					    vlib_buffer_t *b,
					    ip4_header_t *ip);

u32 nat44_ei_icmp_hairpinning (nat44_ei_main_t *nm, vlib_buffer_t *b0,
			       u32 thread_index, ip4_header_t *ip0,
			       icmp46_header_t *icmp0,
			       u32 *required_thread_index);

int nat44_ei_set_frame_queue_nelts (u32 frame_queue_nelts);

#define nat44_ei_is_session_static(sp)                                        \
  (sp->flags & NAT44_EI_SESSION_FLAG_STATIC_MAPPING)
#define nat44_ei_is_unk_proto_session(sp)                                     \
  (sp->flags & NAT44_EI_SESSION_FLAG_UNKNOWN_PROTO)

#define nat44_ei_interface_is_inside(ip)                                      \
  (ip->flags & NAT44_EI_INTERFACE_FLAG_IS_INSIDE)
#define nat44_ei_interface_is_outside(ip)                                     \
  (ip->flags & NAT44_EI_INTERFACE_FLAG_IS_OUTSIDE)

#define nat44_ei_is_addr_only_static_mapping(mp)                              \
  (mp->flags & NAT44_EI_STATIC_MAPPING_FLAG_ADDR_ONLY)
#define nat44_ei_is_identity_static_mapping(mp)                               \
  (mp->flags & NAT44_EI_STATIC_MAPPING_FLAG_IDENTITY_NAT)

/* logging */
#define nat44_ei_log_err(...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_ERR, nat44_ei_main.log_class, __VA_ARGS__)
#define nat44_ei_log_warn(...)                                                \
  vlib_log (VLIB_LOG_LEVEL_WARNING, nat44_ei_main.log_class, __VA_ARGS__)
#define nat44_ei_log_notice(...)                                              \
  vlib_log (VLIB_LOG_LEVEL_NOTICE, nat44_ei_main.log_class, __VA_ARGS__)
#define nat44_ei_log_info(...)                                                \
  vlib_log (VLIB_LOG_LEVEL_INFO, nat44_ei_main.log_class, __VA_ARGS__)
#define nat44_ei_log_debug(...)                                               \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, nat44_ei_main.log_class, __VA_ARGS__)

#endif /* __included_nat44_ei_h__ */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
