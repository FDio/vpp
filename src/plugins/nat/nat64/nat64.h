/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#ifndef __included_nat64_h__
#define __included_nat64_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/api_errno.h>
#include <vnet/fib/fib_source.h>
#include <vppinfra/dlist.h>
#include <vppinfra/error.h>
#include <vlibapi/api.h>
#include <vlib/log.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/ip/reass/ip4_sv_reass.h>

#include <nat/lib/lib.h>
#include <nat/lib/nat_inlines.h>

#include <nat/nat64/nat64_db.h>

typedef struct
{
  u16 identifier;
  u16 sequence;
} icmp_echo_header_t;

typedef struct
{
  u16 src_port, dst_port;
} tcp_udp_header_t;

#define foreach_nat64_tcp_ses_state            \
  _(0, CLOSED, "closed")                       \
  _(1, V4_INIT, "v4-init")                     \
  _(2, V6_INIT, "v6-init")                     \
  _(3, ESTABLISHED, "established")             \
  _(4, V4_FIN_RCV, "v4-fin-rcv")               \
  _(5, V6_FIN_RCV, "v6-fin-rcv")               \
  _(6, V6_FIN_V4_FIN_RCV, "v6-fin-v4-fin-rcv") \
  _(7, TRANS, "trans")

typedef enum
{
#define _(v, N, s) NAT64_TCP_STATE_##N = v,
  foreach_nat64_tcp_ses_state
#undef _
} nat64_tcp_ses_state_t;

typedef enum
{
  NAT64_CLEANER_RESCHEDULE = 1,
} nat64_cleaner_process_event_e;

typedef struct
{
  ip6_address_t prefix;
  u8 plen;
  u32 vrf_id;
  u32 fib_index;
} nat64_prefix_t;

typedef struct
{
  ip6_address_t in_addr;
  u16 in_port;
  ip4_address_t out_addr;
  u16 out_port;
  u32 fib_index;
  clib_thread_index_t thread_index;
  u8 proto;
  u8 is_add;
  u8 done;
} nat64_static_bib_to_update_t;

typedef struct
{
  ip4_address_t addr;
  u32 fib_index;
#define _(N, i, n, s) \
  u16 busy_##n##_ports; \
  u16 * busy_##n##_ports_per_thread; \
  u32 busy_##n##_port_refcounts[65535];
  foreach_nat_protocol
#undef _
} nat64_address_t;

typedef struct
{
  u32 sw_if_index;
  u8 flags;
} nat64_interface_t;

typedef struct
{
  u32 enabled;

  nat64_config_t config;

  /* API message ID base */
  u16 msg_id_base;

  /* log class */
  vlib_log_class_t log_class;

  /** Interface pool */
  nat64_interface_t *interfaces;

  /** Address pool vector */
  nat64_address_t *addr_pool;

  /** sw_if_indices whose interface addresses should be auto-added */
  u32 *auto_add_sw_if_indices;

  /** Pref64 vector */
  nat64_prefix_t *pref64;

  /** BIB and session DB per thread */
  nat64_db_t *db;

  /** Worker handoff */
  u32 fq_in2out_index;
  u32 fq_out2in_index;

  /** Pool of static BIB entries to be added/deleted in worker threads */
  nat64_static_bib_to_update_t *static_bibs;

  /** config parameters */
  u32 bib_buckets;
  uword bib_memory_size;
  u32 st_buckets;
  uword st_memory_size;

  /** values of various timeouts */
  u32 udp_timeout;
  u32 icmp_timeout;
  u32 tcp_trans_timeout;
  u32 tcp_est_timeout;

  /* Total count of interfaces enabled */
  u32 total_enabled_count;

  /* Expire walk process node index */
  u32 expire_walk_node_index;

  /* Expire worker walk process node index */
  u32 expire_worker_walk_node_index;

  /* counters/gauges */
  vlib_simple_counter_main_t total_bibs;
  vlib_simple_counter_main_t total_sessions;

  /** node index **/
  u32 error_node_index;

  u32 in2out_node_index;
  u32 in2out_slowpath_node_index;

  u32 out2in_node_index;

#define _(x) vlib_simple_counter_main_t x;
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
  } counters;
#undef _

  /* convenience */
  ip4_main_t *ip4_main;

  /* required */
  vnet_main_t *vnet_main;

  /* Randomize port allocation order */
  u32 random_seed;

  /* TCP MSS clamping */
  u16 mss_clamping;

  fib_source_t fib_src_hi;
  fib_source_t fib_src_low;

  /* Thread settings */
  u32 num_workers;
  u32 first_worker_index;
  u32 *workers;
  u16 port_per_thread;

} nat64_main_t;

extern nat64_main_t nat64_main;
extern vlib_node_registration_t nat64_in2out_node;
extern vlib_node_registration_t nat64_out2in_node;

/**
 * @brief Add/delete address to NAT64 pool.
 *
 * @param thread_index Thread index used by ipfix nat logging (not address per thread).
 * @param addr   IPv4 address.
 * @param vrf_id VRF id of tenant, ~0 means independent of VRF.
 * @param is_add 1 if add, 0 if delete.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_add_del_pool_addr (clib_thread_index_t thread_index,
			     ip4_address_t *addr, u32 vrf_id, u8 is_add);

/**
 * @brief Call back function when walking addresses in NAT64 pool, non-zero
 * return value stop walk.
 */
typedef int (*nat64_pool_addr_walk_fn_t) (nat64_address_t * addr, void *ctx);

/**
 * @brief Walk NAT64 pool.
 *
 * @param fn The function to invoke on each entry visited.
 * @param ctx A context passed in the visit function.
 */
void nat64_pool_addr_walk (nat64_pool_addr_walk_fn_t fn, void *ctx);

/**
 * @brief NAT64 pool address from specific (DHCP addressed) interface.
 *
 * @param sw_if_index Index of the interface.
 * @param is_add      1 if add, 0 if delete.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_add_interface_address (u32 sw_if_index, int is_add);

/**
 * @brief Enable/disable NAT64 feature on the interface.
 *
 * @param sw_if_index Index of the interface.
 * @param is_inside   1 if inside, 0 if outside.
 * @param is_add      1 if add, 0 if delete.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_interface_add_del (u32 sw_if_index, u8 is_inside, u8 is_add);

/**
 * @brief Call back function when walking interfaces with NAT64 feature,
 * non-zero return value stop walk.
 */
typedef int (*nat64_interface_walk_fn_t) (nat64_interface_t * i, void *ctx);

/**
 * @brief Walk NAT64 interfaces.
 *
 * @param fn The function to invoke on each entry visited.
 * @param ctx A context passed in the visit function.
 */
void nat64_interfaces_walk (nat64_interface_walk_fn_t fn, void *ctx);

/**
 * @brief Initialize NAT64.
 *
 * @param vm vlib main.
 *
 * @return error code.
 */
clib_error_t *nat64_init (vlib_main_t * vm);

/**
 * @brief Add/delete static NAT64 BIB entry.
 *
 * @param in_addr  Inside IPv6 address.
 * @param out_addr Outside IPv4 address.
 * @param in_port  Inside port number.
 * @param out_port Outside port number.
 * @param proto    L4 protocol.
 * @param vrf_id   VRF id of tenant.
 * @param is_add   1 if add, 0 if delete.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_add_del_static_bib_entry (ip6_address_t * in_addr,
				    ip4_address_t * out_addr, u16 in_port,
				    u16 out_port, u8 proto, u32 vrf_id,
				    u8 is_add);

/**
 * @brief Alloce IPv4 address and port pair from NAT64 pool.
 *
 * @param fib_index    FIB index of tenant.
 * @param proto        L4 protocol.
 * @param addr         Allocated IPv4 address.
 * @param port         Allocated port number.
 * @param thread_index Thread index.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_alloc_out_addr_and_port (u32 fib_index, nat_protocol_t proto,
				   ip4_address_t *addr, u16 *port,
				   clib_thread_index_t thread_index);

/**
 * @brief Set UDP session timeout.
 *
 * @param timeout Timeout value in seconds (if 0 reset to default value 300sec).
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_set_udp_timeout (u32 timeout);

/**
 * @brief Get UDP session timeout.
 *
 * @returns UDP session timeout in seconds.
 */
u32 nat64_get_udp_timeout (void);

/**
 * @brief Set ICMP session timeout.
 *
 * @param timeout Timeout value in seconds (if 0 reset to default value 60sec).
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_set_icmp_timeout (u32 timeout);

/**
 * @brief Get ICMP session timeout.
 *
 * @returns ICMP session timeout in seconds.
 */
u32 nat64_get_icmp_timeout (void);

/**
 * @brief Set TCP session timeouts.
 *
 * @param trans Transitory timeout in seconds (if 0 reset to default value 240sec).
 * @param est Established timeout in seconds (if 0 reset to default value 7440sec).
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_set_tcp_timeouts (u32 trans, u32 est);

/**
 * @brief Get TCP transitory timeout.
 *
 * @returns TCP transitory timeout in seconds.
 */
u32 nat64_get_tcp_trans_timeout (void);

/**
 * @brief Get TCP established timeout.
 *
 * @returns TCP established timeout in seconds.
 */
u32 nat64_get_tcp_est_timeout (void);

/**
 * @brief Reset NAT64 session timeout.
 *
 * @param ste Session table entry.
 * @param vm VLIB main.
 **/
void nat64_session_reset_timeout (nat64_db_st_entry_t * ste,
				  vlib_main_t * vm);

/**
 * @brief Set NAT64 TCP session state.
 *
 * @param ste Session table entry.
 * @param tcp TCP header.
 * @param is_ip6 1 if IPv6 packet, 0 if IPv4.
 */
void nat64_tcp_session_set_state (nat64_db_st_entry_t * ste,
				  tcp_header_t * tcp, u8 is_ip6);

/**
 * @brief Add/delete NAT64 prefix.
 *
 * @param prefix NAT64 prefix.
 * @param plen Prefix length.
 * @param vrf_id VRF id of tenant.
 * @param is_add 1 if add, 0 if delete.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_add_del_prefix (ip6_address_t * prefix, u8 plen, u32 vrf_id,
			  u8 is_add);

/**
 * @brief Call back function when walking addresses in NAT64 prefixes, non-zero
 * return value stop walk.
 */
typedef int (*nat64_prefix_walk_fn_t) (nat64_prefix_t * pref64, void *ctx);

/**
 * @brief Walk NAT64 prefixes.
 *
 * @param fn The function to invoke on each entry visited.
 * @param ctx A context passed in the visit function.
 */
void nat64_prefix_walk (nat64_prefix_walk_fn_t fn, void *ctx);

/**
 * Compose IPv4-embedded IPv6 addresses.
 * @param ip6 IPv4-embedded IPv6 addresses.
 * @param ip4 IPv4 address.
 * @param fib_index Tenant FIB index.
 */
void nat64_compose_ip6 (ip6_address_t * ip6, ip4_address_t * ip4,
			u32 fib_index);

/**
 * Extract IPv4 address from the IPv4-embedded IPv6 addresses.
 *
 * @param ip6 IPv4-embedded IPv6 addresses.
 * @param ip4 IPv4 address.
 * @param fib_index Tenant FIB index.
 */
void nat64_extract_ip4 (ip6_address_t * ip6, ip4_address_t * ip4,
			u32 fib_index);

/**
 * @brief Set NAT64 hash tables configuration.
 *
 * @param bib_buckets Number of BIB hash buckets.
 * @param bib_memory_size Memory size of BIB hash.
 * @param st_buckets Number of session table hash buckets.
 * @param st_memory_size Memory size of session table hash.
 */
void nat64_set_hash (u32 bib_buckets, uword bib_memory_size, u32 st_buckets,
		     uword st_memory_size);

/**
 * @brief Get worker thread index for NAT64 in2out.
 *
 * @param addr IPv6 src address.
 *
 * @returns worker thread index.
 */
u32 nat64_get_worker_in2out (ip6_address_t * addr);

/**
 * @brief Get worker thread index for NAT64 out2in.
 *
 * @param ip IPv4 header.
 *
 * @returns worker thread index.
 */
u32 nat64_get_worker_out2in (vlib_buffer_t * b, ip4_header_t * ip);

/* NAT64 interface flags */
#define NAT64_INTERFACE_FLAG_IS_INSIDE 1
#define NAT64_INTERFACE_FLAG_IS_OUTSIDE 2

/** \brief Check if NAT64 interface is inside.
    @param i NAT64 interface
    @return 1 if inside interface
*/
#define nat64_interface_is_inside(i) i->flags & NAT64_INTERFACE_FLAG_IS_INSIDE

/** \brief Check if NAT64 interface is outside.
    @param i NAT64 interface
    @return 1 if outside interface
*/
#define nat64_interface_is_outside(i) i->flags & NAT64_INTERFACE_FLAG_IS_OUTSIDE

static_always_inline u8
plugin_enabled ()
{
  nat64_main_t *nm = &nat64_main;
  return nm->enabled;
}

void
nat64_add_del_addr_to_fib (ip4_address_t * addr, u8 p_len, u32 sw_if_index,
			   int is_add);

int nat64_plugin_enable (nat64_config_t c);
int nat64_plugin_disable ();
void nat64_reset_timeouts ();

format_function_t format_nat_protocol;
unformat_function_t unformat_nat_protocol;

/* logging */
#define nat64_log_err(...) \
  vlib_log(VLIB_LOG_LEVEL_ERR, nat64_main.log_class, __VA_ARGS__)
#define nat64_log_warn(...) \
  vlib_log(VLIB_LOG_LEVEL_WARNING, nat64_main.log_class, __VA_ARGS__)
#define nat64_log_notice(...) \
  vlib_log(VLIB_LOG_LEVEL_NOTICE, nat64_main.log_class, __VA_ARGS__)
#define nat64_log_info(...) \
  vlib_log(VLIB_LOG_LEVEL_INFO, nat64_main.log_class, __VA_ARGS__)
#define nat64_log_debug(...)\
  vlib_log(VLIB_LOG_LEVEL_DEBUG, nat64_main.log_class, __VA_ARGS__)

clib_error_t *nat64_api_hookup (vlib_main_t * vm);

#endif /* __included_nat64_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
