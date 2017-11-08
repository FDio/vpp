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
/**
 * @file
 * @brief NAT64 global declarations
 */
#ifndef __included_nat64_h__
#define __included_nat64_h__

#include <nat/nat.h>
#include <nat/nat64_db.h>

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

typedef struct
{
  ip6_address_t prefix;
  u8 plen;
  u32 vrf_id;
  u32 fib_index;
} nat64_prefix_t;

typedef struct
{
  /** Interface pool */
  snat_interface_t *interfaces;

  /** Address pool vector */
  snat_address_t *addr_pool;

  /** sw_if_indices whose interface addresses should be auto-added */
  u32 *auto_add_sw_if_indices;

  /** Pref64 vector */
  nat64_prefix_t *pref64;

  /** BIB and session DB */
  nat64_db_t db;

  /* values of various timeouts */
  u32 udp_timeout;
  u32 icmp_timeout;
  u32 tcp_trans_timeout;
  u32 tcp_est_timeout;
  u32 tcp_incoming_syn_timeout;

  u8 is_disabled;

  ip4_main_t *ip4_main;
  snat_main_t *sm;
} nat64_main_t;

extern nat64_main_t nat64_main;
extern vlib_node_registration_t nat64_in2out_node;
extern vlib_node_registration_t nat64_out2in_node;

/**
 * @brief Add/delete address to NAT64 pool.
 *
 * @param addr   IPv4 address.
 * @param vrf_id VRF id of tenant, ~0 means independent of VRF.
 * @param is_add 1 if add, 0 if delete.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_add_del_pool_addr (ip4_address_t * addr, u32 vrf_id, u8 is_add);

/**
 * @brief Call back function when walking addresses in NAT64 pool, non-zero
 * return value stop walk.
 */
typedef int (*nat64_pool_addr_walk_fn_t) (snat_address_t * addr, void *ctx);

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
int nat64_add_del_interface (u32 sw_if_index, u8 is_inside, u8 is_add);

/**
 * @brief Call back function when walking interfaces with NAT64 feature,
 * non-zero return value stop walk.
 */
typedef int (*nat64_interface_walk_fn_t) (snat_interface_t * i, void *ctx);

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
 * @param fib_index FIB index of tenant.
 * @param proto     L4 protocol.
 * @param addr      Allocated IPv4 address.
 * @param port      Allocated port number.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_alloc_out_addr_and_port (u32 fib_index, snat_protocol_t proto,
				   ip4_address_t * addr, u16 * port);

/**
 * @brief Free IPv4 address and port pair from NAT64 pool.
 *
 * @param addr  IPv4 address to free.
 * @param port  Port number to free.
 * @param proto L4 protocol.
 *
 * @returns 0 on success, non-zero value otherwise.
 */
void nat64_free_out_addr_and_port (ip4_address_t * addr, u16 port,
				   snat_protocol_t proto);

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
 * @param incoming_syn Incoming SYN timeout in seconds (if 0 reset to default value 6sec).
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat64_set_tcp_timeouts (u32 trans, u32 est, u32 incoming_syn);

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
 * @brief Get TCP incoming SYN timeout.
 *
 * @returns TCP incoming SYN timeout in seconds.
 */
u32 nat64_get_tcp_incoming_syn_timeout (void);

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

#define u8_ptr_add(ptr, index) (((u8 *)ptr) + index)
#define u16_net_add(u, val) clib_host_to_net_u16(clib_net_to_host_u16(u) + (val))

#endif /* __included_nat64_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
