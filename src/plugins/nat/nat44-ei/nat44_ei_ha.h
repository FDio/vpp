/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
 * @brief NAT active-passive HA
 */

#ifndef __included_nat_ha_h__
#define __included_nat_ha_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>

/* Call back functions for received HA events on passive/failover */
typedef void (*nat_ha_sadd_cb_t) (ip4_address_t * in_addr, u16 in_port,
				  ip4_address_t * out_addr, u16 out_port,
				  ip4_address_t * eh_addr, u16 eh_port,
				  ip4_address_t * ehn_addr, u16 ehn_port,
				  u8 proto, u32 fib_index, u16 flags,
				  u32 thread_index);
typedef void (*nat_ha_sdel_cb_t) (ip4_address_t * out_addr, u16 out_port,
				  ip4_address_t * eh_addr, u16 eh_port,
				  u8 proto, u32 fib_index, u32 thread_index);
typedef void (*nat_ha_sref_cb_t) (ip4_address_t * out_addr, u16 out_port,
				  ip4_address_t * eh_addr, u16 eh_port,
				  u8 proto, u32 fib_index, u32 total_pkts,
				  u64 total_bytes, u32 thread_index);

/**
 * @brief Enable NAT HA
 */
void nat_ha_enable ();

/**
 * @brief Disable NAT HA
 */
void nat_ha_disable ();

/**
 * @brief Initialize NAT HA
 */
void nat_ha_init (vlib_main_t * vm, u32 num_workers, u32 num_threads);

/**
 * @brief Set HA listener (local settings)
 *
 * @param addr local IP4 address
 * @param port local UDP port number
 * @param path_mtu path MTU between local and failover
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat_ha_set_listener (vlib_main_t *vm, ip4_address_t *addr, u16 port,
			 u32 path_mtu);

/**
 * @brief Get HA listener/local configuration
 */
void nat_ha_get_listener (ip4_address_t * addr, u16 * port, u32 * path_mtu);

/**
 * @brief Set HA failover (remote settings)
 *
 * @param addr failover IP4 address
 * @param port failvoer UDP port number
 * @param session_refresh_interval number of seconds after which to send
 *                                 session counters refresh
 *
 * @returns 0 on success, non-zero value otherwise.
 */
int nat_ha_set_failover (vlib_main_t *vm, ip4_address_t *addr, u16 port,
			 u32 session_refresh_interval);

/**
 * @brief Get HA failover/remote settings
 */
void nat_ha_get_failover (ip4_address_t * addr, u16 * port,
			  u32 * session_refresh_interval);

/**
 * @brief Create session add HA event
 *
 * @param in_addr inside IPv4 address
 * @param in_port inside L4 port number
 * @param out_addr outside IPv4 address
 * @param out_port outside L4 port number
 * @param eh_addr external host IPv4 address
 * @param eh_port external host L4 port number
 * @param ehn_addr external host IPv4 address after translation
 * @param ehn_port external host L4 port number after translation
 * @param proto L4 protocol
 * @param fib_index fib index
 * @param flags session flags
 * @param thread_index thread index
 * @param is_resync 1 if HA resync
 */
void nat_ha_sadd (ip4_address_t * in_addr, u16 in_port,
		  ip4_address_t * out_addr, u16 out_port,
		  ip4_address_t * eh_addr, u16 eh_port,
		  ip4_address_t * ehn_addr, u16 ehn_port, u8 proto,
		  u32 fib_index, u16 flags, u32 thread_index, u8 is_resync);

/**
 * @brief Create session delete HA event
 *
 * @param out_addr outside IPv4 address
 * @param out_port outside L4 port number
 * @param eh_addr external host IPv4 address
 * @param eh_port external host L4 port number
 * @param proto L4 protocol
 * @param fib_index fib index
 * @param session_thread_index index of thread where this session was stored
 */
void nat_ha_sdel (ip4_address_t *out_addr, u16 out_port,
		  ip4_address_t *eh_addr, u16 eh_port, u8 proto, u32 fib_index,
		  u32 session_thread_index);

/**
 * @brief Create session refresh HA event
 *
 * @param out_addr outside IPv4 address
 * @param out_port outside L4 port number
 * @param eh_addr external host IPv4 address
 * @param eh_port external host L4 port number
 * @param proto L4 protocol
 * @param fib_index fib index
 * @param total_pkts total packets processed
 * @param total_bytes total bytes processed
 * @param thread_index thread index
 * @param last_refreshed last session refresh time
 * @param now current time
 */
void nat_ha_sref (ip4_address_t * out_addr, u16 out_port,
		  ip4_address_t * eh_addr, u16 eh_port, u8 proto,
		  u32 fib_index, u32 total_pkts, u64 total_bytes,
		  u32 thread_index, f64 * last_refreshed, f64 now);

/**
 * @brief Flush the current HA data (for testing)
 */
void nat_ha_flush (u8 is_resync);

typedef void (*nat_ha_resync_event_cb_t) (u32 client_index, u32 pid,
					  u32 missed_count);

/**
 * @brief Resync HA (resend existing sessions to new failover)
 */
int nat_ha_resync (u32 client_index, u32 pid,
		   nat_ha_resync_event_cb_t event_callback);

/**
 * @brief Get resync status
 *
 * @param in_resync 1 if resync in progress
 * @param resync_ack_missed number of missed (not ACKed) messages
 */
void nat_ha_get_resync_status (u8 * in_resync, u32 * resync_ack_missed);

#endif /* __included_nat_ha_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
