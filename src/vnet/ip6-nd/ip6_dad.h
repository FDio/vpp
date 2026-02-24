/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco and/or its affiliates.
 */

/**
 * @file
 * @brief IPv6 Duplicate Address Detection (DAD) - RFC 4862
 */

#ifndef __IP6_DAD_H__
#define __IP6_DAD_H__

#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip.h>

/**
 * DAD state for an address
 */
typedef enum ip6_dad_state_e_
{
  IP6_DAD_STATE_IDLE = 0,      /**< No DAD in progress */
  IP6_DAD_STATE_TENTATIVE = 1, /**< Address is tentative, DAD in progress */
  IP6_DAD_STATE_PREFERRED = 2, /**< DAD succeeded, address is usable */
  IP6_DAD_STATE_DUPLICATE = 3, /**< DAD failed, duplicate detected */
} ip6_dad_state_e;

/**
 * DAD entry for a single address undergoing DAD
 */
typedef struct ip6_dad_entry_t_
{
  /** Interface index */
  u32 sw_if_index;

  /** Address being tested */
  ip6_address_t address;

  /** Prefix length */
  u8 address_length;

  /** Current DAD state */
  ip6_dad_state_e state;

  /** Number of NS transmissions configured */
  u8 dad_transmits;

  /** Number of NS already sent */
  u8 dad_count;

  /** Start time of DAD process */
  f64 dad_start_time;

  /** Next transmission time */
  f64 dad_next_send_time;

  /** Retransmit delay in seconds (default 1.0) */
  f64 dad_retransmit_delay;

  /** Pre-built DAD NS buffer */
  vlib_buffer_t *dad_ns_buffer;

} ip6_dad_entry_t;

/**
 * DAD main structure
 */
typedef struct ip6_dad_main_t_
{
  /** Pool of active DAD entries */
  ip6_dad_entry_t *dad_entries;

  /** DAD enabled/disabled */
  bool dad_enabled;

  /** Default number of DAD NS transmissions (RFC 4862: 1) */
  u8 dad_transmits_default;

  /** Default retransmit timer in seconds (RFC 4862: 1.0) */
  f64 dad_retransmit_delay_default;

  /** Logging class */
  vlib_log_class_t log_class;

  /** Node index for process node */
  u32 dad_process_node_index;

} ip6_dad_main_t;

/**
 * Global DAD main
 */
extern ip6_dad_main_t ip6_dad_main;

/**
 * DAD event types
 */
typedef enum ip6_dad_event_e_
{
  IP6_DAD_EVENT_START = 1,	 /**< New DAD started */
  IP6_DAD_EVENT_NA_RECEIVED = 2, /**< NA received (potential conflict) */
  IP6_DAD_EVENT_STOP = 3,	 /**< Stop DAD (address deleted) */
} ip6_dad_event_e;

/**
 * Event data for NA received
 */
typedef struct ip6_dad_na_event_t_
{
  u32 sw_if_index;
  ip6_address_t address;
} ip6_dad_na_event_t;

/**
 * @brief Start DAD for an IPv6 address
 *
 * @param sw_if_index Interface index
 * @param address IPv6 address to test for uniqueness
 * @param address_length Prefix length
 * @return Error if DAD cannot be started
 */
extern clib_error_t *ip6_dad_start (u32 sw_if_index, const ip6_address_t *address,
				    u8 address_length);

/**
 * @brief Called when NA is received (from data plane - worker thread)
 *
 * This function is called from worker threads when a Neighbor Advertisement
 * is received. It uses RPC to notify the main thread.
 *
 * @param sw_if_index Interface where NA was received
 * @param address Target address in the NA
 */
extern void ip6_dad_na_received_dp (u32 sw_if_index, const ip6_address_t *address);

/**
 * @brief Stop DAD for an address (called when address is deleted)
 *
 * @param sw_if_index Interface index
 * @param address IPv6 address
 */
extern void ip6_dad_stop (u32 sw_if_index, const ip6_address_t *address);

/**
 * @brief Enable/disable DAD globally
 *
 * @param enable True to enable, false to disable
 */
extern void ip6_dad_enable_disable (bool enable);

/**
 * @brief Configure DAD parameters
 *
 * @param transmits Number of NS transmissions (1-10)
 * @param delay Retransmit delay in seconds
 * @return Error if parameters are invalid
 */
extern clib_error_t *ip6_dad_config (u8 transmits, f64 delay);

/**
 * @brief Get DAD configuration
 *
 * @param enabled Output: DAD enabled/disabled
 * @param transmits Output: Number of transmissions
 * @param delay Output: Retransmit delay
 */
extern void ip6_dad_get_config (bool *enabled, u8 *transmits, f64 *delay);

/**
 * @brief Format DAD state
 */
extern u8 *format_ip6_dad_state (u8 *s, va_list *args);

/**
 * @brief Format DAD entry
 */
extern u8 *format_ip6_dad_entry (u8 *s, va_list *args);

#endif /* __IP6_DAD_H__ */
