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

#ifndef included_flowrouter_h
#define included_flowrouter_h

#include <stdbool.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_template.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include "flow_instructions.h"
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

enum flowrouter_session_state {
  FLOWROUTER_STATE_UNKNOWN = 0,
  FLOWROUTER_STATE_TCP_SYN_SEEN,
  FLOWROUTER_STATE_TCP_SYN_SENT,
  FLOWROUTER_STATE_TCP_ESTABLISHED,
  FLOWROUTER_STATE_TCP_FIN_WAIT,
  FLOWROUTER_STATE_TCP_CLOSE_WAIT,
  FLOWROUTER_STATE_TCP_CLOSED,
  FLOWROUTER_STATE_TCP_LAST_ACK,
};

/* Connection 6-tuple key. 16 octets */
typedef struct {
  union {
    struct {
      ip4_address_t sa;
      ip4_address_t da;
      u32 proto:8, fib_index:24;
      u16 sp;
      u16 dp;
    };
    u64 as_u64[2];
  };
} flowrouter_key_t;

/* FP to SP signal */
typedef struct {
  u32 handle;
  enum flowrouter_session_state state;
  f64 last_heard;
} flowrouter_session_signal_t;

/* SP to FP signal */
typedef struct {
  u32 handle;
  enum flowrouter_session_state state;
  f64 last_heard;
} flowrouter_session_to_dp_signal_t;

/* Session cache entries */
typedef struct {
  flowrouter_key_t k;

  /* What to translate to */
  flow_instructions_t instructions;
  u32 fib_index;
  /* NAT */
  /* Stored in network byte order */
  ip4_address_t post_sa;
  ip4_address_t post_da;
  u16 post_sp;
  u16 post_dp;
  ip_csum_t checksum;
  ip_csum_t l4_checksum;
  u16 tcp_mss;

  /* Writeable by fast-path */
  enum flowrouter_session_state state;
  //  vlib_combined_counter_t counter;
  f64 last_heard;
} flowrouter_session_t;

typedef flowrouter_session_t * flowrouter_session_find_t (flowrouter_key_t *key, u32 *pool_index);
typedef void flowrouter_state_change_t (u32 pool_index);
typedef struct {
  u32 sw_if_index;
  //bool inside;
  u32 punt_node;
  u32 process_node;
  flowrouter_session_find_t *session_find;

  clib_bihash_16_8_t *hash;

} flowrouter_interface_t;

/*
 * Events sent to the NAT slowpath process
 */
typedef enum nat_slowpath_process_event_t_
{
  FLOWROUTER_EVENT_STATE_CHANGE,
} flowrouter_process_event;

//void flowrouter_signal_worker (u32 worker, u32 handle);
//u32 flowrouter_worker_enqueue (u32 sw_if_index, u32 thread_index, flowrouter_session_t *s);
void flowrouter_register_interface (u32 sw_if_index, u32 node_index, flowrouter_session_find_t *f,
				    flowrouter_state_change_t *sf, u32 process_node_index);
flowrouter_session_t *flowrouter_session_create (u8 dbidx, flowrouter_key_t *k,
						 flow_instructions_t instructions,
						 u32 fib_index, ip4_address_t *post_sa, ip4_address_t *post_da,
						 u16 post_sp, u16 post_dp, ip_csum_t checksum,
						 ip_csum_t l4_checksum,
						 u16 tcp_mss, enum flowrouter_session_state state,
						 u32 timer, u32 *session_index);
void flowrouter_hash_key (clib_bihash_kv_16_8_t *kv, ip4_address_t *sa, ip4_address_t *da,
			  u8 proto, u32 fib_index, u16 sp, u16 dp);
//u32 flowrouter_create_table (char *name, u32 max_sessions, bool timer);
//bool flowrouter_session_exists (u8 dbidx, flowrouter_key_t *kv);
//flowrouter_session_t *flowrouter_session_find_index(u8 dbidx, u32 poolidx);
//void flowrouter_session_delete (u8 dbidx, flowrouter_session_t *s);
//void flowrouter_session_delete_index (flowrouter_session_signal_t *sp);
void flowrouter_conntrack_timeouts (u32 tcp_transitory_timeout, u32 tcp_established_timeout);
u8 *format_flowrouter_state (u8 *s, va_list * args);
u8 *format_flowrouter_session (u8 * s, va_list * args);

#endif
