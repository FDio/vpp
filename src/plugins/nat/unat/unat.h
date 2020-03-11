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

#ifndef included_unat_h
#define included_unat_h

#include <vnet/ip/ip4_packet.h>
#include <vppinfra/bihash_16_8.h>
#include "pool.h"
#include <vppinfra/dlist.h>

typedef enum
{
  UNAT_NEXT_DROP,
  UNAT_NEXT_ICMP_ERROR,
  UNAT_NEXT_FASTPATH,
  UNAT_NEXT_SLOWPATH_I2O,
  UNAT_NEXT_SLOWPATH_O2I,
  UNAT_N_NEXT
} unat_next_t;

typedef enum {
  UNAT_INSTR_NO_TRANSLATE           = 1 << 0,
  UNAT_INSTR_SOURCE_ADDRESS         = 1 << 1,
  UNAT_INSTR_SOURCE_PORT            = 1 << 2,
  UNAT_INSTR_DESTINATION_ADDRESS    = 1 << 3,
  UNAT_INSTR_DESTINATION_PORT       = 1 << 4,
  UNAT_INSTR_TCP_CONN_TRACK         = 1 << 5,
  UNAT_INSTR_TCP_MSS                = 1 << 6,
} unat_instructions_t;

enum unat_session_state {
  UNAT_STATE_UNKNOWN = 0,
  UNAT_STATE_TCP_SYN_SEEN,
  UNAT_STATE_TCP_SYN_SENT,
  UNAT_STATE_TCP_ESTABLISHED,
  UNAT_STATE_TCP_FIN_WAIT,
  UNAT_STATE_TCP_CLOSE_WAIT,
  UNAT_STATE_TCP_CLOSED,
  UNAT_STATE_TCP_LAST_ACK,
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
} __clib_packed unat_key_t;
STATIC_ASSERT_SIZEOF (unat_key_t, 16);

/* Session cache entries */
typedef struct {
  unat_key_t k;

  /* What to translate to */
  unat_instructions_t instructions;
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
  enum unat_session_state state;
  //  vlib_combined_counter_t counter;
} unat_fp_session_t;

typedef struct {
  unat_fp_session_t in2out;
  unat_fp_session_t out2in;
  u32 timer;
  f64 last_heard;
  u32 lru_index;
  f64 last_lru_update;
} unat_session_t;

typedef struct {
  u32 sw_if_index;
  bool in2out;
  clib_bihash_16_8_t *hash;
} unat_interface_t;

typedef enum
{
 UNAT_COUNTER_HANDOFF_SLOWPATH = 0,
 UNAT_COUNTER_HANDOFF_FP,
 UNAT_COUNTER_HANDOFF_DIFFERENT_WORKER_FP,
 UNAT_COUNTER_FASTPATH_FORWARDED,
 UNAT_COUNTER_SLOWPATH_FREED_ALREADY,
 UNAT_COUNTER_SLOWPATH_DELETED,
 UNAT_COUNTER_SLOWPATH_PORT_ALLOC_CONFLICT,
 UNAT_COUNTER_SLOWPATH_CREATED,
 UNAT_COUNTER_SLOWPATH_EXPIRE_VECTOR_MAX,
 UNAT_N_COUNTER
} unat_counter_type_t;

#define foreach_unat_counter_name					\
  _(HANDOFF_SLOWPATH, slowpath, unat/handoff)				\
  _(HANDOFF_FP, fastpath, unat/handoff)		\
  _(HANDOFF_DIFFERENT_WORKER_FP, different_worker_fp, unat/handoff)     \
  _(FASTPATH_FORWARDED, forwarded, unat/fastpath)			\
  _(SLOWPATH_FREED_ALREADY, freedalready, unat/slowpath)		\
  _(SLOWPATH_DELETED, deleted, unat/slowpath)                           \
  _(SLOWPATH_PORT_ALLOC_CONFLICT, portallocconflict, unat/slowpath)     \
  _(SLOWPATH_CREATED, created, unat/slowpath)                           \
  _(SLOWPATH_EXPIRE_VECTOR_MAX, expire_vector_max, unat/slowpath)

typedef struct {
  bool enabled;
  clib_bihash_16_8_t in2out_hash;
  clib_bihash_16_8_t out2in_hash;

  /* Interface pool */
  unat_interface_t *interfaces;
  u32 *interface_by_sw_if_index;

  u32 fast_path_node_index;

  u32 max_sessions;

  u32 default_timeout;
  u32 icmp_timeout;
  u32 udp_timeout;
  u32 tcp_transitory_timeout;
  u32 tcp_established_timeout;

  /* Configuration */
  char *handoff_i2o_node;
  char *handoff_o2i_node;

  /* per-thread data */
  unat_session_t **sessions_per_worker;

  /* LRU session list - head is stale, tail is fresh */
  dlist_elt_t **lru_pool;
  u32 *lru_head_index;

  //u32 **expired_sessions_per_worker;
  u32 *pool_per_thread;

  /* Counters */
  clib_spinlock_t counter_lock;
  vlib_simple_counter_main_t *counters;
} unat_main_t;
extern unat_main_t unat_main;

void unat_register_interface (u32 sw_if_index, u32 node_index, bool in2out, clib_bihash_16_8_t *h);
u8 *format_unat_state (u8 *s, va_list * args);
u8 *format_unat_fp_session (u8 * s, va_list * args);
u8 *format_unat_session (u8 * s, va_list * args);
clib_error_t *unat_enable (vlib_main_t *vm);
void unat_enable_worker (u32 thread_index);

#endif
