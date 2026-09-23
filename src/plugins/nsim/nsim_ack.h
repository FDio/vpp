/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef __included_nsim_ack_h__
#define __included_nsim_ack_h__

#include <vlib/vlib.h>
#include <vppinfra/bihash_48_8.h>

typedef struct
{
  clib_bihash_kv_48_8_t kv;
  u32 ack_number;
} nsim_ack_info_t;

typedef struct
{
  clib_bihash_kv_48_8_t kv;
  u32 wheel_index;
  u32 ack_number;
} nsim_ack_flow_t;

typedef struct
{
  clib_bihash_48_8_t flows_by_key;
  nsim_ack_flow_t *flows;
  u32 *flow_by_wheel;
  u64 candidates;
  u64 coalesced;
  u64 tracked;
  u32 max_active;
  u8 initialized;
} nsim_ack_state_t;

typedef enum
{
  NSIM_ACK_EMIT_UNTRACKED,
  NSIM_ACK_EMIT_TRACKED,
  NSIM_ACK_REPLACED,
} nsim_ack_action_t;

typedef enum
{
  NSIM_ACK_PARSE_NONE,
  NSIM_ACK_PARSE_BARRIER,
  NSIM_ACK_PARSE_CANDIDATE,
} nsim_ack_parse_result_t;

struct nsim_wheel_;

nsim_ack_state_t *nsim_ack_state_alloc (u32 wheel_size);
void nsim_ack_state_free (nsim_ack_state_t *state);
nsim_ack_parse_result_t nsim_ack_parse (vlib_buffer_t *b, u32 sw_if_index, nsim_ack_info_t *info);
void nsim_ack_barrier (nsim_ack_state_t *state, const nsim_ack_info_t *info);
nsim_ack_action_t nsim_ack_prepare (vlib_main_t *vm, nsim_ack_state_t *state,
				    struct nsim_wheel_ *wheel, const nsim_ack_info_t *info,
				    u32 buffer_index, f64 release_time);
void nsim_ack_track (nsim_ack_state_t *state, const nsim_ack_info_t *info, u32 wheel_index);
void nsim_ack_release (nsim_ack_state_t *state, u32 wheel_index);

static_always_inline uword
nsim_ack_memory_size (const nsim_ack_state_t *state)
{
  return state ? sizeof (*state) + state->flows_by_key.memory_size + vec_mem_size (state->flows) +
		   vec_mem_size (state->flow_by_wheel) :
		 0;
}

#endif /* __included_nsim_ack_h__ */
