/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __vlib_tw_funcs_h__
#define __vlib_tw_funcs_h__

#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>
#define VLIB_TW_TICKS_PER_SECOND 1e5 /* 10 us */

typedef enum
{
  VLIB_TW_EVENT_T_PROCESS_NODE = 1,
  VLIB_TW_EVENT_T_TIMED_EVENT = 2,
  VLIB_TW_EVENT_T_SCHED_NODE = 3,
} vlib_tw_event_type_t;

typedef union
{
  struct
  {
    u32 type : 2; /* vlib_tw_event_type_t */
    u32 index : 30;
  };
  u32 as_u32;
} vlib_tw_event_t;

static_always_inline u32
vlib_tw_timer_start (vlib_main_t *vm, vlib_tw_event_t e, u64 interval)
{
  TWT (tw_timer_wheel) *tw = (TWT (tw_timer_wheel) *) vm->timing_wheel;
  return TW (tw_timer_start) (tw, e.as_u32, 0 /* timer_id */, interval);
}

static_always_inline void
vlib_tw_timer_stop (vlib_main_t *vm, u32 handle)
{
  TWT (tw_timer_wheel) *tw = (TWT (tw_timer_wheel) *) vm->timing_wheel;
  TW (tw_timer_stop) (tw, handle);
}

static_always_inline int
vlib_tw_timer_handle_is_free (vlib_main_t *vm, u32 handle)
{
  TWT (tw_timer_wheel) *tw = (TWT (tw_timer_wheel) *) vm->timing_wheel;
  return TW (tw_timer_handle_is_free) (tw, handle);
}

static_always_inline u32
vlib_tw_timer_first_expires_in_ticks (vlib_main_t *vm)
{
  return TW (tw_timer_first_expires_in_ticks) (
    (TWT (tw_timer_wheel) *) vm->timing_wheel);
}

#endif /* __vlib_tw_funcs_h__ */
