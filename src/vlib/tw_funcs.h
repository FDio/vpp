/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */

#ifndef __vlib_tw_funcs_h__
#define __vlib_tw_funcs_h__

#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>
#include <vlib/tw.h>

static_always_inline u32
vlib_tw_timer_start (vlib_main_t *vm, vlib_tw_event_t e, u64 interval)
{
  TWT (tw_timer_wheel) *tw = (TWT (tw_timer_wheel) *) vm->timing_wheel;
  vm->n_tw_timers++;
  return TW (tw_timer_start) (tw, e.as_u32, 0 /* timer_id */, interval);
}

static_always_inline void
vlib_tw_timer_stop (vlib_main_t *vm, u32 handle)
{
  TWT (tw_timer_wheel) *tw = (TWT (tw_timer_wheel) *) vm->timing_wheel;
  ASSERT (vm->n_tw_timers > 0);
  vm->n_tw_timers--;
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

static_always_inline void
vlib_tw_init (vlib_main_t *vm)
{
  TWT (tw_timer_wheel) *tw = (TWT (tw_timer_wheel) *) vm->timing_wheel;
  tw = clib_mem_alloc_aligned (sizeof (TWT (tw_timer_wheel)),
			       CLIB_CACHE_LINE_BYTES);
  /* Create the process timing wheel */
  TW (tw_timer_wheel_init)
  (tw, 0 /* callback */, 1 / VLIB_TW_TICKS_PER_SECOND,
   ~0 /* max expirations per call */);
  vm->timing_wheel = tw;
  vm->n_tw_timers = 0;
}

static_always_inline u32 *
vlib_tw_timer_expire_timers (vlib_main_t *vm, u32 *v)
{
  TWT (tw_timer_wheel) *tw = (TWT (tw_timer_wheel) *) vm->timing_wheel;

  vec_reset_length (v);

  if (vm->n_tw_timers > 0)
    {
      v = TW (tw_timer_expire_timers_vec) (tw, vlib_time_now (vm), v);
      ASSERT (vec_len (v) <= vm->n_tw_timers);
      vm->n_tw_timers -= vec_len (v);
    }

  return v;
}

#endif /* __vlib_tw_funcs_h__ */
