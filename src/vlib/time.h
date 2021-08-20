/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vlib_time_h
#define included_vlib_time_h

#include <vlib/vlib.h>
#include <vppinfra/tw_timer_1t_3w_1024sl_ov.h>

static inline f64
vlib_time_get_next_timer (vlib_main_t *vm)
{
  vlib_node_main_t *nm = &vm->node_main;
  TWT (tw_timer_wheel) *wheel = nm->timing_wheel;
  return TW (tw_timer_first_expires_in_ticks) (wheel) * wheel->timer_interval;
}

static inline void
vlib_time_adjust (vlib_main_t *vm, f64 offset)
{
  vm->time_offset += offset;
}

#endif /* included_vlib_time_h */
