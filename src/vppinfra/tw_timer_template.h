/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef TW_SUFFIX
#error do not include tw_timer_template.h directly
#endif

#include <vppinfra/clib.h>
#include <vppinfra/pool.h>

#ifndef _twt
#define _twt(a,b) a##b##_t
#define __twt(a,b) _twt(a,b)
#define TWT(a) __twt(a,TW_SUFFIX)

#define _tw(a,b) a##b
#define __tw(a,b) _tw(a,b)
#define TW(a) __tw(a,TW_SUFFIX)
#endif

/** @file
 *  @brief TW timer definitions
 */

typedef struct
{
  /** next, previous pool indices */
  u32 next;
  u32 prev;
#if TW_TIMER_WHEELS > 0
  /** fast ring offset, only valid in the slow ring */
  u16 fast_ring_offset;
  u16 pad;
#endif
  /** user timer handle */
  u32 user_handle;
} TWT (tw_timer);

/*
 * These structures ar used by all geometries,
 * so they need a private #include block...
 */
#ifndef __defined_tw_timer_wheel_slot__
#define __defined_tw_timer_wheel_slot__
typedef struct
{
  /** Listhead of timers which expire in this interval */
  u32 head_index;
} tw_timer_wheel_slot_t;
typedef enum
{
  /** Fast timer ring ID */
  TW_TIMER_RING_FAST,
  /** Slow timer ring ID */
  TW_TIMER_RING_SLOW,
} tw_ring_index_t;
#endif /* __defined_tw_timer_wheel_slot__ */

typedef struct
{
  /** Timer pool */
  TWT (tw_timer) * timers;

  /** Next time the wheel should run */
  f64 next_run_time;

  /** Last time the wheel ran */
  f64 last_run_time;

  /** Timer ticks per second */
  f64 ticks_per_second;

  /** Timer interval, also needed to avoid fp divide in speed path */
  f64 timer_interval;

  /** current tick */
  u32 current_tick;

  /** current wheel indices */
  u32 current_index[TW_TIMER_WHEELS];

  /** wheel arrays */
  tw_timer_wheel_slot_t w[TW_TIMER_WHEELS][TW_SLOTS_PER_RING];

  /** expired timer callback, receives a vector of handles */
  void (*expired_timer_callback) (u32 * expired_timer_handles);

  /** vector of expired timers */
  u32 *expired_timer_handles;
} TWT (tw_timer_wheel);

/** start a tw timer */
u32 TW (tw_timer_start) (TWT (tw_timer_wheel) * tw,
			 u32 pool_index, u32 timer_id, u32 interval);

/** Stop a tw timer */
void TW (tw_timer_stop) (TWT (tw_timer_wheel) * tw, u32 handle);

/** Initialize a tw timer wheel */
void TW (tw_timer_wheel_init) (TWT (tw_timer_wheel) * tw,
			       void *expired_timer_callback,
			       f64 timer_interval);

/** free a tw timer wheel */
void TW (tw_timer_wheel_free) (TWT (tw_timer_wheel) * tw);

/** run the tw timer wheel. Call every ms. */
void TW (tw_timer_expire_timers) (TWT (tw_timer_wheel) * tw, f64 now);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
