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
#include <vppinfra/bitmap.h>

#ifndef _twt
#define _twt(a,b) a##b##_t
#define __twt(a,b) _twt(a,b)
#define TWT(a) __twt(a,TW_SUFFIX)

#define _tw(a,b) a##b
#define __tw(a,b) _tw(a,b)
#define TW(a) __tw(a,TW_SUFFIX)
#endif

/** @file
    @brief TW timer template header file, do not compile directly

Instantiation of tw_timer_template.h generates named structures to
implement specific timer wheel geometries. Choices include: number of
timer wheels (currently, 1 or 2), number of slots per ring (a power of
two), and the number of timers per "object handle".

Internally, user object/timer handles are 32-bit integers, so if one
selects 16 timers/object (4 bits), the resulting timer wheel handle is
limited to 2**28 objects.

Here are the specific settings required to generate a single 2048 slot
wheel which supports 2 timers per object:

    #define TW_TIMER_WHEELS 1
    #define TW_SLOTS_PER_RING 2048
    #define TW_RING_SHIFT 11
    #define TW_RING_MASK (TW_SLOTS_PER_RING -1)
    #define TW_TIMERS_PER_OBJECT 2
    #define LOG2_TW_TIMERS_PER_OBJECT 1
    #define TW_SUFFIX _2t_1w_2048sl

See tw_timer_2t_1w_2048sl.h for a complete
example.

tw_timer_template.h is not intended to be #included directly. Client
codes can include multiple timer geometry header files, although
extreme caution would required to use the TW and TWT macros in such a
case.

API usage example:

Initialize a two-timer, single 2048-slot wheel w/ a 1-second
timer granularity:

    tw_timer_wheel_init_2t_1w_2048sl (&tm->single_wheel,
                                     expired_timer_single_callback,
				      1.0 / * timer interval * / );

Start a timer:

    handle = tw_timer_start_2t_1w_2048sl (&tm->single_wheel, elt_index,
                                          [0 | 1] / * timer id * / ,
                                          expiration_time_in_u32_ticks);

Stop a timer:

    tw_timer_stop_2t_1w_2048sl (&tm->single_wheel, handle);

Expired timer callback:

    static void
    expired_timer_single_callback (u32 * expired_timers)
    {
    	int i;
        u32 pool_index, timer_id;
        tw_timer_test_elt_t *e;
        tw_timer_test_main_t *tm = &tw_timer_test_main;

        for (i = 0; i < vec_len (expired_timers);
            {
            pool_index = expired_timers[i] & 0x7FFFFFFF;
            timer_id = expired_timers[i] >> 31;

            ASSERT (timer_id == 1);

            e = pool_elt_at_index (tm->test_elts, pool_index);

            if (e->expected_to_expire != tm->single_wheel.current_tick)
              {
              	fformat (stdout, "[%d] expired at %d not %d\n",
                         e - tm->test_elts, tm->single_wheel.current_tick,
                         e->expected_to_expire);
              }
         pool_put (tm->test_elts, e);
         }
     }
 */

#if (TW_TIMER_WHEELS != 1 && TW_TIMER_WHEELS != 2 && TW_TIMER_WHEELS != 3)
#error TW_TIMER_WHEELS must be 1, 2 or 3
#endif

typedef struct
{
  /** next, previous pool indices */
  u32 next;
  u32 prev;

  union
  {
    struct
    {
#if (TW_TIMER_WHEELS == 3)
      /** fast ring offset, only valid in the slow ring */
      u16 fast_ring_offset;
      /** slow ring offset, only valid in the glacier ring */
      u16 slow_ring_offset;
#endif
#if (TW_TIMER_WHEELS == 2)
      /** fast ring offset, only valid in the slow ring */
      u16 fast_ring_offset;
      /** slow ring offset, only valid in the glacier ring */
      u16 pad;
#endif
    };

#if (TW_OVERFLOW_VECTOR > 0)
    u64 expiration_time;
#endif
  };

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
  /** Glacier ring ID */
  TW_TIMER_RING_GLACIER,
} tw_ring_index_t;
#endif /* __defined_tw_timer_wheel_slot__ */

typedef CLIB_PACKED (struct
		     {
		     u8 timer_id;
		     u32 pool_index;
		     u32 handle;
		     }) TWT (trace);

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
  u64 current_tick;

  /** first expiration time */
  u64 first_expires_tick;

  /** current wheel indices */
  u32 current_index[TW_TIMER_WHEELS];

  /** wheel arrays */
  tw_timer_wheel_slot_t w[TW_TIMER_WHEELS][TW_SLOTS_PER_RING];

#if TW_OVERFLOW_VECTOR > 0
  tw_timer_wheel_slot_t overflow;
#endif

#if TW_FAST_WHEEL_BITMAP > 0
  /** Fast wheel slot occupancy bitmap */
  uword *fast_slot_bitmap;
#endif

  /** expired timer callback, receives a vector of handles */
  void (*expired_timer_callback) (u32 * expired_timer_handles);

  /** vectors of expired timers */
  u32 *expired_timer_handles;

  /** maximum expirations */
  u32 max_expirations;

  /** current trace index */
#if TW_START_STOP_TRACE_SIZE > 0
  /* Start/stop/expire tracing */
  u32 trace_index;
  u32 trace_wrapped;
    TWT (trace) traces[TW_START_STOP_TRACE_SIZE];
#endif

} TWT (tw_timer_wheel);

u32 TW (tw_timer_start) (TWT (tw_timer_wheel) * tw,
			 u32 pool_index, u32 timer_id, u64 interval);

void TW (tw_timer_stop) (TWT (tw_timer_wheel) * tw, u32 handle);

void TW (tw_timer_wheel_init) (TWT (tw_timer_wheel) * tw,
			       void *expired_timer_callback,
			       f64 timer_interval, u32 max_expirations);

void TW (tw_timer_wheel_free) (TWT (tw_timer_wheel) * tw);

u32 *TW (tw_timer_expire_timers) (TWT (tw_timer_wheel) * tw, f64 now);
u32 *TW (tw_timer_expire_timers_vec) (TWT (tw_timer_wheel) * tw, f64 now,
				      u32 * vec);
#if TW_FAST_WHEEL_BITMAP
u32 TW (tw_timer_first_expires_in_ticks) (TWT (tw_timer_wheel) * tw);
#endif

#if TW_START_STOP_TRACE_SIZE > 0
void TW (tw_search_trace) (TWT (tw_timer_wheel) * tw, u32 handle);
void TW (tw_timer_trace) (TWT (tw_timer_wheel) * tw, u32 timer_id,
			  u32 pool_index, u32 handle);
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
