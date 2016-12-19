/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#ifndef included_clib_timing_wheel_h
#define included_clib_timing_wheel_h

#include <vppinfra/format.h>

typedef struct
{
  /* Time of this element in units cpu clock ticks relative to time
     base. 32 bits should be large enough for serveral kilo-seconds
     to elapse before we have to re-set time base. */
  u32 cpu_time_relative_to_base;

  /* User data to store in this bin. */
  u32 user_data;
} timing_wheel_elt_t;

/* Overflow wheel elements where time does not fit into 32 bits. */
typedef struct
{
  /* Absolute time of this element. */
  u64 cpu_time;

  /* User data to store in this bin. */
  u32 user_data;

  u32 pad;
} timing_wheel_overflow_elt_t;

typedef struct
{
  /* 2^M bits: 1 means vector is non-zero else zero. */
  uword *occupancy_bitmap;

  /* 2^M element table of element vectors, one for each time bin. */
  timing_wheel_elt_t **elts;
} timing_wheel_level_t;

typedef struct
{
  /* Vector of refill counts per level. */
  u64 *refills;

  /* Number of times cpu time base was rescaled. */
  u64 cpu_time_base_advances;
} timing_wheel_stats_t;

typedef struct
{
  /* Each bin is a power of two clock ticks (N)
     chosen so that 2^N >= min_sched_time. */
  u8 log2_clocks_per_bin;

  /* Wheels are 2^M bins where 2^(N+M) >= max_sched_time. */
  u8 log2_bins_per_wheel;

  /* N + M. */
  u8 log2_clocks_per_wheel;

  /* Number of bits to use in cpu_time_relative_to_base field
     of timing_wheel_elt_t. */
  u8 n_wheel_elt_time_bits;

  /* 2^M. */
  u32 bins_per_wheel;

  /* 2^M - 1. */
  u32 bins_per_wheel_mask;

  timing_wheel_level_t *levels;

  timing_wheel_overflow_elt_t *overflow_pool;

  /* Free list of element vector so we can recycle old allocated vectors. */
  timing_wheel_elt_t **free_elt_vectors;

  timing_wheel_elt_t *unexpired_elts_pending_insert;

  /* Hash table of user data values which have been deleted but not yet re-inserted. */
  uword *deleted_user_data_hash;

  /* Enable validation for debugging. */
  u32 validate;

  /* Time index.  Measures time in units of 2^N clock ticks from
     when wheel starts. */
  u64 current_time_index;

  /* All times are 32 bit numbers relative to cpu_time_base.
     So, roughly every 2^(32 + N) clocks we'll need to subtract from
     all timing_wheel_elt_t times to make sure they never overflow. */
  u64 cpu_time_base;

  /* When current_time_index is >= this we update cpu_time_base
     to avoid overflowing 32 bit cpu_time_relative_to_base
     in timing_wheel_elt_t. */
  u64 time_index_next_cpu_time_base_update;

  /* Cached earliest element on wheel; 0 if not valid. */
  u64 cached_min_cpu_time_on_wheel;

  f64 min_sched_time, max_sched_time, cpu_clocks_per_second;

  timing_wheel_stats_t stats;
} timing_wheel_t;

/* Initialization function. */
void timing_wheel_init (timing_wheel_t * w,
			u64 current_cpu_time, f64 cpu_clocks_per_second);

/* Insert user data on wheel at given CPU time stamp. */
void timing_wheel_insert (timing_wheel_t * w, u64 insert_cpu_time,
			  u32 user_data);

/* Delete user data from wheel (until it is again inserted). */
void timing_wheel_delete (timing_wheel_t * w, u32 user_data);

/* Advance wheel and return any expired user data in vector.  If non-zero
   min_next_expiring_element_cpu_time will return a cpu time stamp
   before which there are guaranteed to be no elements in the current wheel. */
u32 *timing_wheel_advance (timing_wheel_t * w, u64 advance_cpu_time,
			   u32 * expired_user_data,
			   u64 * min_next_expiring_element_cpu_time);

/* Returns absolute time in clock cycles of next expiring element. */
u64 timing_wheel_next_expiring_elt_time (timing_wheel_t * w);

/* Format a timing wheel. */
format_function_t format_timing_wheel;

/* Testing function to validate wheel. */
void timing_wheel_validate (timing_wheel_t * w);

#endif /* included_clib_timing_wheel_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
