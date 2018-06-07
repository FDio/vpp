/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_time_range_h
#define included_time_range_h

#include <vppinfra/format.h>
#include <vppinfra/time.h>

typedef struct
{
  /* provides f64 seconds since clib_time_init was called */
  clib_time_t clib_time;
  /* 
   * time in f64 seconds since Thursday 1 Jan 1970 00:00:00 UTC
   * when clib_time_init was called
   */
  f64 time_zero;
  f64 timezone_offset;
  f64 *year_start_times;
} clib_timebase_t;

typedef struct
{
  u32 year, month, day, hour, minute, second, nanosecond;
  /* 0 => Thursday */
  u32 day_name_index;
  f64 fractional_seconds;
} clib_timebase_component_t;

typedef struct
{
  f64 start, end;
} clib_timebase_range_t;

void clib_timebase_init (clib_timebase_t *tb, i32 timezone_offset_in_hours);

void clib_timebase_time_to_components (f64 now, clib_timebase_component_t *cp);

f64 clib_timebase_components_to_time (clib_timebase_component_t *cp);

f64 clib_timebase_find_sunday_midnight (f64 start_time);
f64 clib_timebase_offset_from_sunday (u8 *day);

unformat_function_t unformat_clib_timebase_range_hms;
format_function_t format_clib_timebase_time;

static inline f64 clib_timebase_now (clib_timebase_t *tb)
{
  return tb->time_zero + clib_time_now (&tb->clib_time) + tb->timezone_offset;
}

static inline int clib_timebase_is_leap_year (u32 year)
{
  int rv = 0;

  if ((year %   4) == 0)
    rv = 1;
  if ((year % 100) == 0)
    rv = 0;
  if ((year % 400) == 0)
    rv = 1;
  return rv;
}

#endif /* included_time_range_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

