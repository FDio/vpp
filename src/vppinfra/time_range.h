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

typedef enum
{
  CLIB_TIMEBASE_DAYLIGHT_NONE = 0,
  CLIB_TIMEBASE_DAYLIGHT_USA,
} clib_timebase_daylight_time_t;

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
  f64 summer_offset;
  clib_timebase_daylight_time_t daylight_time_type;
  f64 cached_year_start;
  f64 cached_year_end;
  f64 cached_summer_start;
  f64 cached_summer_end;
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

void clib_timebase_init (clib_timebase_t * tb, i32 timezone_offset_in_hours,
			 clib_timebase_daylight_time_t daylight_type);

void clib_timebase_time_to_components (f64 now,
				       clib_timebase_component_t * cp);

f64 clib_timebase_components_to_time (clib_timebase_component_t * cp);

f64 clib_timebase_find_sunday_midnight (f64 start_time);
f64 clib_timebase_offset_from_sunday (u8 * day);
f64 clib_timebase_summer_offset (clib_timebase_t * tb, f64 now);

unformat_function_t unformat_clib_timebase_range_hms;
unformat_function_t unformat_clib_timebase_range_vector;

format_function_t format_clib_timebase_time;

static inline f64 clib_timebase_summer_offset_fastpath
  (clib_timebase_t * tb, f64 now)
{
  if (PREDICT_TRUE
      (now >= tb->cached_year_start && now <= tb->cached_year_end))
    {
      if (now >= tb->cached_summer_start && now <= tb->cached_summer_end)
	return tb->summer_offset;
      else
	return 0.0;
    }
  else
    return clib_timebase_summer_offset (tb, now);
}

static inline f64
clib_timebase_now (clib_timebase_t * tb)
{
  f64 now;

  now = tb->time_zero + clib_time_now (&tb->clib_time);
  now += tb->timezone_offset;
  now += clib_timebase_summer_offset_fastpath (tb, now);

  return now;
}

static inline int
clib_timebase_is_leap_year (u32 year)
{
  int rv;

  if (PREDICT_TRUE ((year % 4) != 0))
    return 0;

  rv = 0;

  if ((year % 4) == 0)
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
