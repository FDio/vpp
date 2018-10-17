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

#include <vppinfra/time_range.h>

void
clib_timebase_init (clib_timebase_t * tb, i32 timezone_offset_in_hours,
		    clib_timebase_daylight_time_t daylight_type)
{
  clib_memset (tb, 0, sizeof (*tb));

  clib_time_init (&tb->clib_time);
  tb->time_zero = unix_time_now ();

  tb->timezone_offset = ((f64) (timezone_offset_in_hours)) * 3600.0;
  tb->daylight_time_type = daylight_type;
  switch (tb->daylight_time_type)
    {
    case CLIB_TIMEBASE_DAYLIGHT_NONE:
      tb->summer_offset = 0.0;
      break;
    case CLIB_TIMEBASE_DAYLIGHT_USA:
      tb->summer_offset = 3600.0;
      break;
    default:
      clib_warning ("unknown daylight type %d", tb->daylight_time_type);
      tb->daylight_time_type = CLIB_TIMEBASE_DAYLIGHT_NONE;
      tb->summer_offset = 0.0;
    }
}

const static u32 days_per_month[] = {
  31,				/* Jan */
  28,				/* Feb */
  31,				/* Mar */
  30,				/* Apr */
  31,				/* May */
  30,				/* Jun */
  31,				/* Jul */
  31,				/* Aug */
  30,				/* Sep */
  31,				/* Oct */
  30,				/* Nov */
  31,				/* Dec */
};

const static char *month_short_names[] = {
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
};

const static char *day_names_epoch_order[] = {
  "Thu",
  "Fri",
  "Sat",
  "Sun",
  "Mon",
  "Tue",
  "Wed",
};

const static char *day_names_calendar_order[] = {
  "Sun",
  "Mon",
  "Tue",
  "Wed",
  "Thu",
  "Fri",
  "Sat",
};


void
clib_timebase_time_to_components (f64 now, clib_timebase_component_t * cp)
{
  u32 year, month, hours, minutes, seconds, nanoseconds;
  u32 days_in_year, days_in_month, day_of_month;
  u32 days_since_epoch;
  u32 day_name_index;

  /* Unix epoch is 1/1/1970 00:00:00.00, a Thursday */

  year = 1970;
  days_since_epoch = 0;

  do
    {
      days_in_year = clib_timebase_is_leap_year (year) ? 366 : 365;
      days_since_epoch += days_in_year;
      now = now - ((f64) days_in_year) * 86400.0;
      year++;
    }
  while (now > 0.0);

  days_since_epoch -= days_in_year;
  now += ((f64) days_in_year) * 86400;
  year--;

  month = 0;

  do
    {
      days_in_month = days_per_month[month];
      if (month == 1 && clib_timebase_is_leap_year (year))
	days_in_month++;

      days_since_epoch += days_in_month;
      now = now - ((f64) days_in_month) * 86400.0;
      month++;
    }
  while (now > 0.0);

  days_since_epoch -= days_in_month;
  now += ((f64) days_in_month) * 86400;
  month--;

  day_of_month = 1;
  do
    {
      now = now - 86400;
      day_of_month++;
      days_since_epoch++;
    }
  while (now > 0.0);

  day_of_month--;
  days_since_epoch--;
  now += 86400.0;

  day_name_index = days_since_epoch % 7;

  hours = (u32) (now / (3600.0));
  now -= (f64) (hours * 3600);

  minutes = (u32) (now / 60.0);
  now -= (f64) (minutes * 60);

  seconds = (u32) (now);
  now -= (f64) (seconds);

  nanoseconds = (f64) (now * 1e9);

  cp->year = year;
  cp->month = month;
  cp->day = day_of_month;
  cp->day_name_index = day_name_index;
  cp->hour = hours;
  cp->minute = minutes;
  cp->second = seconds;
  cp->nanosecond = nanoseconds;
  cp->fractional_seconds = now;
}

f64
clib_timebase_components_to_time (clib_timebase_component_t * cp)
{
  f64 now = 0;
  u32 year, days_in_year, month, days_in_month;

  year = 1970;

  while (year < cp->year)
    {
      days_in_year = clib_timebase_is_leap_year (year) ? 366 : 365;
      now += ((f64) days_in_year) * 86400.0;
      year++;
    }

  month = 0;

  while (month < cp->month)
    {
      days_in_month = days_per_month[month];
      if (month == 1 && clib_timebase_is_leap_year (year))
	days_in_month++;

      now += ((f64) days_in_month) * 86400.0;
      month++;
    }

  now += ((f64) cp->day - 1) * 86400.0;
  now += ((f64) cp->hour) * 3600.0;
  now += ((f64) cp->minute) * 60.0;
  now += ((f64) cp->second);
  now += ((f64) cp->nanosecond) * 1e-9;

  return (now);
}

f64
clib_timebase_find_sunday_midnight (f64 start_time)
{
  clib_timebase_component_t _c, *cp = &_c;

  clib_timebase_time_to_components (start_time, cp);

  /* back up to midnight */
  cp->hour = cp->minute = cp->second = 0;

  start_time = clib_timebase_components_to_time (cp);

  while (cp->day_name_index != 3 /* sunday */ )
    {
      /* Back up one day */
      start_time -= 86400.0;
      clib_timebase_time_to_components (start_time, cp);
    }
  /* Clean up residual fraction */
  start_time -= cp->fractional_seconds;
  start_time += 1e-6;		/* 1us inside Sunday  */

  return (start_time);
}

f64
clib_timebase_offset_from_sunday (u8 * day)
{
  int i;

  for (i = 0; i < ARRAY_LEN (day_names_calendar_order); i++)
    {
      if (!strncmp ((char *) day, day_names_calendar_order[i], 3))
	return ((f64) i) * 86400.0;
    }
  return 0.0;
}


u8 *
format_clib_timebase_time (u8 * s, va_list * args)
{
  f64 now = va_arg (*args, f64);
  clib_timebase_component_t _c, *cp = &_c;

  clib_timebase_time_to_components (now, cp);

  s = format (s, "%s, %u %s %u %u:%02u:%02u",
	      day_names_epoch_order[cp->day_name_index],
	      cp->day,
	      month_short_names[cp->month],
	      cp->year, cp->hour, cp->minute, cp->second);
  return (s);
}

uword
unformat_clib_timebase_range_hms (unformat_input_t * input, va_list * args)
{
  clib_timebase_range_t *rp = va_arg (*args, clib_timebase_range_t *);
  clib_timebase_component_t _c, *cp = &_c;
  u32 start_hour, start_minute, start_second;
  u32 end_hour, end_minute, end_second;

  start_hour = start_minute = start_second
    = end_hour = end_minute = end_second = 0;

  if (unformat (input, "%u:%u:%u - %u:%u:%u",
		&start_hour, &start_minute, &start_second,
		&end_hour, &end_minute, &end_second))
    ;
  else if (unformat (input, "%u:%u - %u:%u",
		     &start_hour, &start_minute, &end_hour, &end_minute))
    ;
  else if (unformat (input, "%u - %u", &start_hour, &end_hour))
    ;
  else
    return 0;

  clib_timebase_time_to_components (1e-6, cp);

  cp->hour = start_hour;
  cp->minute = start_minute;
  cp->second = start_second;

  rp->start = clib_timebase_components_to_time (cp);

  cp->hour = end_hour;
  cp->minute = end_minute;
  cp->second = end_second;

  rp->end = clib_timebase_components_to_time (cp);

  return 1;
}

uword
unformat_clib_timebase_range_vector (unformat_input_t * input, va_list * args)
{
  clib_timebase_range_t **rpp = va_arg (*args, clib_timebase_range_t **);
  clib_timebase_range_t _tmp, *tmp = &_tmp;
  clib_timebase_range_t *rp, *new_rp;
  int day_range_match = 0;
  int time_range_match = 0;
  f64 range_start_time_offset;
  f64 range_end_time_offset;
  f64 now;
  u8 *start_day = 0, *end_day = 0;

  rp = *rpp;

  while (1)
    {
      if (!day_range_match
	  && unformat (input, "%s - %s", &start_day, &end_day))
	{
	  range_start_time_offset
	    = clib_timebase_offset_from_sunday (start_day);
	  range_end_time_offset = clib_timebase_offset_from_sunday (end_day);
	  vec_free (start_day);
	  vec_free (end_day);
	  day_range_match = 1;
	  time_range_match = 0;
	}
      else if (!day_range_match && unformat (input, "%s", &start_day))
	{
	  range_start_time_offset
	    = clib_timebase_offset_from_sunday (start_day);
	  range_end_time_offset = range_start_time_offset + 86399.0;
	  day_range_match = 1;
	  vec_free (start_day);
	  day_range_match = 1;
	  time_range_match = 0;
	}
      else if (day_range_match &&
	       unformat (input, "%U", unformat_clib_timebase_range_hms, tmp))
	{
	  /* Across the week... */
	  for (now = range_start_time_offset; now <= range_end_time_offset;
	       now += 86400.0)
	    {
	      vec_add2 (rp, new_rp, 1);
	      new_rp->start = now + tmp->start;
	      new_rp->end = now + tmp->end;
	    }
	  day_range_match = 0;
	  time_range_match = 1;
	}
      else if (time_range_match)
	break;
      else
	{
	  vec_free (rp);
	  *rpp = 0;
	  return 0;
	}
    }

  if (time_range_match)
    {
      *rpp = rp;
      return 1;
    }
  else
    {
      vec_free (rp);
      *rpp = 0;
      return 0;
    }
}

f64
clib_timebase_summer_offset (clib_timebase_t * tb, f64 now)
{
  clib_timebase_component_t _c, *cp = &_c;
  f64 second_sunday_march_2am;
  f64 first_sunday_november_2am;

  if (PREDICT_TRUE
      (now >= tb->cached_year_start && now <= tb->cached_year_end))
    {
      if (now >= tb->cached_summer_start && now <= tb->cached_summer_end)
	return tb->summer_offset;
      else
	return (0.0);
    }

  clib_timebase_time_to_components (now, cp);

  cp->month = 0;
  cp->day = 1;
  cp->hour = 0;
  cp->minute = 0;
  cp->second = 1;

  tb->cached_year_start = clib_timebase_components_to_time (cp);

  cp->year += 1;

  tb->cached_year_end = clib_timebase_components_to_time (cp);

  cp->year -= 1;

  /* Search for the second sunday in march, 2am */
  cp->month = 2;
  cp->day = 1;
  cp->hour = 2;
  cp->second = 0;
  cp->nanosecond = 1;

  /* March 1st will never be the second sunday... */
  second_sunday_march_2am = clib_timebase_components_to_time (cp);
  cp->day_name_index = 0;

  /* Find the first sunday */
  do
    {
      clib_timebase_time_to_components (second_sunday_march_2am, cp);
      second_sunday_march_2am += 86400.0;
    }
  while (cp->day_name_index != 3 /* sunday */ );

  /* Find the second sunday */
  do
    {
      clib_timebase_time_to_components (second_sunday_march_2am, cp);
      second_sunday_march_2am += 86400.0;
    }
  while (cp->day_name_index != 3 /* sunday */ );

  second_sunday_march_2am -= 86400.0;

  tb->cached_summer_start = second_sunday_march_2am;

  /* Find the first sunday in November, which can easily be 11/1 */
  cp->month = 10;
  cp->day = 1;

  first_sunday_november_2am = clib_timebase_components_to_time (cp);
  clib_timebase_time_to_components (first_sunday_november_2am, cp);

  while (cp->day_name_index != 3 /* sunday */ )
    {
      first_sunday_november_2am += 86400.0;
      clib_timebase_time_to_components (first_sunday_november_2am, cp);
    }

  tb->cached_summer_end = first_sunday_november_2am;

  if (now >= tb->cached_summer_start && now <= tb->cached_summer_end)
    return tb->summer_offset;
  else
    return (0.0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
