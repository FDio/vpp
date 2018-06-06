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

static int test_time_range_main (unformat_input_t *input)
{
  clib_timebase_t _tb, *tb = &_tb;
  clib_timebase_component_t _c, *cp = &_c;
  clib_timebase_range_t _r, *rp = &_r;
  unformat_input_t _input2, *input2= &_input2;
  char *test_range_string;
  u8 *start_day, *end_day;
  f64 range_start_time_offset, range_end_time_offset;
  f64 sunday_midnight;
  f64 now; 
  f64 start_time, end_time;

  /* Init time base */
  clib_timebase_init (tb, -5 /* EST */, CLIB_TIMEBASE_DAYLIGHT_USA);

  now = clib_timebase_now (tb);
  now = clib_timebase_now (tb);

  /* show current time */
  fformat (stdout, "%U", format_clib_timebase_time, now);

  /* Test conversion to component structure */

  clib_timebase_time_to_components (now, cp);
  now = clib_timebase_components_to_time (cp);
  fformat (stdout, " -> %U\n", format_clib_timebase_time, now);

  /* Find previous Sunday midnight */
  sunday_midnight = now = clib_timebase_find_sunday_midnight (now);

  clib_timebase_time_to_components (now, cp);

  fformat (stdout, "Sunday midnight: %U\n", format_clib_timebase_time, now);

  test_range_string = "Mon - Fri 8 - 18";

  unformat_init_string (input2, test_range_string, strlen(test_range_string));

  if (unformat (input2, "%s - %s", &start_day, &end_day))
    {
      range_start_time_offset = clib_timebase_offset_from_sunday (start_day);
      range_end_time_offset = clib_timebase_offset_from_sunday (end_day);
    }
  else
    {
      fformat (stdout, "day range convert fail.\n");
    }

  if (unformat (input2, "%U", unformat_clib_timebase_range_hms, rp))
    {
      /* Across the week... */
      for (now=sunday_midnight + range_start_time_offset;
           now <= sunday_midnight + range_end_time_offset;
           now += 86400.0)
        {
          start_time = now + rp->start;
          end_time = now + rp->end;
          fformat (stdout, "range: %U - %U\n",
                   format_clib_timebase_time, start_time,
                   format_clib_timebase_time, end_time);
        }
    }
  else
    {
      fformat (stdout, "Time convert fail!\n");
    }
  
  unformat_free (input2);

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  unformat_init_command_line (&i, argv);
  ret = test_time_range_main (&i);
  unformat_free (&i);

  return ret;
}
#endif /* CLIB_UNIX */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
