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

static int
test_time_range_main (unformat_input_t * input)
{
  clib_timebase_t _tb, *tb = &_tb;
  clib_timebase_component_t _c, *cp = &_c;
  clib_timebase_range_t *rp = 0;
  clib_timebase_range_t *this_rp;
  unformat_input_t _input2, *input2 = &_input2;
  char *test_range_string;
  f64 sunday_midnight;
  f64 now, then;
  f64 start_time, end_time;
  f64 timezone_offset;

  /* Init time base */
  clib_timebase_init (tb, -5 /* EST */ , CLIB_TIMEBASE_DAYLIGHT_USA);

  /* Set up summer time cache */
  now = clib_timebase_now (tb);

  /* Test it */
  now = clib_timebase_now (tb);

  /* show current time */
  fformat (stdout, "Current time in UTC%f, US daylight time rules:\n",
	   tb->timezone_offset / 3600.0);
  fformat (stdout, "%U", format_clib_timebase_time, now);

  /* Test conversion to component structure */
  clib_timebase_time_to_components (now, cp);
  now = clib_timebase_components_to_time (cp);
  fformat (stdout, " -> %U\n", format_clib_timebase_time, now);

  /*
   * test a few other dates, to verify summer time operation
   * 2011: started sunday 3/13, ended sunday 11/6
   */

  fformat (stdout, "Test daylight time rules:\n");

  clib_memset (cp, 0, sizeof (*cp));

  /* Just before DST starts */
  cp->year = 2011;
  cp->month = 2;
  cp->day = 13;
  cp->hour = 1;
  cp->minute = 59;
  cp->second = 59;
  then = clib_timebase_components_to_time (cp);

  timezone_offset = clib_timebase_summer_offset_fastpath (tb, then);

  fformat (stdout, "%U should not be in DST, and it %s\n",
	   format_clib_timebase_time, then,
	   (timezone_offset != 0.0) ? "is" : "is not");

  /* add two seconds */

  then += 2.0;

  timezone_offset = clib_timebase_summer_offset_fastpath (tb, then);

  fformat (stdout, "%U should be in DST, and it %s\n",
	   format_clib_timebase_time, then,
	   (timezone_offset != 0.0) ? "is" : "is not");

  /* Just before DST ends */
  cp->year = 2011;
  cp->month = 10;
  cp->day = 6;
  cp->hour = 1;
  cp->minute = 59;
  cp->second = 59;
  then = clib_timebase_components_to_time (cp);

  timezone_offset = clib_timebase_summer_offset_fastpath (tb, then);

  fformat (stdout, "%U should be in DST, and it %s\n",
	   format_clib_timebase_time, then,
	   (timezone_offset != 0.0) ? "is" : "is not");

  /* add two seconds. */

  then += 2.0;

  timezone_offset = clib_timebase_summer_offset_fastpath (tb, then);

  fformat (stdout, "%U should not be in DST, and it %s\n",
	   format_clib_timebase_time, then,
	   (timezone_offset != 0.0) ? "is" : "is not");

  /* Back to the future... */
  clib_timebase_time_to_components (now, cp);

  fformat (stdout, "Test time range calculations:\n");

  /* Find previous Sunday midnight */
  sunday_midnight = now = clib_timebase_find_sunday_midnight (now);

  clib_timebase_time_to_components (now, cp);

  fformat (stdout, "Sunday midnight: %U\n", format_clib_timebase_time, now);

  test_range_string = "Mon 11 - 17 Tue 7 - 11 Wed - Fri 8 - 18";

  unformat_init_string (input2, test_range_string,
			strlen (test_range_string));

  if (unformat (input2, "%U", unformat_clib_timebase_range_vector, &rp))
    {
      vec_foreach (this_rp, rp)
      {
	start_time = sunday_midnight + this_rp->start;
	end_time = sunday_midnight + this_rp->end;
	fformat (stdout, "range: %U - %U\n",
		 format_clib_timebase_time, start_time,
		 format_clib_timebase_time, end_time);
      }
      vec_free (rp);
    }
  else
    {
      fformat (stdout, "Time convert fail!\n");
    }

  unformat_free (input2);

  return 0;
}

/*
 * GDB callable function: vl - Return vector length of vector
 */
u32
vl (void *p)
{
  return vec_len (p);
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  clib_mem_init (0, 64ULL << 20);

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
