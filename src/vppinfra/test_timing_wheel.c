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
#include <vppinfra/bitmap.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/random.h>
#include <vppinfra/time.h>
#include <vppinfra/timing_wheel.h>
#include <vppinfra/zvec.h>

#include <vppinfra/math.h>

#if __GNUC__ < 4
#define SQRT(a) a
#else
#define SQRT(a) sqrt(a)
#endif

typedef struct
{
  uword n_iter;

  u32 n_events;
  u32 seed;
  u32 verbose;

  /* Time is "synthetic" e.g. not taken from CPU timer. */
  u32 synthetic_time;

  clib_time_t time;
  timing_wheel_t timing_wheel;

  u64 *events;

  f64 max_time;
  f64 wait_time;

  f64 total_iterate_time;
  f64 time_iterate_start;

  f64 time_per_status_update;
  f64 time_next_status_update;
} test_timing_wheel_main_t;

typedef struct
{
  f64 dt;
  f64 fraction;
  u64 count;
} test_timing_wheel_tmp_t;

static void
set_event (test_timing_wheel_main_t * tm, uword i)
{
  timing_wheel_t *w = &tm->timing_wheel;
  u64 cpu_time;

  cpu_time = w->current_time_index << w->log2_clocks_per_bin;
  if (tm->synthetic_time)
    cpu_time += random_u32 (&tm->seed) % tm->n_iter;
  else
    cpu_time +=
      random_f64 (&tm->seed) * tm->max_time * tm->time.clocks_per_second;

  timing_wheel_insert (w, cpu_time, i);
  timing_wheel_validate (w);
  tm->events[i] = cpu_time;
}

static int
test_timing_wheel_tmp_cmp (void *a1, void *a2)
{
  test_timing_wheel_tmp_t *f1 = a1;
  test_timing_wheel_tmp_t *f2 = a2;

  return f1->dt < f2->dt ? -1 : (f1->dt > f2->dt ? +1 : 0);
}

clib_error_t *
test_timing_wheel_main (unformat_input_t * input)
{
  clib_error_t *error = 0;
  test_timing_wheel_main_t _tm, *tm = &_tm;
  timing_wheel_t *w = &tm->timing_wheel;
  uword iter, i;

  clib_memset (tm, 0, sizeof (tm[0]));
  tm->n_iter = 10;
  tm->time_per_status_update = 0;
  tm->n_events = 100;
  tm->seed = 1;
  tm->synthetic_time = 1;
  tm->max_time = 1;
  tm->wait_time = 1e-3;

  w->validate = 0;
  w->n_wheel_elt_time_bits = 32;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "iter %wd", &tm->n_iter))
	;
      else if (unformat (input, "events %d", &tm->n_events))
	;
      else
	if (unformat (input, "elt-time-bits %d", &w->n_wheel_elt_time_bits))
	;
      else if (unformat (input, "seed %d", &tm->seed))
	;
      else if (unformat (input, "verbose"))
	tm->verbose = 1;
      else if (unformat (input, "validate"))
	w->validate = 1;

      else if (unformat (input, "real-time"))
	tm->synthetic_time = 0;
      else if (unformat (input, "synthetic-time"))
	tm->synthetic_time = 1;
      else if (unformat (input, "max-time %f", &tm->max_time))
	;
      else if (unformat (input, "wait-time %f", &tm->wait_time))
	;
      else if (unformat (input, "iter-time %f", &tm->total_iterate_time))
	;
      else if (unformat (input, "print %f", &tm->time_per_status_update))
	;

      else
	{
	  error = clib_error_create ("unknown input `%U'\n",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (!tm->seed)
    tm->seed = random_default_seed ();

  clib_time_init (&tm->time);

  if (tm->synthetic_time)
    {
      w->min_sched_time = tm->time.seconds_per_clock;
      w->max_sched_time = w->min_sched_time * 256;
      timing_wheel_init (w, 0, tm->time.clocks_per_second);
    }
  else
    {
      timing_wheel_init (w, clib_cpu_time_now (), tm->time.clocks_per_second);
    }

  clib_warning ("iter %wd, events %d, seed %u, %U",
		tm->n_iter, tm->n_events, tm->seed,
		format_timing_wheel, &tm->timing_wheel, /* verbose */ 0);

  /* Make some events. */
  vec_resize (tm->events, tm->n_events);
  for (i = 0; i < vec_len (tm->events); i++)
    set_event (tm, i);

  {
    u32 *expired = 0;
    f64 ave_error = 0;
    f64 rms_error = 0;
    f64 max_error = 0, min_error = 1e30;
    u32 *error_hist = 0;
    uword n_expired = 0;
    uword *expired_bitmap[2] = { 0 };
    uword n_events_in_wheel = vec_len (tm->events);

    vec_resize (expired, 32);
    vec_resize (error_hist, 1024);

    tm->time_iterate_start = clib_time_now (&tm->time);
    tm->time_next_status_update =
      tm->time_iterate_start + tm->time_per_status_update;

    if (tm->total_iterate_time != 0)
      tm->n_iter = ~0;

    for (iter = 0; iter < tm->n_iter || n_events_in_wheel > 0; iter++)
      {
	u64 cpu_time, min_next_time[2];

	if (tm->synthetic_time)
	  cpu_time = iter << w->log2_clocks_per_bin;
	else
	  cpu_time = clib_cpu_time_now ();

	_vec_len (expired) = 0;
	expired =
	  timing_wheel_advance (w, cpu_time, expired, &min_next_time[0]);
	timing_wheel_validate (w);

	/* Update bitmap of expired events. */
	if (w->validate)
	  {
	    for (i = 0; i < vec_len (tm->events); i++)
	      {
		uword is_expired;

		is_expired =
		  (cpu_time >> w->log2_clocks_per_bin) >=
		  (tm->events[i] >> w->log2_clocks_per_bin);
		expired_bitmap[0] =
		  clib_bitmap_set (expired_bitmap[0], i, is_expired);

		/* Validate min next time. */
		if (is_expired)
		  ASSERT (min_next_time[0] > tm->events[i]);
		else
		  ASSERT (min_next_time[0] <= tm->events[i]);
	      }
	  }

	n_expired += vec_len (expired);
	for (i = 0; i < vec_len (expired); i++)
	  {
	    word j, idt;
	    i64 dt_cpu;
	    f64 fdt_cpu;

	    j = expired[i];
	    expired_bitmap[1] = clib_bitmap_ori (expired_bitmap[1], j);

	    dt_cpu = cpu_time - tm->events[j];

	    /* Event must be scheduled in correct bin. */
	    if (tm->synthetic_time)
	      ASSERT (dt_cpu >= 0 && dt_cpu <= (1 << w->log2_clocks_per_bin));

	    fdt_cpu = dt_cpu * tm->time.seconds_per_clock;

	    ave_error += fdt_cpu;
	    rms_error += fdt_cpu * fdt_cpu;

	    if (fdt_cpu > max_error)
	      max_error = fdt_cpu;
	    if (fdt_cpu < min_error)
	      min_error = fdt_cpu;

	    idt =
	      (cpu_time >> w->log2_clocks_per_bin) -
	      (tm->events[j] >> w->log2_clocks_per_bin);
	    idt = zvec_signed_to_unsigned (idt);
	    vec_validate (error_hist, idt);
	    error_hist[idt] += 1;
	  }

	if (w->validate)
	  for (i = 0; i < vec_len (tm->events); i++)
	    {
	      int is_expired = clib_bitmap_get (expired_bitmap[0], i);
	      int is_expired_w = clib_bitmap_get (expired_bitmap[1], i);
	      ASSERT (is_expired == is_expired_w);
	    }

	min_next_time[1] = ~0;
	for (i = 0; i < vec_len (tm->events); i++)
	  {
	    if (!clib_bitmap_get (expired_bitmap[1], i))
	      min_next_time[1] = clib_min (min_next_time[1], tm->events[i]);
	  }
	if (min_next_time[0] != min_next_time[1])
	  clib_error ("min next time wrong 0x%Lx != 0x%Lx", min_next_time[0],
		      min_next_time[1]);

	if (tm->time_per_status_update != 0
	    && clib_time_now (&tm->time) >= tm->time_next_status_update)
	  {
	    f64 ave = 0, rms = 0;

	    tm->time_next_status_update += tm->time_per_status_update;
	    if (n_expired > 0)
	      {
		ave = ave_error / n_expired;
		rms = SQRT (rms_error / n_expired - ave * ave);
	      }

	    clib_warning
	      ("%12wd iter done %10wd expired; ave. error %.4e +- %.4e, range %.4e %.4e",
	       iter, n_expired, ave, rms, min_error, max_error);
	  }

	if (tm->total_iterate_time != 0
	    && (clib_time_now (&tm->time) - tm->time_iterate_start
		>= tm->total_iterate_time))
	  tm->n_iter = iter;

	/* Add new events to wheel to replace expired ones. */
	n_events_in_wheel -= vec_len (expired);
	if (iter < tm->n_iter)
	  {
	    for (i = 0; i < vec_len (expired); i++)
	      {
		uword j = expired[i];
		set_event (tm, j);
		expired_bitmap[1] =
		  clib_bitmap_andnoti (expired_bitmap[1], j);
	      }
	    n_events_in_wheel += vec_len (expired);
	  }
      }

    ave_error /= n_expired;
    rms_error = SQRT (rms_error / n_expired - ave_error * ave_error);

    clib_warning
      ("%wd iter done %wd expired; ave. error %.4e +- %.4e, range %.4e %.4e",
       1 + iter, n_expired, ave_error, rms_error, min_error, max_error);

    {
      test_timing_wheel_tmp_t *fs, *f;
      f64 total_fraction;

      fs = 0;
      for (i = 0; i < vec_len (error_hist); i++)
	{
	  if (error_hist[i] == 0)
	    continue;
	  vec_add2 (fs, f, 1);
	  f->dt =
	    (((i64) zvec_unsigned_to_signed (i) << w->log2_clocks_per_bin) *
	     tm->time.seconds_per_clock);
	  f->fraction = (f64) error_hist[i] / (f64) n_expired;
	  f->count = error_hist[i];
	}

      vec_sort_with_function (fs, test_timing_wheel_tmp_cmp);

      total_fraction = 0;
      vec_foreach (f, fs)
      {
	total_fraction += f->fraction;
	if (f == fs)
	  fformat (stdout, "%=12s %=16s %=16s %s\n", "Error max", "Fraction",
		   "Total", "Count");
	fformat (stdout, "%12.4e %16.4f%% %16.4f%% %Ld\n", f->dt,
		 f->fraction * 100, total_fraction * 100, f->count);
      }
    }

    clib_warning ("%U", format_timing_wheel, w, /* verbose */ 1);
  }

done:
  return error;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  clib_error_t *error;

  clib_mem_init (0, 64ULL << 20);

  unformat_init_command_line (&i, argv);
  error = test_timing_wheel_main (&i);
  unformat_free (&i);
  if (error)
    {
      clib_error_report (error);
      return 1;
    }
  else
    return 0;
}
#endif /* CLIB_UNIX */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
