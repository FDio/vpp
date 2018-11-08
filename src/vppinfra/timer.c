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
/*
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>

#include <vppinfra/vec.h>
#include <vppinfra/smp.h>
#include <vppinfra/time.h>
#include <vppinfra/timer.h>
#include <vppinfra/error.h>

#ifndef HZ
#define HZ 1000
#endif

typedef struct
{
  f64 time;
  timer_func_t *func;
  any arg;
} timer_callback_t;

/* Vector of currently unexpired timers. */
static timer_callback_t *timers;

/* Convert time from 64bit floating format to struct timeval. */
always_inline void
f64_to_tv (f64 t, struct timeval *tv)
{
  tv->tv_sec = t;
  tv->tv_usec = 1e6 * (t - tv->tv_sec);
  while (tv->tv_usec >= 1000000)
    {
      tv->tv_usec -= 1000000;
      tv->tv_sec += 1;
    }
}

/* Sort timers so that timer soonest to expire is at end. */
static int
timer_compare (const void *_a, const void *_b)
{
  const timer_callback_t *a = _a;
  const timer_callback_t *b = _b;
  f64 dt = b->time - a->time;
  return dt < 0 ? -1 : (dt > 0 ? +1 : 0);
}

static inline void
sort_timers (timer_callback_t * timers)
{
  qsort (timers, vec_len (timers), sizeof (timers[0]), timer_compare);
}

#define TIMER_SIGNAL SIGALRM

/* Don't bother set timer if time different is less than this value. */
/* We would like to initialize this to 0.75 / (f64) HZ,
 * but HZ may not be a compile-time constant on some systems,
 * so instead we do the initialization before first use.
 */
static f64 time_resolution;

/* Interrupt handler.  Call functions for all expired timers.
   Set time for next timer interrupt. */
static void
timer_interrupt (int signum)
{
  f64 now = unix_time_now ();
  f64 dt;
  timer_callback_t *t;

  while (1)
    {
      if (vec_len (timers) <= 0)
	return;

      /* Consider last (earliest) timer in reverse sorted
         vector of pending timers. */
      t = vec_end (timers) - 1;

      ASSERT (now >= 0 && isfinite (now));

      /* Time difference between when timer goes off and now. */
      dt = t->time - now;

      /* If timer is within threshold of going off
         call user's callback. */
      if (dt <= time_resolution && isfinite (dt))
	{
	  _vec_len (timers) -= 1;
	  (*t->func) (t->arg, -dt);
	}
      else
	{
	  /* Set timer for to go off in future. */
	  struct itimerval itv;
	  memset (&itv, 0, sizeof (itv));
	  f64_to_tv (dt, &itv.it_value);
	  if (setitimer (ITIMER_REAL, &itv, 0) < 0)
	    clib_unix_error ("sititmer");
	  return;
	}
    }
}

void
timer_block (sigset_t * save)
{
  sigset_t block_timer;

  memset (&block_timer, 0, sizeof (block_timer));
  sigaddset (&block_timer, TIMER_SIGNAL);
  sigprocmask (SIG_BLOCK, &block_timer, save);
}

void
timer_unblock (sigset_t * save)
{
  sigprocmask (SIG_SETMASK, save, 0);
}

/* Arrange for function to be called some time,
   roughly equal to dt seconds, in the future. */
void
timer_call (timer_func_t * func, any arg, f64 dt)
{
  timer_callback_t *t;
  sigset_t save;

  /* Install signal handler on first call. */
  static word signal_installed = 0;

  if (!signal_installed)
    {
      struct sigaction sa;

      /* Initialize time_resolution before first call to timer_interrupt */
      time_resolution = 0.75 / (f64) HZ;

      memset (&sa, 0, sizeof (sa));
      sa.sa_handler = timer_interrupt;

      if (sigaction (TIMER_SIGNAL, &sa, 0) < 0)
	clib_panic ("sigaction");

      signal_installed = 1;
    }

  timer_block (&save);

  /* Add new timer. */
  vec_add2 (timers, t, 1);

  t->time = unix_time_now () + dt;
  t->func = func;
  t->arg = arg;

  {
    word reset_timer = vec_len (timers) == 1;

    if (_vec_len (timers) > 1)
      {
	reset_timer += t->time < (t - 1)->time;
	sort_timers (timers);
      }

    if (reset_timer)
      timer_interrupt (TIMER_SIGNAL);
  }

  timer_unblock (&save);
}

#ifdef TEST

#include <vppinfra/random.h>

/* Compute average delay of function calls to foo.
   If this is a small number over a lot of iterations we know
   the code is working. */

static f64 ave_delay = 0;
static word ave_delay_count = 0;

always_inline
update (f64 delay)
{
  ave_delay += delay;
  ave_delay_count += 1;
}

typedef struct
{
  f64 time_requested, time_called;
} foo_t;

static f64 foo_base_time = 0;
static foo_t *foos = 0;

void
foo (any arg, f64 delay)
{
  foos[arg].time_called = unix_time_now () - foo_base_time;
  update (delay);
}

typedef struct
{
  word count;
  word limit;
} bar_t;

void
bar (any arg, f64 delay)
{
  bar_t *b = (bar_t *) arg;

  fformat (stdout, "bar %d delay %g\n", b->count++, delay);

  update (delay);
  if (b->count < b->limit)
    timer_call (bar, arg, random_f64 ());
}

int
main (int argc, char *argv[])
{
  word i, n = atoi (argv[1]);
  word run_foo = argc > 2;
bar_t b = { limit:10 };

  if (run_foo)
    {
      f64 time_limit;

      time_limit = atof (argv[2]);

      vec_resize (foos, n);
      for (i = 0; i < n; i++)
	{
	  foos[i].time_requested = time_limit * random_f64 ();
	  foos[i].time_called = 1e100;
	}

      foo_base_time = unix_time_now ();
      for (i = 0; i < n; i++)
	timer_call (foo, i, foos[i].time_requested);
    }
  else
    timer_call (bar, (any) & b, random_f64 ());

  while (vec_len (timers) > 0)
    os_sched_yield ();

  if (vec_len (foos) > 0)
    {
      f64 min = 1e100, max = -min;
      f64 ave = 0, rms = 0;

      for (i = 0; i < n; i++)
	{
	  f64 dt = foos[i].time_requested - foos[i].time_called;
	  if (dt < min)
	    min = dt;
	  if (dt > max)
	    max = dt;
	  ave += dt;
	  rms += dt * dt;
	}
      ave /= n;
      rms = sqrt (rms / n - ave * ave);
      fformat (stdout, "error min %g max %g ave %g +- %g\n", min, max, ave,
	       rms);
    }

  fformat (stdout, "%d function calls, ave. timer delay %g secs\n",
	   ave_delay_count, ave_delay / ave_delay_count);

  return 0;
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
