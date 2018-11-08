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
  Copyright (c) 2005 Eliot Dresselhaus

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

#include <vppinfra/os.h>
#include <vppinfra/time.h>
#include <vppinfra/format.h>
#include <vppinfra/cpu.h>

#ifdef CLIB_UNIX

#include <math.h>
#include <sys/time.h>
#include <fcntl.h>

/* Not very accurate way of determining cpu clock frequency
   for unix.  Better to use /proc/cpuinfo on linux. */
static f64
estimate_clock_frequency (f64 sample_time)
{
  /* Round to nearest 100KHz. */
  const f64 round_to_units = 100e5;

  f64 time_now, time_start, time_limit, freq;
  u64 ifreq, t[2];

  time_start = time_now = unix_time_now ();
  time_limit = time_now + sample_time;
  t[0] = clib_cpu_time_now ();
  while (time_now < time_limit)
    time_now = unix_time_now ();
  t[1] = clib_cpu_time_now ();

  freq = (t[1] - t[0]) / (time_now - time_start);
  ifreq = flt_round_nearest (freq / round_to_units);
  freq = ifreq * round_to_units;

  return freq;
}

/* Fetch cpu frequency via parseing /proc/cpuinfo.
   Only works for Linux. */
static f64
clock_frequency_from_proc_filesystem (void)
{
  f64 cpu_freq = 1e9;		/* better than 40... */
  f64 ppc_timebase = 0;		/* warnings be gone */
  int fd;
  unformat_input_t input;

/* $$$$ aarch64 kernel doesn't report "cpu MHz" */
#if defined(__aarch64__)
  return 0.0;
#endif

  cpu_freq = 0;
  fd = open ("/proc/cpuinfo", 0);
  if (fd < 0)
    return cpu_freq;

  unformat_init_clib_file (&input, fd);

  ppc_timebase = 0;
  while (unformat_check_input (&input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (&input, "cpu MHz : %f", &cpu_freq))
	cpu_freq *= 1e6;
      else if (unformat (&input, "timebase : %f", &ppc_timebase))
	;
      else
	unformat_skip_line (&input);
    }

  unformat_free (&input);

  close (fd);

  /* Override CPU frequency with time base for PPC. */
  if (ppc_timebase != 0)
    cpu_freq = ppc_timebase;

  return cpu_freq;
}

/* Fetch cpu frequency via reading /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq
   Only works for Linux. */
static f64
clock_frequency_from_sys_filesystem (void)
{
  f64 cpu_freq;
  int fd;
  unformat_input_t input;

  /* Time stamp always runs at max frequency. */
  cpu_freq = 0;
  fd = open ("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq", 0);
  if (fd < 0)
    goto done;

  unformat_init_clib_file (&input, fd);
  unformat (&input, "%f", &cpu_freq);
  cpu_freq *= 1e3;		/* measured in kHz */
  unformat_free (&input);
  close (fd);
done:
  return cpu_freq;
}

f64
os_cpu_clock_frequency (void)
{
#if defined (__aarch64__)
  /* The system counter increments at a fixed frequency. It is distributed
   * to each core which has registers for reading the current counter value
   * as well as the clock frequency. The system counter is not clocked at
   * the same frequency as the core. */
  u64 hz;
  asm volatile ("mrs %0, cntfrq_el0":"=r" (hz));
  return (f64) hz;
#endif
  f64 cpu_freq;

  if (clib_cpu_supports_invariant_tsc ())
    return estimate_clock_frequency (1e-3);

  /* First try /sys version. */
  cpu_freq = clock_frequency_from_sys_filesystem ();
  if (cpu_freq != 0)
    return cpu_freq;

  /* Next try /proc version. */
  cpu_freq = clock_frequency_from_proc_filesystem ();
  if (cpu_freq != 0)
    return cpu_freq;

  /* If /proc/cpuinfo fails (e.g. not running on Linux) fall back to
     gettimeofday based estimated clock frequency. */
  return estimate_clock_frequency (1e-3);
}

#endif /* CLIB_UNIX */

/* Initialize time. */
void
clib_time_init (clib_time_t * c)
{
  clib_memset (c, 0, sizeof (c[0]));
  c->clocks_per_second = os_cpu_clock_frequency ();
  c->seconds_per_clock = 1 / c->clocks_per_second;
  c->log2_clocks_per_second = min_log2_u64 ((u64) c->clocks_per_second);

  /* Initially verify frequency every sec */
  c->log2_clocks_per_frequency_verify = c->log2_clocks_per_second;

  c->last_verify_reference_time = unix_time_now ();
  c->last_cpu_time = clib_cpu_time_now ();
  c->init_cpu_time = c->last_verify_cpu_time = c->last_cpu_time;
}

void
clib_time_verify_frequency (clib_time_t * c)
{
  f64 now_reference = unix_time_now ();
  f64 dtr = now_reference - c->last_verify_reference_time;
  f64 dtr_max;
  u64 dtc = c->last_cpu_time - c->last_verify_cpu_time;
  f64 new_clocks_per_second, delta;
  f64 round_units = 100e5;

  c->last_verify_cpu_time = c->last_cpu_time;
  c->last_verify_reference_time = now_reference;

  /*
   * Is the reported reference interval non-positive,
   * or off by a factor of two - or 8 seconds - whichever is larger?
   * Someone reset the clock behind our back.
   */
  dtr_max = (f64) (2ULL << c->log2_clocks_per_frequency_verify) /
    (f64) (1ULL << c->log2_clocks_per_second);
  dtr_max = dtr_max > 8.0 ? dtr_max : 8.0;

  if (dtr <= 0.0 || dtr > dtr_max)
    {
      c->log2_clocks_per_frequency_verify = c->log2_clocks_per_second;
      return;
    }

  /*
   * Reject large frequency changes, another consequence of
   * system clock changes particularly with old kernels.
   */
  new_clocks_per_second =
    flt_round_nearest ((f64) dtc / (dtr * round_units)) * round_units;

  delta = new_clocks_per_second - c->clocks_per_second;
  if (delta < 0.0)
    delta = -delta;

  if (PREDICT_FALSE ((delta / c->clocks_per_second) > .01))
    {
      clib_warning ("Rejecting large frequency change of %.2f%%",
		    (delta / c->clocks_per_second) * 100.0);
      c->log2_clocks_per_frequency_verify = c->log2_clocks_per_second;
      return;
    }

  c->clocks_per_second =
    flt_round_nearest ((f64) dtc / (dtr * round_units)) * round_units;
  c->seconds_per_clock = 1 / c->clocks_per_second;

  /* Double time between verifies; max at 64 secs ~ 1 minute. */
  if (c->log2_clocks_per_frequency_verify < c->log2_clocks_per_second + 6)
    c->log2_clocks_per_frequency_verify += 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
