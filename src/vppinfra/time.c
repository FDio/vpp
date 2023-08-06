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
#include <math.h>

#ifdef CLIB_UNIX

#include <math.h>
#include <sys/time.h>
#include <fcntl.h>

/* Not very accurate way of determining cpu clock frequency
   for unix.  Better to use /proc/cpuinfo on linux. */
static f64
estimate_clock_frequency (f64 sample_time)
{
  f64 time_now, time_start, time_limit, freq;
  u64 t[2];

  time_start = time_now = unix_time_now ();
  time_limit = time_now + sample_time;
  t[0] = clib_cpu_time_now ();
  while (time_now < time_limit)
    time_now = unix_time_now ();
  t[1] = clib_cpu_time_now ();

  freq = (t[1] - t[0]) / (time_now - time_start);

  return freq;
}

/* Fetch cpu frequency via parseing /proc/cpuinfo.
   Only works for Linux. */
static f64
clock_frequency_from_proc_filesystem (void)
{
  f64 cpu_freq = 1e9;		/* better than 40... */
  f64 ppc_timebase = 0;		/* warnings be gone */
  unformat_input_t input;

/* $$$$ aarch64 kernel doesn't report "cpu MHz" */
#if defined(__aarch64__)
  return 0.0;
#endif

  cpu_freq = 0;

  ppc_timebase = 0;
  if (unformat_init_file (&input, "/proc/cpuinfo"))
    {
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
    }
  else
    return cpu_freq;

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
  f64 cpu_freq = 0.0;
  unformat_input_t input;

  /* Time stamp always runs at max frequency. */
  cpu_freq = 0;

  if (unformat_init_file (
	&input, "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq"))
    {
      if (unformat (&input, "%f", &cpu_freq))
	cpu_freq *= 1e3; /* measured in kHz */
      unformat_free (&input);
    }

  return cpu_freq;
}

__clib_export f64
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

#ifdef __x86_64__
  u32 __clib_unused eax = 0, ebx = 0, ecx = 0, edx = 0;
  clib_get_cpuid (0x00, &eax, &ebx, &ecx, &edx);
  if (eax >= 0x15)
    {
      u32 max_leaf = eax;
      /*
         CPUID Leaf 0x15 - Time Stamp Counter and Nominal Core Crystal Clock Info
         eax - denominator of the TSC/”core crystal clock” ratio
         ebx - numerator of the TSC/”core crystal clock” ratio
         ecx - nominal frequency of the core crystal clock in Hz
         edx - reseved
       */

      clib_get_cpuid (0x15, &eax, &ebx, &ecx, &edx);
      if (ebx && ecx)
	return (u64) ecx *ebx / eax;

      if (max_leaf >= 0x16)
	{
	  /*
	     CPUID Leaf 0x16 - Processor Frequency Information Leaf
	     eax - Bits 15 - 00: Processor Base Frequency (in MHz).
	   */

	  clib_get_cpuid (0x16, &eax, &ebx, &ecx, &edx);
	  if (eax)
	    return 1e6 * (eax & 0xffff);
	}
    }
#endif

  /* If we have an invariant TSC, use it to estimate the clock frequency */
  if (clib_cpu_supports_invariant_tsc ())
    return estimate_clock_frequency (1e-3);

  /* Next, try /sys version. */
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
__clib_export void
clib_time_init (clib_time_t * c)
{
  clib_memset (c, 0, sizeof (c[0]));
  c->clocks_per_second = os_cpu_clock_frequency ();
  /*
   * Sporadic reports of os_cpu_clock_frequency() returning 0.0
   * in highly parallel container environments.
   * To avoid immediate division by zero:
   *   Step 1: try estimate_clock_frequency().
   *   Step 2: give up. Pretend we have a 2gHz clock.
   */
  if (PREDICT_FALSE (c->clocks_per_second == 0.0))
    {
      c->clocks_per_second = estimate_clock_frequency (1e-3);
      if (c->clocks_per_second == 0.0)
	{
	  clib_warning ("os_cpu_clock_frequency() returned 0.0, use 2e9...");
	  c->clocks_per_second = 2e9;
	}
    }
  c->seconds_per_clock = 1 / c->clocks_per_second;
  c->log2_clocks_per_second = min_log2_u64 ((u64) c->clocks_per_second);

  /* Verify frequency every 16 sec */
  c->log2_clocks_per_frequency_verify = c->log2_clocks_per_second + 4;

  c->last_verify_reference_time = unix_time_now ();
  c->init_reference_time = c->last_verify_reference_time;
  c->last_cpu_time = clib_cpu_time_now ();
  c->init_cpu_time = c->last_verify_cpu_time = c->last_cpu_time;
  c->total_cpu_time = 0ULL;

  /*
   * Use exponential smoothing, with a half-life of 1 minute
   * reported_rate(t) = reported_rate(t-1) * K + rate(t)*(1-K)
   * where K = e**(-1.0/3.75);
   * 15 samples in 4 minutes
   * 7.5 samples in 2 minutes,
   * 3.75 samples in 1 minute, etc.
   */
  c->damping_constant = exp (-1.0 / 3.75);
}

__clib_export void
clib_time_verify_frequency (clib_time_t * c)
{
  f64 now_reference, delta_reference, delta_reference_max;
  f64 delta_clock_in_seconds;
  u64 now_clock, delta_clock;
  f64 new_clocks_per_second, delta;

  /* Ask the kernel and the CPU what time it is... */
  now_reference = unix_time_now ();
  now_clock = clib_cpu_time_now ();

  /* Compute change in the reference clock */
  delta_reference = now_reference - c->last_verify_reference_time;

  /* And change in the CPU clock */
  delta_clock_in_seconds = (f64) (now_clock - c->last_verify_cpu_time) *
    c->seconds_per_clock;

  /*
   * Recompute vpp start time reference, and total clocks
   * using the current clock rate
   */
  c->init_reference_time += (delta_reference - delta_clock_in_seconds);
  c->total_cpu_time = (now_reference - c->init_reference_time)
    * c->clocks_per_second;

  c->last_cpu_time = now_clock;

  /* Calculate a new clock rate sample */
  delta_clock = c->last_cpu_time - c->last_verify_cpu_time;

  c->last_verify_cpu_time = c->last_cpu_time;
  c->last_verify_reference_time = now_reference;

  /*
   * Is the reported reference interval non-positive,
   * or off by a factor of two - or 8 seconds - whichever is larger?
   * Someone reset the clock behind our back.
   */
  delta_reference_max = (f64) (2ULL << c->log2_clocks_per_frequency_verify) /
    (f64) (1ULL << c->log2_clocks_per_second);
  delta_reference_max = delta_reference_max > 8.0 ? delta_reference_max : 8.0;

  /* Ignore this sample */
  if (delta_reference <= 0.0 || delta_reference > delta_reference_max)
    return;

  /*
   * Reject large frequency changes, another consequence of
   * system clock changes particularly with old kernels.
   */
  new_clocks_per_second = ((f64) delta_clock) / delta_reference;

  /* Compute abs(rate change) */
  delta = new_clocks_per_second - c->clocks_per_second;
  if (delta < 0.0)
    delta = -delta;

  /* If rate change > 1%, reject this sample */
  if (PREDICT_FALSE ((delta / c->clocks_per_second) > .01))
    {
      clib_warning ("Rejecting large frequency change of %.2f%%",
		    (delta / c->clocks_per_second) * 100.0);
      return;
    }

  /* Add sample to the exponentially-smoothed rate */
  c->clocks_per_second = c->clocks_per_second * c->damping_constant +
    (1.0 - c->damping_constant) * new_clocks_per_second;
  c->seconds_per_clock = 1.0 / c->clocks_per_second;

  /*
   * Recalculate total_cpu_time based on the kernel timebase, and
   * the calculated clock rate
   */
  c->total_cpu_time =
    (now_reference - c->init_reference_time) * c->clocks_per_second;
}


__clib_export u8 *
format_clib_time (u8 * s, va_list * args)
{
  clib_time_t *c = va_arg (*args, clib_time_t *);
  int verbose = va_arg (*args, int);
  f64 now, reftime, delta_reftime_in_seconds, error;

  /* Compute vpp elapsed time from the CPU clock */
  reftime = unix_time_now ();
  now = clib_time_now (c);

  s = format (s, "Time now %.6f", now);
  if (verbose == 0)
    return s;

  /* And also from the kernel */
  delta_reftime_in_seconds = reftime - c->init_reference_time;

  error = now - delta_reftime_in_seconds;

  s = format (s, ", reftime %.6f, error %.6f, clocks/sec %.6f",
	      delta_reftime_in_seconds, error, c->clocks_per_second);
  return (s);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
