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

#ifndef included_time_h
#define included_time_h

#include <vppinfra/clib.h>

typedef struct
{
  /* Total run time in clock cycles
     since clib_time_init call. */
  u64 total_cpu_time;

  /* Last recorded time stamp. */
  u64 last_cpu_time;

  /* CPU clock frequency. */
  f64 clocks_per_second;

  /* 1 / cpu clock frequency: conversion factor
     from clock cycles into seconds. */
  f64 seconds_per_clock;

  /* Time stamp of call to clib_time_init call. */
  u64 init_cpu_time;

  u64 last_verify_cpu_time;

  /* Same but for reference time (if present). */
  f64 last_verify_reference_time;

  u32 log2_clocks_per_second, log2_clocks_per_frequency_verify;
} clib_time_t;

/* Return CPU time stamp as 64bit number. */
#if defined(__x86_64__) || defined(i386)
always_inline u64
clib_cpu_time_now (void)
{
  u32 a, d;
  asm volatile ("rdtsc":"=a" (a), "=d" (d));
  return (u64) a + ((u64) d << (u64) 32);
}

#elif defined (__powerpc64__)

always_inline u64
clib_cpu_time_now (void)
{
  u64 t;
  asm volatile ("mftb %0":"=r" (t));
  return t;
}

#elif defined (__SPU__)

always_inline u64
clib_cpu_time_now (void)
{
#ifdef _XLC
  return spu_rdch (0x8);
#else
  return 0 /* __builtin_si_rdch (0x8) FIXME */ ;
#endif
}

#elif defined (__powerpc__)

always_inline u64
clib_cpu_time_now (void)
{
  u32 hi1, hi2, lo;
  asm volatile ("1:\n"
		"mftbu %[hi1]\n"
		"mftb  %[lo]\n"
		"mftbu %[hi2]\n"
		"cmpw %[hi1],%[hi2]\n"
		"bne 1b\n":[hi1] "=r" (hi1),[hi2] "=r" (hi2),[lo] "=r" (lo));
  return (u64) lo + ((u64) hi2 << (u64) 32);
}

#elif defined (__arm__)
#if defined(__ARM_ARCH_8A__)
always_inline u64
clib_cpu_time_now (void)	/* We may run arm64 in aarch32 mode, to leverage 64bit counter */
{
  u64 tsc;
  asm volatile ("mrrc p15, 0, %Q0, %R0, c9":"=r" (tsc));
  return tsc;
}
#elif defined(__ARM_ARCH_7A__)
always_inline u64
clib_cpu_time_now (void)
{
  u32 tsc;
  asm volatile ("mrc p15, 0, %0, c9, c13, 0":"=r" (tsc));
  return (u64) tsc;
}
#else
always_inline u64
clib_cpu_time_now (void)
{
  u32 lo;
  asm volatile ("mrc p15, 0, %[lo], c15, c12, 1":[lo] "=r" (lo));
  return (u64) lo;
}
#endif

#elif defined (__xtensa__)

/* Stub for now. */
always_inline u64
clib_cpu_time_now (void)
{
  return 0;
}

#elif defined (__TMS320C6X__)

always_inline u64
clib_cpu_time_now (void)
{
  u32 l, h;

  asm volatile (" dint\n"
		" mvc .s2 TSCL,%0\n"
		" mvc .s2 TSCH,%1\n" " rint\n":"=b" (l), "=b" (h));

  return ((u64) h << 32) | l;
}

#elif defined (__aarch64__)
always_inline u64
clib_cpu_time_now (void)
{
  u64 tsc;

  /* Works on Cavium ThunderX. Other platforms: YMMV */
  asm volatile ("mrs %0, cntvct_el0":"=r" (tsc));

  return tsc;
}

#else
#error "don't know how to read CPU time stamp"

#endif

void clib_time_verify_frequency (clib_time_t * c);

always_inline f64
clib_time_now_internal (clib_time_t * c, u64 n)
{
  u64 l = c->last_cpu_time;
  u64 t = c->total_cpu_time;
  t += n - l;
  c->total_cpu_time = t;
  c->last_cpu_time = n;
  if (PREDICT_FALSE
      ((c->last_cpu_time -
	c->last_verify_cpu_time) >> c->log2_clocks_per_frequency_verify))
    clib_time_verify_frequency (c);
  return t * c->seconds_per_clock;
}

always_inline f64
clib_time_now (clib_time_t * c)
{
  return clib_time_now_internal (c, clib_cpu_time_now ());
}

always_inline void
clib_cpu_time_wait (u64 dt)
{
  u64 t_end = clib_cpu_time_now () + dt;
  while (clib_cpu_time_now () < t_end)
    ;
}

void clib_time_init (clib_time_t * c);

#ifdef CLIB_UNIX

#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <sys/syscall.h>

/* Use 64bit floating point to represent time offset from epoch. */
always_inline f64
unix_time_now (void)
{
  /* clock_gettime without indirect syscall uses GLIBC wrappers which
     we don't want.  Just the bare metal, please. */
  struct timespec ts;
  syscall (SYS_clock_gettime, CLOCK_REALTIME, &ts);
  return ts.tv_sec + 1e-9 * ts.tv_nsec;
}

/* As above but integer number of nano-seconds. */
always_inline u64
unix_time_now_nsec (void)
{
  struct timespec ts;
  syscall (SYS_clock_gettime, CLOCK_REALTIME, &ts);
  return 1e9 * ts.tv_sec + ts.tv_nsec;
}

always_inline void
unix_time_now_nsec_fraction (u32 * sec, u32 * nsec)
{
  struct timespec ts;
  syscall (SYS_clock_gettime, CLOCK_REALTIME, &ts);
  *sec = ts.tv_sec;
  *nsec = ts.tv_nsec;
}

always_inline f64
unix_usage_now (void)
{
  struct rusage u;
  getrusage (RUSAGE_SELF, &u);
  return u.ru_utime.tv_sec + 1e-6 * u.ru_utime.tv_usec
    + u.ru_stime.tv_sec + 1e-6 * u.ru_stime.tv_usec;
}

always_inline void
unix_sleep (f64 dt)
{
  struct timespec ts, tsrem;
  ts.tv_sec = dt;
  ts.tv_nsec = 1e9 * (dt - (f64) ts.tv_sec);

  while (nanosleep (&ts, &tsrem) < 0)
    ts = tsrem;
}

#else /* ! CLIB_UNIX */

always_inline f64
unix_time_now (void)
{
  return 0;
}

always_inline u64
unix_time_now_nsec (void)
{
  return 0;
}

always_inline void
unix_time_now_nsec_fraction (u32 * sec, u32 * nsec)
{
}

always_inline f64
unix_usage_now (void)
{
  return 0;
}

always_inline void
unix_sleep (f64 dt)
{
}

#endif

#endif /* included_time_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
