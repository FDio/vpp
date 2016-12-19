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

#ifndef included_random_h
#define included_random_h

#include <vppinfra/clib.h>
#include <vppinfra/vec.h>	/* for vec_resize */
#include <vppinfra/format.h>	/* for unformat_input_t */

/** \file
    Linear Congruential Random Number Generator

    This specific random number generator is described in
    "Numerical Recipes in C", 2nd edition, page 284. If you need
    random numbers with really excellent statistics, take a look
    at Chapter 7...

    By definition, a linear congruential random number generator
    is of the form: rand[i+1] = a*rand[i] + c (mod m) for specific
    values of (a,c,m).

    In this case, choose m = 2**32 and use the low-order 32-bits of
    the 64-bit product a*N[i]. Knuth suggests the use of a=1664525,
    H.W. Lewis has tested C=1013904223 extensively. This routine is
    reputedly as good as any 32-bit LCRN, and costs only a single
    multiply-add.

    Several variants: 32/64-bit, machine word width,
    f64 on the closed interval [0,1].
*/

/** \brief 32-bit random number generator */
always_inline u32
random_u32 (u32 * seed)
{
  *seed = (1664525 * *seed) + 1013904223;
  return *seed;
}

/* External test routine. */
int test_random_main (unformat_input_t * input);

/** \brief Maximum value returned by random_u32() */
always_inline u32
random_u32_max (void)
{
  return 0xffffffff;
}

#ifdef CLIB_UNIX

#include <unistd.h>		/* for getpid */

/** \brief Default random seed (unix/linux user-mode) */
always_inline uword
random_default_seed (void)
{
  return getpid ();
}

#endif

#ifdef CLIB_LINUX_KERNEL

#include <linux/sched.h>	/* for jiffies */

/** \brief Default random seed (Linux kernel) */
always_inline uword
random_default_seed (void)
{
  return jiffies;
}

#endif

#ifdef CLIB_STANDALONE
extern u32 standalone_random_default_seed;

always_inline u32
random_default_seed (void)
{
  return standalone_random_default_seed;
}
#endif

/** \brief 64-bit random number generator
 * Again, constants courtesy of Donald Knuth.
 *
 */
always_inline u64
random_u64 (u64 * seed)
{
  *seed = 6364136223846793005ULL * *seed + 1442695040888963407ULL;
  return *seed;
}

/** \brief machine word size random number generator */

always_inline uword
random_uword (u32 * seed)
{
  if (sizeof (uword) == sizeof (u64))
    return random_u64 ((u64 *) seed);
  else
    return random_u32 (seed);
}

/** \brief Generate f64 random number in the interval [0,1] */
always_inline f64
random_f64 (u32 * seed)
{
  return (f64) random_u32 (seed) / (f64) random_u32_max ();
}

/** \brief Generate random character vector

    From the alphabet a-z, lower case.
    Returns a vector of the supplied length which is NOT guaranteed to be
    NULL-terminated. FIXME?
*/
always_inline u8 *
random_string (u32 * seed, uword len)
{
  u8 *alphabet = (u8 *) "abcdefghijklmnopqrstuvwxyz";
  u8 *s = 0;
  word i;

  vec_resize (s, len);
  for (i = 0; i < len; i++)
    s[i] = alphabet[random_u32 (seed) % 26];

  return s;
}

#endif /* included_random_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
