/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef included_clib_string_h
#define included_clib_string_h

#include <vppinfra/clib.h>	/* for CLIB_LINUX_KERNEL */
#include <vppinfra/vector.h>

#ifdef CLIB_LINUX_KERNEL
#include <linux/string.h>
#endif

#ifdef CLIB_UNIX
#include <string.h>
#endif

#ifdef CLIB_STANDALONE
#include <vppinfra/standalone_string.h>
#endif

/* Exchanges source and destination. */
void clib_memswap (void *_a, void *_b, uword bytes);

/*
 * the vector unit memcpy variants confuse coverity
 * so don't let it anywhere near them.
 */
#ifndef __COVERITY__
#if __AVX__
#include <vppinfra/memcpy_avx.h>
#elif __SSSE3__
#include <vppinfra/memcpy_sse3.h>
#else
#define clib_memcpy(a,b,c) memcpy(a,b,c)
#endif
#else /* __COVERITY__ */
#define clib_memcpy(a,b,c) memcpy(a,b,c)
#endif

/*
 * Copy 64 bytes of data to 4 destinations
 * this function is typically used in quad-loop case when whole cacheline
 * needs to be copied to 4 different places. First it reads whole cacheline
 * to 1/2/4 SIMD registers and then it writes data to 4 destinations.
 */

static_always_inline void
clib_memcpy64_x4 (void *d0, void *d1, void *d2, void *d3, void *s)
{
#if defined (CLIB_HAVE_VEC512)
  u8x64 __attribute__ ((aligned (1))) r0 = *(((u8x64 *) s) + 0);

  *(((u8x64 *) d0) + 0) = r0;
  *(((u8x64 *) d1) + 0) = r0;
  *(((u8x64 *) d2) + 0) = r0;
  *(((u8x64 *) d3) + 0) = r0;
#elif defined (CLIB_HAVE_VEC256)
  u8x32 __attribute__ ((aligned (1))) r0 = *(((u8x32 *) s) + 0);
  u8x32 __attribute__ ((aligned (1))) r1 = *(((u8x32 *) s) + 1);

  *(((u8x32 *) d0) + 0) = r0;
  *(((u8x32 *) d0) + 1) = r1;

  *(((u8x32 *) d1) + 0) = r0;
  *(((u8x32 *) d1) + 1) = r1;

  *(((u8x32 *) d2) + 0) = r0;
  *(((u8x32 *) d2) + 1) = r1;

  *(((u8x32 *) d3) + 0) = r0;
  *(((u8x32 *) d3) + 1) = r1;
#elif defined (CLIB_HAVE_VEC128)
  u8x16 __attribute__ ((aligned (1))) r0 = *(((u8x16 *) s) + 0);
  u8x16 __attribute__ ((aligned (1))) r1 = *(((u8x16 *) s) + 1);
  u8x16 __attribute__ ((aligned (1))) r2 = *(((u8x16 *) s) + 3);
  u8x16 __attribute__ ((aligned (1))) r3 = *(((u8x16 *) s) + 4);

  *(((u8x16 *) d0) + 0) = r0;
  *(((u8x16 *) d0) + 1) = r1;
  *(((u8x16 *) d0) + 2) = r2;
  *(((u8x16 *) d0) + 3) = r3;

  *(((u8x16 *) d1) + 0) = r0;
  *(((u8x16 *) d1) + 1) = r1;
  *(((u8x16 *) d1) + 2) = r2;
  *(((u8x16 *) d1) + 3) = r3;

  *(((u8x16 *) d2) + 0) = r0;
  *(((u8x16 *) d2) + 1) = r1;
  *(((u8x16 *) d2) + 2) = r2;
  *(((u8x16 *) d2) + 3) = r3;

  *(((u8x16 *) d3) + 0) = r0;
  *(((u8x16 *) d3) + 1) = r1;
  *(((u8x16 *) d3) + 2) = r2;
  *(((u8x16 *) d3) + 3) = r3;
#else
  clib_memcpy (d0, s, 64);
  clib_memcpy (d1, s, 64);
  clib_memcpy (d2, s, 64);
  clib_memcpy (d3, s, 64);
#endif
}

#endif /* included_clib_string_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
