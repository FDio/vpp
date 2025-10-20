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

#ifndef included_clib_cache_h
#define included_clib_cache_h

#include <vppinfra/error_bootstrap.h>

/* Default cache line size of 64 bytes. */
#ifndef CLIB_LOG2_CACHE_LINE_BYTES
#define CLIB_LOG2_CACHE_LINE_BYTES 6
#endif

/* How much data prefetch instruction prefetches */
#ifndef CLIB_LOG2_CACHE_PREFETCH_BYTES
#define CLIB_LOG2_CACHE_PREFETCH_BYTES CLIB_LOG2_CACHE_LINE_BYTES
#endif

/* Default cache line fill buffers. */
#ifndef CLIB_N_PREFETCHES
#define CLIB_N_PREFETCHES 16
#endif

#define CLIB_CACHE_LINE_BYTES	  (1 << CLIB_LOG2_CACHE_LINE_BYTES)
#define CLIB_CACHE_PREFETCH_BYTES (1 << CLIB_LOG2_CACHE_PREFETCH_BYTES)
#define CLIB_CACHE_LINE_ALIGN_MARK(mark)                                      \
  u8 mark[0] __attribute__ ((aligned (CLIB_CACHE_LINE_BYTES)))
#define CLIB_CACHE_LINE_ROUND(x)                                              \
  ((x + CLIB_CACHE_LINE_BYTES - 1) & ~(CLIB_CACHE_LINE_BYTES - 1))

/* Read/write arguments to __builtin_prefetch. */
#define CLIB_PREFETCH_READ 0
#define CLIB_PREFETCH_LOAD 0	/* alias for read */
#define CLIB_PREFETCH_WRITE 1
#define CLIB_PREFETCH_STORE 1	/* alias for write */

/* locality arguments to __builtin_prefetch. */
#define CLIB_PREFETCH_TO_STREAM 0 // NTA
#define CLIB_PREFETCH_TO_L3	1 // T2
#define CLIB_PREFETCH_TO_L2	2 // T1
#define CLIB_PREFETCH_TO_L1	3 // T0

#define _CLIB_TARGETED_PREFETCH(n, size, type, loc)                           \
  if ((size) > (n) *CLIB_CACHE_PREFETCH_BYTES)                                \
    __builtin_prefetch (_addr + (n) *CLIB_CACHE_PREFETCH_BYTES,               \
			CLIB_PREFETCH_##type, CLIB_PREFETCH_TO_##loc);

#define _CLIB_PREFETCH(n, size, type)                                         \
  if ((size) > (n) *CLIB_CACHE_PREFETCH_BYTES)                                \
    __builtin_prefetch (_addr + (n) *CLIB_CACHE_PREFETCH_BYTES,               \
			CLIB_PREFETCH_##type, /* locality */ 3);

#define CLIB_PREFETCH(addr, size, type)                                       \
  do                                                                          \
    {                                                                         \
      void *_addr = (addr);                                                   \
                                                                              \
      ASSERT ((size) <= 4 * CLIB_CACHE_PREFETCH_BYTES);                       \
      _CLIB_PREFETCH (0, size, type);                                         \
      _CLIB_PREFETCH (1, size, type);                                         \
      _CLIB_PREFETCH (2, size, type);                                         \
      _CLIB_PREFETCH (3, size, type);                                         \
    }                                                                         \
  while (0)

#define CLIB_TARGETED_PREFETCH(addr, size, type, locality)                    \
  do                                                                          \
    {                                                                         \
      void *_addr = (addr);                                                   \
                                                                              \
      ASSERT ((size) <= 4 * CLIB_CACHE_PREFETCH_BYTES);                       \
      _CLIB_TARGETED_PREFETCH (0, size, type, locality);                      \
      _CLIB_TARGETED_PREFETCH (1, size, type, locality);                      \
      _CLIB_TARGETED_PREFETCH (2, size, type, locality);                      \
      _CLIB_TARGETED_PREFETCH (3, size, type, locality);                      \
    }                                                                         \
  while (0)

#undef _

static_always_inline void
clib_prefetch_load (void *p)
{
  __builtin_prefetch (p, /* rw */ 0, /* locality */ 3);
}

static_always_inline void
clib_prefetch_store (void *p)
{
  __builtin_prefetch (p, /* rw */ 1, /* locality */ 3);
}

static_always_inline void
clib_cacheline_demote (void *p)
{
#if __has_builtin(__builtin_ia32_cldemote)
  __builtin_ia32_cldemote (p);
#endif
}

#endif /* included_clib_cache_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
