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

/*
 * Allow CFLAGS to override the arch-specific cache line size
 */
#ifndef CLIB_LOG2_CACHE_LINE_BYTES

#if defined(__x86_64__) || defined(__ARM_ARCH_7A__) || defined(__i386__)
#define CLIB_LOG2_CACHE_LINE_BYTES 6
#endif

#ifdef __aarch64__
#define CLIB_LOG2_CACHE_LINE_BYTES 7
#endif

/* Default cache line size of 32 bytes. */
#ifndef CLIB_LOG2_CACHE_LINE_BYTES
#define CLIB_LOG2_CACHE_LINE_BYTES 5
#endif

#endif /* CLIB_LOG2_CACHE_LINE_BYTES defined */

#if (CLIB_LOG2_CACHE_LINE_BYTES >= 9)
#error Cache line size 512 bytes or greater
#endif

#define CLIB_CACHE_LINE_BYTES (1 << CLIB_LOG2_CACHE_LINE_BYTES)
#define CLIB_CACHE_LINE_ALIGN_MARK(mark) u8 mark[0] __attribute__((aligned(CLIB_CACHE_LINE_BYTES)))

/* Read/write arguments to __builtin_prefetch. */
#define CLIB_PREFETCH_READ 0
#define CLIB_PREFETCH_LOAD 0	/* alias for read */
#define CLIB_PREFETCH_WRITE 1
#define CLIB_PREFETCH_STORE 1	/* alias for write */

#define _CLIB_PREFETCH(n,size,type)				\
  if ((size) > (n)*CLIB_CACHE_LINE_BYTES)			\
    __builtin_prefetch (_addr + (n)*CLIB_CACHE_LINE_BYTES,	\
			CLIB_PREFETCH_##type,			\
			/* locality */ 3);

#define CLIB_PREFETCH(addr,size,type)		\
do {						\
  void * _addr = (addr);			\
						\
  ASSERT ((size) <= 4*CLIB_CACHE_LINE_BYTES);	\
  _CLIB_PREFETCH (0, size, type);		\
  _CLIB_PREFETCH (1, size, type);		\
  _CLIB_PREFETCH (2, size, type);		\
  _CLIB_PREFETCH (3, size, type);		\
} while (0)

#undef _

#endif /* included_clib_cache_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
