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

#ifndef included_test_vec_h
#define included_test_vec_h


#include <vppinfra/clib.h>
#include <vppinfra/mem.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>


extern uword g_verbose;
extern u32 g_seed;

always_inline u8 *
format_u32_binary (u8 * s, va_list * va)
{
  u32 val = va_arg (*va, u32);
  word i = 0;

  for (i = BITS (val) - 1; i >= 0; i--)
    {
      if (val & (1 << i))
	s = format (s, "1");
      else
	s = format (s, "0");
    }

  return s;
}

#define VERBOSE1(fmt, args...)			\
do {						\
  if (g_verbose >= 1)				\
    fformat (stdout, fmt, ## args);		\
} while (0)

#define VERBOSE2(fmt, args...)			\
do {						\
  if (g_verbose >= 2)				\
    fformat (stdout, fmt, ## args);		\
} while (0)

#define VERBOSE3(fmt, args...)			\
do {						\
  if (g_verbose >= 3)				\
    fformat (stdout, fmt, ## args);		\
} while (0)

#define clib_mem_free_safe(p)			\
do {						\
  if (p)					\
    {						\
      clib_mem_free (p);			\
      (p) = NULL;				\
    }						\
} while (0)

/* XXX - I get undefined symbol trying to call random_u32() <vppinfra/random.h> */
/* Simple random number generator with period 2^31 - 1. */
static u32
my_random_u32 (u32 * seed_return)
{
  /* Unlikely mask value to XOR into seed.
     Otherwise small seed values would give
     non-random seeming smallish numbers. */
  const u32 mask = 0x12345678;
  u32 seed, a, b, result;

  seed = *seed_return;
  seed ^= mask;

  a = seed / 127773;
  b = seed % 127773;
  seed = 16807 * b - 2836 * a;

  if ((i32) seed < 0)
    seed += ((u32) 1 << 31) - 1;

  result = seed;

  *seed_return = seed ^ mask;

  return result;
}

static u32
bounded_random_u32 (u32 * seed, uword lo, uword hi)
{
  if (lo == hi)
    return lo;

  ASSERT (lo < hi);

  return ((my_random_u32 (seed) % (hi - lo + ((hi != ~0) ? (1) : (0)))) + lo);
}

#define fill_with_random_data(ptr, bytes, seed)			\
do {								\
  u8 * _v(p) = (u8 *) (ptr);					\
  uword _v(b) = (bytes);					\
  uword _v(i);							\
								\
  for (_v(i) = 0; _v(i) < _v(b); _v(i)++)			\
    _v(p)[_v(i)] = (u8) bounded_random_u32 (&(seed), 0, 255);	\
								\
} while (0)

#define compute_mem_hash(hash, ptr, bytes)	\
({						\
  u8 * _v(p) = (u8 *) (ptr);			\
  uword _v(b) = (uword) (bytes);		\
  uword _v(i);					\
  uword _v(h) = (u8) (hash);			\
						\
  if (_v(p) && _v(b) > 0)			\
    {						\
      for (_v(i) = 0; _v(i) < _v(b); _v(i)++)	\
	_v(h) ^= _v(p)[_v(i)];			\
    }						\
						\
  _v(h);					\
})

#define log2_align_down(value, align)		\
({						\
  uword _v = (uword) (value);			\
  uword _a = (uword) (align);			\
  uword _m = (1 << _a) - 1;			\
						\
  _v = _v & ~_m;				\
})

#define log2_align_up(value, align)		\
({						\
  uword _v = (uword) (value);			\
  uword _a = (uword) (align);			\
  uword _m = (1 << _a) - 1;			\
						\
  _v = (_v + _m) & ~_m;				\
})

#define log2_align_ptr_down(ptr, align) \
uword_to_pointer (log2_align_down (pointer_to_uword (ptr), align), void *)

#define log2_align_ptr_up(ptr, align) \
uword_to_pointer (log2_align_up (pointer_to_uword (ptr), align), void *)

#define MAX_LOG2_ALIGN		6
#define MAX_UNALIGN_OFFSET	((1 << MAX_LOG2_ALIGN) - 1)

/* Allocates pointer to memory whose address is:
   addr = <log2_align>-aligned address */
always_inline void *
alloc_aligned (uword size, uword log2_align, void **ptr_to_free)
{
  void *p;

  if (size <= 0)
    return NULL;

  p = (void *) clib_mem_alloc (size + (1 << log2_align) - 1);

  if (ptr_to_free)
    *ptr_to_free = p;

  return (p) ? log2_align_ptr_up (p, log2_align) : (NULL);
}

/* Allocates pointer to memory whose address is:
   addr = MAX_LOG2_ALIGN-aligned address + <offset> */
always_inline void *
alloc_unaligned (uword size, uword offset, void **ptr_to_free)
{
  void *p;

  if (size <= 0)
    return NULL;

  ASSERT (offset <= MAX_UNALIGN_OFFSET);

  p =
    alloc_aligned (size + (1 << MAX_LOG2_ALIGN), MAX_LOG2_ALIGN, ptr_to_free);

  if (!p)
    return NULL;

  return (void *) ((u8 *) p + (offset % MAX_UNALIGN_OFFSET));
}

#define memory_snap()						\
do {								\
  clib_mem_usage_t _usage = { 0 };				\
  clib_mem_usage (&_usage);					\
  fformat (stdout, "%U\n", format_clib_mem_usage, _usage, 0);	\
} while (0)


#endif /* included_test_vec_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
