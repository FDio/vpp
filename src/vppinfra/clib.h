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

#ifndef included_clib_h
#define included_clib_h

#include <vppinfra/config.h>

/* Standalone means to not assume we are running on a Unix box. */
#if ! defined (CLIB_STANDALONE) && ! defined (CLIB_LINUX_KERNEL)
#define CLIB_UNIX
#endif

#include <vppinfra/types.h>
#include <vppinfra/atomics.h>

/* Global DEBUG flag.  Setting this to 1 or 0 turns off
   ASSERT (see vppinfra/error.h) & other debugging code. */
#ifndef CLIB_DEBUG
#define CLIB_DEBUG 0
#endif

#ifndef NULL
#define NULL ((void *) 0)
#endif

#define BITS(x)		(8*sizeof(x))
#define ARRAY_LEN(x)	(sizeof (x)/sizeof (x[0]))

#define _STRUCT_FIELD(t,f) (((t *) 0)->f)
#define STRUCT_OFFSET_OF(t,f) ((uword) & _STRUCT_FIELD (t, f))
#define STRUCT_BIT_OFFSET_OF(t,f) (BITS(u8) * (uword) & _STRUCT_FIELD (t, f))
#define STRUCT_SIZE_OF(t,f)   (sizeof (_STRUCT_FIELD (t, f)))
#define STRUCT_BITS_OF(t,f)   (BITS (_STRUCT_FIELD (t, f)))
#define STRUCT_ARRAY_LEN(t,f) ARRAY_LEN (_STRUCT_FIELD (t, f))
#define STRUCT_MARK(mark)     u8 mark[0]
#define STRUCT_MARK_PTR(v, f) &(v)->f

/* Stride in bytes between struct array elements. */
#define STRUCT_STRIDE_OF(t,f)			\
  (  ((uword) & (((t *) 0)[1].f))		\
   - ((uword) & (((t *) 0)[0].f)))

#define STRUCT_OFFSET_OF_VAR(v,f) ((uword) (&(v)->f) - (uword) (v))

/* Used to pack structure elements. */
#define CLIB_PACKED(x)	x __attribute__ ((packed))
#define CLIB_UNUSED(x)	x __attribute__ ((unused))

/* similar to CLIB_CACHE_LINE_ALIGN_MARK() but with arbitrary alignment */
#define CLIB_ALIGN_MARK(name, alignment) u8 name[0] __attribute__((aligned(alignment)))

/* Make a string from the macro's argument */
#define CLIB_STRING_MACRO(x) #x

#define __clib_unused __attribute__ ((unused))
#define __clib_weak __attribute__ ((weak))
#define __clib_packed __attribute__ ((packed))
#define __clib_constructor __attribute__ ((constructor))

#define never_inline __attribute__ ((__noinline__))

#if CLIB_DEBUG > 0
#define always_inline static inline
#define static_always_inline static inline
#else
#define always_inline static inline __attribute__ ((__always_inline__))
#define static_always_inline static inline __attribute__ ((__always_inline__))
#endif


/* Reserved (unused) structure element with address offset between
   from and to. */
#define CLIB_PAD_FROM_TO(from,to) u8 pad_##from[(to) - (from)]

/* Hints to compiler about hot/cold code. */
#define PREDICT_FALSE(x) __builtin_expect((x),0)
#define PREDICT_TRUE(x) __builtin_expect((x),1)

/* Full memory barrier (read and write). */
#define CLIB_MEMORY_BARRIER() __sync_synchronize ()

#if __x86_64__
#define CLIB_MEMORY_STORE_BARRIER() __builtin_ia32_sfence ()
#else
#define CLIB_MEMORY_STORE_BARRIER() __sync_synchronize ()
#endif

/* Arranges for function to be called before main. */
#define INIT_FUNCTION(decl)			\
  decl __attribute ((constructor));		\
  decl

/* Arranges for function to be called before exit. */
#define EXIT_FUNCTION(decl)			\
  decl __attribute ((destructor));		\
  decl

/* Use __builtin_clz if available. */
#if uword_bits == 64
#define count_leading_zeros(x) __builtin_clzll (x)
#define count_trailing_zeros(x) __builtin_ctzll (x)
#else
#define count_leading_zeros(x) __builtin_clzl (x)
#define count_trailing_zeros(x) __builtin_ctzl (x)
#endif

#if defined (count_leading_zeros)
always_inline uword
min_log2 (uword x)
{
  uword n;
  n = count_leading_zeros (x);
  return BITS (uword) - n - 1;
}
#else
always_inline uword
min_log2 (uword x)
{
  uword a = x, b = BITS (uword) / 2, c = 0, r = 0;

  /* Reduce x to 4 bit result. */
#define _					\
{						\
  c = a >> b;					\
  if (c) a = c;					\
  if (c) r += b;				\
  b /= 2;					\
}

  if (BITS (uword) > 32)
    _;
  _;
  _;
  _;
#undef _

  /* Do table lookup on 4 bit partial. */
  if (BITS (uword) > 32)
    {
      const u64 table = 0x3333333322221104LL;
      uword t = (table >> (4 * a)) & 0xf;
      r = t < 4 ? r + t : ~0;
    }
  else
    {
      const u32 table = 0x22221104;
      uword t = (a & 8) ? 3 : ((table >> (4 * a)) & 0xf);
      r = t < 4 ? r + t : ~0;
    }

  return r;
}
#endif

always_inline uword
max_log2 (uword x)
{
  uword l = min_log2 (x);
  if (x > ((uword) 1 << l))
    l++;
  return l;
}

always_inline u64
min_log2_u64 (u64 x)
{
  if (BITS (uword) == 64)
    return min_log2 (x);
  else
    {
      uword l, y;
      y = x;
      l = 0;
      if (y == 0)
	{
	  l += 32;
	  x >>= 32;
	}
      l += min_log2 (x);
      return l;
    }
}

always_inline uword
pow2_mask (uword x)
{
  return ((uword) 1 << x) - (uword) 1;
}

always_inline uword
max_pow2 (uword x)
{
  word y = (word) 1 << min_log2 (x);
  if (x > y)
    y *= 2;
  return y;
}

always_inline uword
is_pow2 (uword x)
{
  return 0 == (x & (x - 1));
}

always_inline uword
round_pow2 (uword x, uword pow2)
{
  return (x + pow2 - 1) & ~(pow2 - 1);
}

always_inline u64
round_pow2_u64 (u64 x, u64 pow2)
{
  return (x + pow2 - 1) & ~(pow2 - 1);
}

always_inline uword
first_set (uword x)
{
  return x & -x;
}

always_inline uword
log2_first_set (uword x)
{
  uword result;
#ifdef count_trailing_zeros
  result = count_trailing_zeros (x);
#else
  result = min_log2 (first_set (x));
#endif
  return result;
}

always_inline f64
flt_round_down (f64 x)
{
  return (int) x;
}

always_inline word
flt_round_nearest (f64 x)
{
  return (word) (x + .5);
}

always_inline f64
flt_round_to_multiple (f64 x, f64 f)
{
  return f * flt_round_nearest (x / f);
}

#define clib_max(x,y)				\
({						\
  __typeof__ (x) _x = (x);			\
  __typeof__ (y) _y = (y);			\
  _x > _y ? _x : _y;				\
})

#define clib_min(x,y)				\
({						\
  __typeof__ (x) _x = (x);			\
  __typeof__ (y) _y = (y);			\
  _x < _y ? _x : _y;				\
})

#define clib_abs(x)				\
({						\
  __typeof__ (x) _x = (x);			\
  _x < 0 ? -_x : _x;				\
})

/* Standard standalone-only function declarations. */
#ifndef CLIB_UNIX
void clib_standalone_init (void *memory, uword memory_bytes);

void qsort (void *base, uword n, uword size,
	    int (*)(const void *, const void *));
#endif

/* Stack backtrace. */
uword
clib_backtrace (uword * callers, uword max_callers, uword n_frames_to_skip);

#endif /* included_clib_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
