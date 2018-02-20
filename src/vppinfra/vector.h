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

#ifndef included_clib_vector_h
#define included_clib_vector_h

#include <vppinfra/clib.h>

/* Vector types. */

#if defined (__MMX__) || defined (__IWMMXT__) || defined (__aarch64__)
#define CLIB_HAVE_VEC64
#endif

#if defined (__aarch64__) && defined(__ARM_NEON)
#define CLIB_HAVE_VEC128
#endif

#if defined (__SSE4_2__) && __GNUC__ >= 4
#define CLIB_HAVE_VEC128
#endif

#if defined (__ALTIVEC__)
#define CLIB_HAVE_VEC128
#endif

#if defined (__AVX__)
#define CLIB_HAVE_VEC256
#endif

#if defined (__AVX512F__)
#define CLIB_HAVE_VEC512
#endif

/* 128 implies 64 */
#ifdef CLIB_HAVE_VEC128
#define CLIB_HAVE_VEC64
#endif

#define _vector_size(n) __attribute__ ((vector_size (n)))

#define foreach_vec64i  _(i,8,8)  _(i,16,4)  _(i,32,2)
#define foreach_vec64u  _(u,8,8)  _(u,16,4)  _(u,32,2)
#define foreach_vec64f  _(f,32,2)
#define foreach_vec128i _(i,8,16) _(i,16,8)  _(i,32,4)  _(i,64,2)
#define foreach_vec128u _(u,8,16) _(u,16,8)  _(u,32,4)  _(u,64,2)
#define foreach_vec128f _(f,32,4) _(f,64,2)
#define foreach_vec256i _(i,8,32) _(i,16,16) _(i,32,8)  _(i,64,4)
#define foreach_vec256u _(u,8,32) _(u,16,16) _(u,32,8)  _(u,64,4)
#define foreach_vec256f _(f,32,8) _(f,64,4)
#define foreach_vec512i _(i,8,64) _(i,16,32) _(i,32,16) _(i,64,8)
#define foreach_vec512u _(u,8,64) _(u,16,32) _(u,32,16) _(u,64,8)
#define foreach_vec512f _(f,32,16) _(f,64,8)

#if defined (CLIB_HAVE_VEC512)
#define foreach_int_vec foreach_vec64i foreach_vec128i foreach_vec256i foreach_vec512i
#define foreach_uint_vec foreach_vec64u foreach_vec128u foreach_vec256u foreach_vec512u
#define foreach_float_vec foreach_vec64f foreach_vec128f foreach_vec256f foreach_vec512f
#elif defined (CLIB_HAVE_VEC256)
#define foreach_int_vec foreach_vec64i foreach_vec128i foreach_vec256i
#define foreach_uint_vec foreach_vec64u foreach_vec128u foreach_vec256u
#define foreach_float_vec foreach_vec64f foreach_vec128f foreach_vec256f
#else
#define foreach_int_vec foreach_vec64i foreach_vec128i
#define foreach_uint_vec foreach_vec64u foreach_vec128u
#define foreach_float_vec foreach_vec64f foreach_vec128f
#endif

#define foreach_vec foreach_int_vec foreach_uint_vec foreach_float_vec

/* *INDENT-OFF* */

/* Type Definitions */
#define _(t,s,c) \
typedef t##s t##s##x##c _vector_size (s/8*c);	\
typedef union {	  \
  t##s##x##c as_##t##s##x##c;	\
  t##s as_##t##s[c];	  \
} t##s##x##c##_union_t;

  foreach_vec64i foreach_vec64u foreach_vec64f
  foreach_vec128i foreach_vec128u foreach_vec128f
  foreach_vec256i foreach_vec256u foreach_vec256f
  foreach_vec512i foreach_vec512u foreach_vec512f
#undef _

/* Vector word sized types. */
#ifndef CLIB_VECTOR_WORD_BITS
#ifdef CLIB_HAVE_VEC128
#define CLIB_VECTOR_WORD_BITS 128
#else
#define CLIB_VECTOR_WORD_BITS 64
#endif
#endif /* CLIB_VECTOR_WORD_BITS */

/* Vector word sized types. */
#if CLIB_VECTOR_WORD_BITS == 128
typedef i8 i8x _vector_size (16);
typedef i16 i16x _vector_size (16);
typedef i32 i32x _vector_size (16);
typedef i64 i64x _vector_size (16);
typedef u8 u8x _vector_size (16);
typedef u16 u16x _vector_size (16);
typedef u32 u32x _vector_size (16);
typedef u64 u64x _vector_size (16);
#endif
#if CLIB_VECTOR_WORD_BITS == 64
typedef i8 i8x _vector_size (8);
typedef i16 i16x _vector_size (8);
typedef i32 i32x _vector_size (8);
typedef i64 i64x _vector_size (8);
typedef u8 u8x _vector_size (8);
typedef u16 u16x _vector_size (8);
typedef u32 u32x _vector_size (8);
typedef u64 u64x _vector_size (8);
#endif

#undef _vector_size

#define VECTOR_WORD_TYPE(t) t##x
#define VECTOR_WORD_TYPE_LEN(t) (sizeof (VECTOR_WORD_TYPE(t)) / sizeof (t))

/* this series of macros generate _is_equal, _is_greater, _is_zero, _add
   and _sub inline funcitons for each vector type */
#define _(t, s, c) \
  static_always_inline t##s##x##c			\
t##s##x##c##_is_equal (t##s##x##c v1, t##s##x##c v2)	\
{ return (v1 == v2); }					\
							\
static_always_inline t##s##x##c				\
t##s##x##c##_is_greater (t##s##x##c v1, t##s##x##c v2)	\
{ return (v1 > v2); }					\
							\
static_always_inline t##s##x##c				\
t##s##x##c##_is_zero (t##s##x##c v1)			\
{ t##s##x##c z = {0}; return (v1 == z); }		\
							\
static_always_inline t##s##x##c				\
t##s##x##c##_add (t##s##x##c v1, t##s##x##c v2)		\
{ return (v1 + v2); }					\
							\
static_always_inline t##s##x##c				\
t##s##x##c##_sub (t##s##x##c v1, t##s##x##c v2)		\
{ return (v1 - v2); }
  foreach_vec
#undef _

/* this macro generate _splat inline funcitons for each scalar vector type */
#define _(t, s, c) \
  static_always_inline t##s##x##c			\
t##s##x##c##_splat (t##s x)				\
{							\
    t##s##x##c r;					\
    int i;						\
							\
    for (i = 0; i < c; i++)				\
      r[i] = x;						\
							\
    return r;						\
}
  foreach_int_vec foreach_uint_vec
#undef _

#if defined (__SSE4_2__) && __GNUC__ >= 4
#include <vppinfra/vector_sse42.h>
#endif

#if defined (__ALTIVEC__)
#include <vppinfra/vector_altivec.h>
#endif

#if defined (__IWMMXT__)
#include <vppinfra/vector_iwmmxt.h>
#endif

#if defined (__aarch64__)
#include <vppinfra/vector_neon.h>
#endif

#if (defined(CLIB_HAVE_VEC128) || defined(CLIB_HAVE_VEC64))
#include <vppinfra/vector_funcs.h>
#endif

/* *INDENT-ONN* */

#endif /* included_clib_vector_h */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
