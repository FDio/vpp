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

#if defined (__SSE2__) && __GNUC__ >= 4
#define CLIB_HAVE_VEC128
#endif

#if defined (__ALTIVEC__)
#define CLIB_HAVE_VEC128
#endif

/* 128 implies 64 */
#ifdef CLIB_HAVE_VEC128
#define CLIB_HAVE_VEC64
#endif

#define _vector_size(n) __attribute__ ((vector_size (n)))

#if defined (__aarch64__) || defined (__arm__)
typedef unsigned int u32x4 _vector_size (16);
typedef u8 u8x16 _vector_size (16);
typedef u16 u16x8 _vector_size (16);
typedef u32 u32x4 _vector_size (16);
typedef u64 u64x2 _vector_size (16);
#endif

#ifdef CLIB_HAVE_VEC64
/* Signed 64 bit. */
typedef char i8x8 _vector_size (8);
typedef short i16x4 _vector_size (8);
typedef int i32x2 _vector_size (8);

/* Unsigned 64 bit. */
typedef unsigned char u8x8 _vector_size (8);
typedef unsigned short u16x4 _vector_size (8);
typedef unsigned int u32x2 _vector_size (8);

/* Floating point 64 bit. */
typedef float f32x2 _vector_size (8);
#endif /* CLIB_HAVE_VEC64 */

#ifdef CLIB_HAVE_VEC128
/* Signed 128 bit. */
typedef i8 i8x16 _vector_size (16);
typedef i16 i16x8 _vector_size (16);
typedef i32 i32x4 _vector_size (16);
typedef long long i64x2 _vector_size (16);

/* Unsigned 128 bit. */
typedef u8 u8x16 _vector_size (16);
typedef u16 u16x8 _vector_size (16);
typedef u32 u32x4 _vector_size (16);
typedef u64 u64x2 _vector_size (16);

typedef f32 f32x4 _vector_size (16);
typedef f64 f64x2 _vector_size (16);

/* Signed 256 bit. */
typedef i8 i8x32 _vector_size (32);
typedef i16 i16x16 _vector_size (32);
typedef i32 i32x8 _vector_size (32);
typedef long long i64x4 _vector_size (32);

/* Unsigned 256 bit. */
typedef u8 u8x32 _vector_size (32);
typedef u16 u16x16 _vector_size (32);
typedef u32 u32x8 _vector_size (32);
typedef u64 u64x4 _vector_size (32);

typedef f32 f32x8 _vector_size (32);
typedef f64 f64x4 _vector_size (32);
#endif /* CLIB_HAVE_VEC128 */

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

/* Union types. */
#if (defined(CLIB_HAVE_VEC128) || defined(CLIB_HAVE_VEC64))

#define _(t)					\
  typedef union {				\
    t##x as_##t##x;				\
    t as_##t[VECTOR_WORD_TYPE_LEN (t)];	\
  } t##x##_union_t;

_(u8);
_(u16);
_(u32);
_(u64);
_(i8);
_(i16);
_(i32);
_(i64);

#undef _

#endif

#ifdef CLIB_HAVE_VEC64

#define _(t,n)					\
  typedef union {				\
    t##x##n as_##t##x##n;			\
    t as_##t[n];				\
  } t##x##n##_union_t;				\

_(u8, 8);
_(u16, 4);
_(u32, 2);
_(i8, 8);
_(i16, 4);
_(i32, 2);

#undef _

#endif

#ifdef CLIB_HAVE_VEC128

#define _(t,n)					\
  typedef union {				\
    t##x##n as_##t##x##n;			\
    t as_##t[n];				\
  } t##x##n##_union_t;				\

_(u8, 16);
_(u16, 8);
_(u32, 4);
_(u64, 2);
_(i8, 16);
_(i16, 8);
_(i32, 4);
_(i64, 2);
_(f32, 4);
_(f64, 2);

#undef _

#endif

/* When we don't have vector types, still define e.g. u32x4_union_t but as an array. */
#if !defined(CLIB_HAVE_VEC128) && !defined(CLIB_HAVE_VEC64)

#define _(t,n)					\
  typedef union {				\
    t as_##t[n];				\
  } t##x##n##_union_t;				\

_(u8, 16);
_(u16, 8);
_(u32, 4);
_(u64, 2);
_(i8, 16);
_(i16, 8);
_(i32, 4);
_(i64, 2);

#undef _

#endif

#if defined (__SSE2__) && __GNUC__ >= 4
#include <vppinfra/vector_sse2.h>
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

#endif /* included_clib_vector_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
