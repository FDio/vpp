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

#if defined (__aarch64__) && defined(__ARM_NEON) || defined (__i686__)
#define CLIB_HAVE_VEC128
#endif

#if defined (__SSE4_2__) && __GNUC__ >= 4
#define CLIB_HAVE_VEC128
#endif

#if defined (__ALTIVEC__)
#define CLIB_HAVE_VEC128
#endif

#if defined (__AVX2__)
#define CLIB_HAVE_VEC256
#if defined (__clang__)  && __clang_major__ < 4
#undef CLIB_HAVE_VEC256
#endif
#endif

#if defined (__AVX512BITALG__)
#define CLIB_HAVE_VEC512
#endif

#if defined(__aarch64__) && defined(__ARM_FEATURE_SVE)
#define CLIB_HAVE_VEC_SCALABLE
#endif

#define _vector_size(n) __attribute__ ((vector_size (n), __may_alias__))
#define _vector_size_unaligned(n)                                             \
  __attribute__ ((vector_size (n), __aligned__ (1), __may_alias__))

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
typedef t##s t##s##x##c##u _vector_size_unaligned (s/8*c);	\
typedef union {	  \
  t##s##x##c as_##t##s##x##c;	\
  t##s as_##t##s[c];	  \
} t##s##x##c##_union_t;

  foreach_vec64i foreach_vec64u foreach_vec64f
  foreach_vec128i foreach_vec128u foreach_vec128f
  foreach_vec256i foreach_vec256u foreach_vec256f
  foreach_vec512i foreach_vec512u foreach_vec512f
#undef _

/* universal inlines */
#define _(t, s, c) \
static_always_inline t##s##x##c                                         \
t##s##x##c##_zero ()                                                    \
{ return (t##s##x##c) {}; }                                             \

foreach_vec
#undef _

#undef _vector_size

  /* _shuffle and _shuffle2 */
#if defined(__GNUC__) && !defined(__clang__)
#define __builtin_shufflevector(v1, v2, ...)                                  \
  __builtin_shuffle ((v1), (v2), (__typeof__ (v1)){ __VA_ARGS__ })
#endif

#define u8x16_shuffle(v1, ...)                                                \
  (u8x16) __builtin_shufflevector ((u8x16) (v1), (u8x16) (v1), __VA_ARGS__)
#define u8x32_shuffle(v1, ...)                                                \
  (u8x32) __builtin_shufflevector ((u8x32) (v1), (u8x32) (v1), __VA_ARGS__)
#define u8x64_shuffle(v1, ...)                                                \
  (u8x64) __builtin_shufflevector ((u8x64) (v1), (u8x64) (v1), __VA_ARGS__)

#define u16x8_shuffle(v1, ...)                                                \
  (u16x8) __builtin_shufflevector ((u16x8) (v1), (u16x8) (v1), __VA_ARGS__)
#define u16x16_shuffle(v1, ...)                                               \
  (u16x16) __builtin_shufflevector ((u16x16) (v1), (u16x16) (v1), __VA_ARGS__)
#define u16x32_shuffle(v1, ...)                                               \
  (u16u32) __builtin_shufflevector ((u16x32) (v1), (u16x32) (v1), __VA_ARGS__);

#define u32x4_shuffle(v1, ...)                                                \
  (u32x4) __builtin_shufflevector ((u32x4) (v1), (u32x4) (v1), __VA_ARGS__)
#define u32x8_shuffle(v1, ...)                                                \
  (u32x8) __builtin_shufflevector ((u32x8) (v1), (u32x8) (v1), __VA_ARGS__)
#define u32x16_shuffle(v1, ...)                                               \
  (u32x16) __builtin_shufflevector ((u32x16) (v1), (u32x16) (v1), __VA_ARGS__)

#define u64x2_shuffle(v1, ...)                                                \
  (u64x2) __builtin_shufflevector ((u64x2) (v1), (u64x2) (v1), __VA_ARGS__)
#define u64x4_shuffle(v1, ...)                                                \
  (u64x4) __builtin_shufflevector ((u64x4) (v1), (u64x4) (v1), __VA_ARGS__)
#define u64x8_shuffle(v1, ...)                                                \
  (u64x8) __builtin_shufflevector ((u64x8) (v1), (u64x8) (v1), __VA_ARGS__)

#define u8x16_shuffle2(v1, v2, ...)                                           \
  (u8x16) __builtin_shufflevector ((u8x16) (v1), (u8x16) (v2), __VA_ARGS__)
#define u8x32_shuffle2(v1, v2, ...)                                           \
  (u8x32) __builtin_shufflevector ((u8x32) (v1), (u8x32) (v2), __VA_ARGS__)
#define u8x64_shuffle2(v1, v2, ...)                                           \
  (u8x64) __builtin_shufflevector ((u8x64) (v1), (u8x64) (v2), __VA_ARGS__)

#define u16x8_shuffle2(v1, v2, ...)                                           \
  (u16x8) __builtin_shufflevector ((u16x8) (v1), (u16x8) (v2), __VA_ARGS__)
#define u16x16_shuffle2(v1, v2, ...)                                          \
  (u16x16) __builtin_shufflevector ((u16x16) (v1), (u16x16) (v2), __VA_ARGS__)
#define u16x32_shuffle2(v1, v2, ...)                                          \
  (u16u32) __builtin_shufflevector ((u16x32) (v1), (u16x32) (v2), __VA_ARGS__);

#define u32x4_shuffle2(v1, v2, ...)                                           \
  (u32x4) __builtin_shufflevector ((u32x4) (v1), (u32x4) (v2), __VA_ARGS__)
#define u32x8_shuffle2(v1, v2, ...)                                           \
  (u32x8) __builtin_shufflevector ((u32x8) (v1), (u32x8) (v2), __VA_ARGS__)
#define u32x16_shuffle2(v1, v2, ...)                                          \
  (u32x16) __builtin_shufflevector ((u32x16) (v1), (u32x16) (v2), __VA_ARGS__)

#define u64x2_shuffle2(v1, v2, ...)                                           \
  (u64x2) __builtin_shufflevector ((u64x2) (v1), (u64x2) (v2), __VA_ARGS__)
#define u64x4_shuffle2(v1, v2, ...)                                           \
  (u64x4) __builtin_shufflevector ((u64x4) (v1), (u64x4) (v2), __VA_ARGS__)
#define u64x8_shuffle2(v1, v2, ...)                                           \
  (u64x8) __builtin_shufflevector ((u64x8) (v1), (u64x8) (v2), __VA_ARGS__)

#define VECTOR_WORD_TYPE(t) t##x
#define VECTOR_WORD_TYPE_LEN(t) (sizeof (VECTOR_WORD_TYPE(t)) / sizeof (t))

#if defined (__SSE4_2__) && __GNUC__ >= 4
#include <vppinfra/vector_sse42.h>
#endif

#if defined (__AVX2__)
#include <vppinfra/vector_avx2.h>
#endif

#if defined(__AVX512F__)
#include <vppinfra/vector_avx512.h>
#endif

#if defined (__ALTIVEC__)
#include <vppinfra/vector_altivec.h>
#endif

#if defined (__aarch64__)
#include <vppinfra/vector_neon.h>
#endif

#if defined(__ARM_FEATURE_SVE)
#include <vppinfra/vector_sve.h>
#endif

/* this macro generate _splat inline functions for each scalar vector type */
#ifndef CLIB_VEC128_SPLAT_DEFINED
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
  foreach_vec128i foreach_vec128u
#undef _
#endif

/* *INDENT-ON* */

#endif /* included_clib_vector_h */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
