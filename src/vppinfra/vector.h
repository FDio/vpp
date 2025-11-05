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

/* Type Definitions */
#define _(t, s, c)                                                            \
  typedef t##s t##s##x##c _vector_size (s / 8 * c);                           \
  typedef t##s t##s##x##c##u _vector_size_unaligned (s / 8 * c);              \
  typedef union                                                               \
  {                                                                           \
    t##s##x##c as_##t##s##x##c;                                               \
    t##s as_##t##s[c];                                                        \
  } t##s##x##c##_union_t;

/* clang-format off */
  foreach_vec64i foreach_vec64u foreach_vec64f
  foreach_vec128i foreach_vec128u foreach_vec128f
  foreach_vec256i foreach_vec256u foreach_vec256f
  foreach_vec512i foreach_vec512u foreach_vec512f
/* clang-format on */
#undef _

  typedef union
{
#define _(t, s, c) t##s##x##c as_##t##s##x##c;
  foreach_vec128i foreach_vec128u foreach_vec128f
#undef _
} vec128_t;

typedef union
{
#define _(t, s, c) t##s##x##c as_##t##s##x##c;
  foreach_vec256i foreach_vec256u foreach_vec256f
#undef _
#define _(t, s, c) t##s##x##c as_##t##s##x##c[2];
    foreach_vec128i foreach_vec128u foreach_vec128f
#undef _
} vec256_t;

typedef union
{
#define _(t, s, c) t##s##x##c as_##t##s##x##c;
  foreach_vec512i foreach_vec512u foreach_vec512f
#undef _
#define _(t, s, c) t##s##x##c as_##t##s##x##c[2];
    foreach_vec256i foreach_vec256u foreach_vec256f
#undef _
#define _(t, s, c) t##s##x##c as_##t##s##x##c[4];
      foreach_vec128i foreach_vec128u foreach_vec128f
#undef _
} vec512_t;

/* universal inlines */
#define _(t, s, c)                                                            \
  static_always_inline t##s##x##c t##s##x##c##_zero ()                        \
  {                                                                           \
    return (t##s##x##c){};                                                    \
  }

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
  foreach_vec128i foreach_vec128u;
#undef _
#endif

static_always_inline u8
clib_bit_reverse_u8 (u8 x)
{
#if defined(__x86_64__) && defined(__GFNI__)
  u8x16 matrix = { 1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128 };
  u8x16 t = { x, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  t = (u8x16) _mm_gf2p8affine_epi64_epi8 ((__m128i) t, (__m128i) matrix, 0);

  return t[0];
#elif defined(__aarch64__) && !defined(__clang__)
  return (u8) (__builtin_aarch64_rbit ((u32) x) >> 24);
#else
  x = ((x & 0xF0u) >> 4) | ((x & 0x0Fu) << 4);
  x = ((x & 0xCCu) >> 2) | ((x & 0x33u) << 2);
  x = ((x & 0xAAu) >> 1) | ((x & 0x55u) << 1);
  return x;
#endif
}

static_always_inline u16
clib_bit_reverse_u16 (u16 x)
{
#if defined(__x86_64__) && defined(__GFNI__)
  u8x16 matrix = { 1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128 };
  u16x8 t = { x, 0, 0, 0, 0, 0, 0, 0 };

  t = (u16x8) _mm_gf2p8affine_epi64_epi8 ((__m128i) t, (__m128i) matrix, 0);

  return __builtin_bswap16 (t[0]);
#elif defined(__aarch64__) && !defined(__clang__)
  return (u16) (__builtin_aarch64_rbit ((u32) x) >> 16);
#else
  x = ((x & 0x00AAu) << 7) | ((x >> 1) & 0x0055u);
  x = ((x & 0x00CCu) << 5) | ((x >> 2) & 0x0033u);
  return (u16) ((x << 8) | (x >> 8));
#endif
}

static_always_inline u32
clib_bit_reverse_u32 (u32 x)
{
#if defined(__x86_64__) && defined(__GFNI__)
  u8x16 matrix = { 1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128 };
  u32x4 t = { x, 0, 0, 0 };

  t = (u32x4) _mm_gf2p8affine_epi64_epi8 ((__m128i) t, (__m128i) matrix, 0);

  return __builtin_bswap32 (t[0]);
#elif defined(__aarch64__) && !defined(__clang__)
  return __builtin_aarch64_rbit (x);
#else
  x = ((x & 0x55555555u) << 1) | ((x >> 1) & 0x55555555u);
  x = ((x & 0x33333333u) << 2) | ((x >> 2) & 0x33333333u);
  x = ((x & 0x0F0F0F0Fu) << 4) | ((x >> 4) & 0x0F0F0F0Fu);
  x = ((x & 0x00FF00FFu) << 8) | ((x >> 8) & 0x00FF00FFu);
  x = (x << 16) | (x >> 16);
  return x;
#endif
}

static_always_inline u64
clib_bit_reverse_u64 (u64 x)
{
#if defined(__x86_64__) && defined(__GFNI__)
  u8x16 matrix = { 1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128 };
  u64x2 t = { x, 0 };

  t = (u64x2) _mm_gf2p8affine_epi64_epi8 ((__m128i) t, (__m128i) matrix, 0);

  return __builtin_bswap64 (t[0]);
#elif defined(__aarch64__) && !defined(__clang__)
  return __builtin_aarch64_rbitll (x);
#else
  x = ((x & 0x5555555555555555ull) << 1) | ((x >> 1) & 0x5555555555555555ull);
  x = ((x & 0x3333333333333333ull) << 2) | ((x >> 2) & 0x3333333333333333ull);
  x = ((x & 0x0F0F0F0F0F0F0F0Full) << 4) | ((x >> 4) & 0x0F0F0F0F0F0F0F0Full);
  x = ((x & 0x00FF00FF00FF00FFull) << 8) | ((x >> 8) & 0x00FF00FF00FF00FFull);
  x =
    ((x & 0x0000FFFF0000FFFFull) << 16) | ((x >> 16) & 0x0000FFFF0000FFFFull);
  return (x << 32) | (x >> 32);
#endif
}
#ifndef CLIB_VEC128_INSERT_DEFINED
#define _(t, s, c)                                                            \
  static_always_inline t##s##x##c t##s##x##c##_insert (t##s##x##c v, t##s x,  \
						       int index)             \
  {                                                                           \
    t##s##x##c tmp = v;                                                       \
    tmp[index] = x;                                                           \
    return tmp;                                                               \
  }
foreach_vec128i foreach_vec128u
#undef _
#endif

#ifndef CLIB_VEC64_DYNAMIC_SHUFFLE_DEFINED

  static_always_inline u8x8
  u8x8_shuffle_dynamic (u8x8 v, u8x8 i)
{
  u8x8 tmp = { 0 };
#if defined(__clang__)
  tmp[0] = v[i[0] & 0x7];
  tmp[1] = v[i[1] & 0x7];
  tmp[2] = v[i[2] & 0x7];
  tmp[3] = v[i[3] & 0x7];
  tmp[4] = v[i[4] & 0x7];
  tmp[5] = v[i[5] & 0x7];
  tmp[6] = v[i[6] & 0x7];
  tmp[7] = v[i[7] & 0x7];
#else
  tmp = __builtin_shuffle (v, i);
#endif
  i >>= 7;  /* Get the MSB*/
  i -= 1;   /* each element is 0 if MSB was set, or 0xFF if not*/
  tmp &= i; /* Clear if MSB was set */
  return tmp;
}

static_always_inline u16x4
u16x4_shuffle_dynamic (u16x4 v, u16x4 i)
{
  u16x4 tmp = { 0 };
#if defined(__clang__)
  tmp[0] = v[i[0] & 0x3];
  tmp[1] = v[i[1] & 0x3];
  tmp[2] = v[i[2] & 0x3];
  tmp[3] = v[i[3] & 0x3];
#else
  tmp = __builtin_shuffle (v, i);
#endif
  i >>= 15;
  i -= 1;
  tmp &= i;
  return tmp;
}
#endif /* CLIB_VEC64_DYNAMIC_SHUFFLE_DEFINED */
#ifndef CLIB_VEC128_DYNAMIC_SHUFFLE_DEFINED
static_always_inline u8x16
u8x16_shuffle_dynamic (u8x16 v, u8x16 i)
{
  u8x16 tmp = { 0 };
#if defined(__clang__)
  tmp[0] = v[i[0] & 0xF];
  tmp[1] = v[i[1] & 0xF];
  tmp[2] = v[i[2] & 0xF];
  tmp[3] = v[i[3] & 0xF];
  tmp[4] = v[i[4] & 0xF];
  tmp[5] = v[i[5] & 0xF];
  tmp[6] = v[i[6] & 0xF];
  tmp[7] = v[i[7] & 0xF];
  tmp[8] = v[i[8] & 0xF];
  tmp[9] = v[i[9] & 0xF];
  tmp[10] = v[i[10] & 0xF];
  tmp[11] = v[i[11] & 0xF];
  tmp[12] = v[i[12] & 0xF];
  tmp[13] = v[i[13] & 0xF];
  tmp[14] = v[i[14] & 0xF];
  tmp[15] = v[i[15] & 0xF];
#else
  tmp = __builtin_shuffle (v, i);
#endif
  i >>= 7;
  i -= 1;
  tmp &= i;
  return tmp;
}

static_always_inline u16x8
u16x8_shuffle_dynamic (u16x8 v, u16x8 i)
{
  u16x8 tmp = { 0 };
#if defined(__clang__)
  tmp[0] = v[i[0] & 0x7];
  tmp[1] = v[i[1] & 0x7];
  tmp[2] = v[i[2] & 0x7];
  tmp[3] = v[i[3] & 0x7];
  tmp[4] = v[i[4] & 0x7];
  tmp[5] = v[i[5] & 0x7];
  tmp[6] = v[i[6] & 0x7];
  tmp[7] = v[i[7] & 0x7];
#else
  tmp = __builtin_shuffle (v, i);
#endif
  i >>= 15;
  i -= 1;
  tmp &= i;
  return tmp;
}

static_always_inline u32x4
u32x4_shuffle_dynamic (u32x4 v, u32x4 i)
{
  u32x4 tmp = { 0 };
#if defined(__clang__)
  tmp[0] = v[i[0] & 0x3];
  tmp[1] = v[i[1] & 0x3];
  tmp[2] = v[i[2] & 0x3];
  tmp[3] = v[i[3] & 0x3];
#else
  tmp = __builtin_shuffle (v, i);
#endif
  i >>= 31;
  i -= 1;
  tmp &= i;
  return tmp;
}
#endif /* CLIB_VEC128_DYNAMIC_SHUFFLE_DEFINED */

#ifndef CLIB_VEC256_DYNAMIC_SHUFFLE_DEFINED
static_always_inline u8x32
u8x32_shuffle_dynamic (u8x32 v, u8x32 i)
{
  u8x32 tmp = { 0 };
#if defined(__clang__)
  tmp[0] = v[i[0] & 0x1F];
  tmp[1] = v[i[1] & 0x1F];
  tmp[2] = v[i[2] & 0x1F];
  tmp[3] = v[i[3] & 0x1F];
  tmp[4] = v[i[4] & 0x1F];
  tmp[5] = v[i[5] & 0x1F];
  tmp[6] = v[i[6] & 0x1F];
  tmp[7] = v[i[7] & 0x1F];
  tmp[8] = v[i[8] & 0x1F];
  tmp[9] = v[i[9] & 0x1F];
  tmp[10] = v[i[10] & 0x1F];
  tmp[11] = v[i[11] & 0x1F];
  tmp[12] = v[i[12] & 0x1F];
  tmp[13] = v[i[13] & 0x1F];
  tmp[14] = v[i[14] & 0x1F];
  tmp[15] = v[i[15] & 0x1F];
  tmp[16] = v[i[16] & 0x1F];
  tmp[17] = v[i[17] & 0x1F];
  tmp[18] = v[i[18] & 0x1F];
  tmp[19] = v[i[19] & 0x1F];
  tmp[20] = v[i[20] & 0x1F];
  tmp[21] = v[i[21] & 0x1F];
  tmp[22] = v[i[22] & 0x1F];
  tmp[23] = v[i[23] & 0x1F];
  tmp[24] = v[i[24] & 0x1F];
  tmp[25] = v[i[25] & 0x1F];
  tmp[26] = v[i[26] & 0x1F];
  tmp[27] = v[i[27] & 0x1F];
  tmp[28] = v[i[28] & 0x1F];
  tmp[29] = v[i[29] & 0x1F];
  tmp[30] = v[i[30] & 0x1F];
  tmp[31] = v[i[31] & 0x1F];
#else
  tmp = __builtin_shuffle (v, i);
#endif
  i >>= 7;
  i -= 1;
  tmp &= i;
  return tmp;
}
static_always_inline u16x16
u16x16_shuffle_dynamic (u16x16 v, u16x16 i)
{
  u16x16 tmp = { 0 };
#if defined(__clang__)
  tmp[0] = v[i[0] & 0xF];
  tmp[1] = v[i[1] & 0xF];
  tmp[2] = v[i[2] & 0xF];
  tmp[3] = v[i[3] & 0xF];
  tmp[4] = v[i[4] & 0xF];
  tmp[5] = v[i[5] & 0xF];
  tmp[6] = v[i[6] & 0xF];
  tmp[7] = v[i[7] & 0xF];
  tmp[8] = v[i[8] & 0xF];
  tmp[9] = v[i[9] & 0xF];
  tmp[10] = v[i[10] & 0xF];
  tmp[11] = v[i[11] & 0xF];
  tmp[12] = v[i[12] & 0xF];
  tmp[13] = v[i[13] & 0xF];
  tmp[14] = v[i[14] & 0xF];
  tmp[15] = v[i[15] & 0xF];
#else
  tmp = __builtin_shuffle (v, i);
#endif
  i >>= 15;
  i -= 1;
  tmp &= i;
  return tmp;
}
static_always_inline u32x8
u32x8_shuffle_dynamic (u32x8 v, u32x8 i)
{
  u32x8 tmp = { 0 };
#if defined(__clang__)
  tmp[0] = v[i[0] & 0x7];
  tmp[1] = v[i[1] & 0x7];
  tmp[2] = v[i[2] & 0x7];
  tmp[3] = v[i[3] & 0x7];
  tmp[4] = v[i[4] & 0x7];
  tmp[5] = v[i[5] & 0x7];
  tmp[6] = v[i[6] & 0x7];
  tmp[7] = v[i[7] & 0x7];
#else
  tmp = __builtin_shuffle (v, i);
#endif
  i >>= 31;
  i -= 1;
  tmp &= i;
  return tmp;
}
#endif /* CLIB_VEC256_DYNAMIC_SHUFFLE_DEFINED */

#endif /* included_clib_vector_h */
