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

#ifndef included_vector_avx512_h
#define included_vector_avx512_h

#include <vppinfra/clib.h>
#include <x86intrin.h>

#define foreach_avx512_vec512i \
  _(i,8,64,epi8) _(i,16,32,epi16) _(i,32,16,epi32)  _(i,64,8,epi64)
#define foreach_avx512_vec512u \
  _(u,8,64,epi8) _(u,16,32,epi16) _(u,32,16,epi32)  _(u,64,8,epi64)
#define foreach_avx512_vec512f \
  _(f,32,8,ps) _(f,64,4,pd)

/* load_unaligned, store_unaligned, is_all_zero, is_equal,
   is_all_equal, is_zero_mask */
#ifdef CLIB_HAVE_VEC512
#define _(t, s, c, i)                                                         \
  static_always_inline int t##s##x##c##_is_all_zero (t##s##x##c v)            \
  {                                                                           \
    return (_mm512_test_epi64_mask ((__m512i) v, (__m512i) v) == 0);          \
  }                                                                           \
                                                                              \
  static_always_inline int t##s##x##c##_is_equal (t##s##x##c a, t##s##x##c b) \
  {                                                                           \
    return t##s##x##c##_is_all_zero (a ^ b);                                  \
  }                                                                           \
                                                                              \
  static_always_inline int t##s##x##c##_is_all_equal (t##s##x##c v, t##s x)   \
  {                                                                           \
    return t##s##x##c##_is_equal (v, t##s##x##c##_splat (x));                 \
  }                                                                           \
                                                                              \
  static_always_inline u##c t##s##x##c##_is_zero_mask (t##s##x##c v)          \
  {                                                                           \
    return _mm512_test_##i##_mask ((__m512i) v, (__m512i) v);                 \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_interleave_lo (t##s##x##c a,   \
							      t##s##x##c b)   \
  {                                                                           \
    return (t##s##x##c) _mm512_unpacklo_##i ((__m512i) a, (__m512i) b);       \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_interleave_hi (t##s##x##c a,   \
							      t##s##x##c b)   \
  {                                                                           \
    return (t##s##x##c) _mm512_unpackhi_##i ((__m512i) a, (__m512i) b);       \
  }

foreach_avx512_vec512i foreach_avx512_vec512u
#undef _
#endif

  static_always_inline u32
  u16x32_msb_mask (u16x32 v)
{
  return (u32) _mm512_movepi16_mask ((__m512i) v);
}

/* 512-bit packs */
#define _(f, t, fn)                                                           \
  always_inline t t##_pack (f lo, f hi)                                       \
  {                                                                           \
    return (t) fn ((__m512i) lo, (__m512i) hi);                               \
  }

_ (i16x32, i8x64, _mm512_packs_epi16)
_ (i16x32, u8x64, _mm512_packus_epi16)
_ (i32x16, i16x32, _mm512_packs_epi32)
_ (i32x16, u16x32, _mm512_packus_epi32)
#undef _

static_always_inline u64x8
u64x8_byte_swap (u64x8 v)
{
  u8x64 swap = {
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
  };
  return (u64x8) _mm512_shuffle_epi8 ((__m512i) v, (__m512i) swap);
}

static_always_inline u32x16
u32x16_byte_swap (u32x16 v)
{
  u8x64 swap = {
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
  };
  return (u32x16) _mm512_shuffle_epi8 ((__m512i) v, (__m512i) swap);
}

static_always_inline u16x32
u16x32_byte_swap (u16x32 v)
{
  u8x64 swap = {
    1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14,
    1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14,
    1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14,
    1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14
  };
  return (u16x32) _mm512_shuffle_epi8 ((__m512i) v, (__m512i) swap);
}

#define _(f, t)                                                               \
  static_always_inline t f##_extract_lo (f v)                                 \
  {                                                                           \
    return (t) _mm512_extracti64x4_epi64 ((__m512i) v, 0);                    \
  }                                                                           \
  static_always_inline t f##_extract_hi (f v)                                 \
  {                                                                           \
    return (t) _mm512_extracti64x4_epi64 ((__m512i) v, 1);                    \
  }

_ (u64x8, u64x4)
_ (u32x16, u32x8)
_ (u16x32, u16x16)
_ (u8x64, u8x32)
#undef _

static_always_inline u32
u32x16_min_scalar (u32x16 v)
{
  return u32x8_min_scalar (u32x8_min (u32x16_extract_lo (v),
				      u32x16_extract_hi (v)));
}

static_always_inline u32x16
u32x16_insert_lo (u32x16 r, u32x8 v)
{
  return (u32x16) _mm512_inserti64x4 ((__m512i) r, (__m256i) v, 0);
}

static_always_inline u32x16
u32x16_insert_hi (u32x16 r, u32x8 v)
{
  return (u32x16) _mm512_inserti64x4 ((__m512i) r, (__m256i) v, 1);
}

static_always_inline u64x8
u64x8_permute (u64x8 a, u64x8 b, u64x8 mask)
{
  return (u64x8) _mm512_permutex2var_epi64 ((__m512i) a, (__m512i) mask,
					    (__m512i) b);
}


#define u32x16_ternary_logic(a, b, c, d) \
  (u32x16) _mm512_ternarylogic_epi32 ((__m512i) a, (__m512i) b, (__m512i) c, d)

#define u8x64_insert_u8x16(a, b, n) \
  (u8x64) _mm512_inserti64x2 ((__m512i) (a), (__m128i) (b), n)

#define u8x64_extract_u8x16(a, n) \
  (u8x16) _mm512_extracti64x2_epi64 ((__m512i) (a), n)

#define u8x64_word_shift_left(a,n)  (u8x64) _mm512_bslli_epi128((__m512i) a, n)
#define u8x64_word_shift_right(a,n) (u8x64) _mm512_bsrli_epi128((__m512i) a, n)

static_always_inline u8x64
u8x64_xor3 (u8x64 a, u8x64 b, u8x64 c)
{
  return (u8x64) _mm512_ternarylogic_epi32 ((__m512i) a, (__m512i) b,
					    (__m512i) c, 0x96);
}

static_always_inline u64x8
u64x8_xor3 (u64x8 a, u64x8 b, u64x8 c)
{
  return (u64x8) _mm512_ternarylogic_epi32 ((__m512i) a, (__m512i) b,
					    (__m512i) c, 0x96);
}

static_always_inline u8x64
u8x64_reflect_u8x16 (u8x64 x)
{
  static const u8x64 mask = {
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
  };
  return (u8x64) _mm512_shuffle_epi8 ((__m512i) x, (__m512i) mask);
}

#define u8x64_align_right(a, b, imm) \
  (u8x64) _mm512_alignr_epi8 ((__m512i) a, (__m512i) b, imm)

#define u64x8_align_right(a, b, imm)                                          \
  (u64x8) _mm512_alignr_epi64 ((__m512i) a, (__m512i) b, imm)

static_always_inline u32
u32x16_sum_elts (u32x16 sum16)
{
  u32x8 sum8;
  sum16 += (u32x16) u8x64_align_right (sum16, sum16, 8);
  sum16 += (u32x16) u8x64_align_right (sum16, sum16, 4);
  sum8 = u32x16_extract_hi (sum16) + u32x16_extract_lo (sum16);
  return sum8[0] + sum8[4];
}

#define _(t, m, p, i, e)                                                      \
  static_always_inline t t##_mask_load (t a, void *p, m mask)                 \
  {                                                                           \
    return (t) p##_mask_loadu_##e ((i) a, mask, p);                           \
  }                                                                           \
  static_always_inline t t##_mask_load_zero (void *p, m mask)                 \
  {                                                                           \
    return (t) p##_maskz_loadu_##e (mask, p);                                 \
  }                                                                           \
  static_always_inline void t##_mask_store (t a, void *p, m mask)             \
  {                                                                           \
    p##_mask_storeu_##e (p, mask, (i) a);                                     \
  }

_ (u8x64, u64, _mm512, __m512i, epi8)
_ (u8x32, u32, _mm256, __m256i, epi8)
_ (u8x16, u16, _mm, __m128i, epi8)
_ (u16x32, u32, _mm512, __m512i, epi16)
_ (u16x16, u16, _mm256, __m256i, epi16)
_ (u16x8, u8, _mm, __m128i, epi16)
_ (u32x16, u16, _mm512, __m512i, epi32)
_ (u32x8, u8, _mm256, __m256i, epi32)
_ (u32x4, u8, _mm, __m128i, epi32)
_ (u64x8, u8, _mm512, __m512i, epi64)
_ (u64x4, u8, _mm256, __m256i, epi64)
_ (u64x2, u8, _mm, __m128i, epi64)
#undef _

#define _(t, m, p, i, e)                                                      \
  static_always_inline t t##_mask_and (t a, t b, m mask)                      \
  {                                                                           \
    return (t) p##_mask_and_##e ((i) a, mask, (i) a, (i) b);                  \
  }                                                                           \
  static_always_inline t t##_mask_andnot (t a, t b, m mask)                   \
  {                                                                           \
    return (t) p##_mask_andnot_##e ((i) a, mask, (i) a, (i) b);               \
  }                                                                           \
  static_always_inline t t##_mask_xor (t a, t b, m mask)                      \
  {                                                                           \
    return (t) p##_mask_xor_##e ((i) a, mask, (i) a, (i) b);                  \
  }                                                                           \
  static_always_inline t t##_mask_or (t a, t b, m mask)                       \
  {                                                                           \
    return (t) p##_mask_or_##e ((i) a, mask, (i) a, (i) b);                   \
  }
_ (u32x16, u16, _mm512, __m512i, epi32)
_ (u32x8, u8, _mm256, __m256i, epi32)
_ (u32x4, u8, _mm, __m128i, epi32)
_ (u64x8, u8, _mm512, __m512i, epi64)
_ (u64x4, u8, _mm256, __m256i, epi64)
_ (u64x2, u8, _mm, __m128i, epi64)
#undef _

#ifdef CLIB_HAVE_VEC512
#define CLIB_HAVE_VEC512_MASK_LOAD_STORE
#define CLIB_HAVE_VEC512_MASK_BITWISE_OPS
#endif
#ifdef CLIB_HAVE_VEC256
#define CLIB_HAVE_VEC256_MASK_LOAD_STORE
#define CLIB_HAVE_VEC256_MASK_BITWISE_OPS
#endif
#ifdef CLIB_HAVE_VEC128
#define CLIB_HAVE_VEC128_MASK_LOAD_STORE
#define CLIB_HAVE_VEC128_MASK_BITWISE_OPS
#endif

static_always_inline u8x64
u8x64_splat_u8x16 (u8x16 a)
{
  return (u8x64) _mm512_broadcast_i64x2 ((__m128i) a);
}

static_always_inline u32x16
u32x16_splat_u32x4 (u32x4 a)
{
  return (u32x16) _mm512_broadcast_i64x2 ((__m128i) a);
}

static_always_inline u32x16
u32x16_mask_blend (u32x16 a, u32x16 b, u16 mask)
{
  return (u32x16) _mm512_mask_blend_epi32 (mask, (__m512i) a, (__m512i) b);
}

static_always_inline u8x64
u8x64_mask_blend (u8x64 a, u8x64 b, u64 mask)
{
  return (u8x64) _mm512_mask_blend_epi8 (mask, (__m512i) a, (__m512i) b);
}

static_always_inline u8x64
u8x64_permute (u8x64 idx, u8x64 a)
{
  return (u8x64) _mm512_permutexvar_epi8 ((__m512i) idx, (__m512i) a);
}

static_always_inline u8x64
u8x64_permute2 (u8x64 idx, u8x64 a, u8x64 b)
{
  return (u8x64) _mm512_permutex2var_epi8 ((__m512i) a, (__m512i) idx,
					   (__m512i) b);
}

#define _(t, m, e, p, it)                                                     \
  static_always_inline m t##_is_equal_mask (t a, t b)                         \
  {                                                                           \
    return p##_cmpeq_##e##_mask ((it) a, (it) b);                             \
  }
_ (u8x16, u16, epu8, _mm, __m128i)
_ (u16x8, u8, epu16, _mm, __m128i)
_ (u32x4, u8, epu32, _mm, __m128i)
_ (u64x2, u8, epu64, _mm, __m128i)

_ (u8x32, u32, epu8, _mm256, __m256i)
_ (u16x16, u16, epu16, _mm256, __m256i)
_ (u32x8, u8, epu32, _mm256, __m256i)
_ (u64x4, u8, epu64, _mm256, __m256i)

_ (u8x64, u64, epu8, _mm512, __m512i)
_ (u16x32, u32, epu16, _mm512, __m512i)
_ (u32x16, u16, epu32, _mm512, __m512i)
_ (u64x8, u8, epu64, _mm512, __m512i)
#undef _

#define _(t, m, e, p, it)                                                     \
  static_always_inline m t##_is_not_equal_mask (t a, t b)                     \
  {                                                                           \
    return p##_cmpneq_##e##_mask ((it) a, (it) b);                            \
  }
_ (u8x16, u16, epu8, _mm, __m128i)
_ (u16x8, u8, epu16, _mm, __m128i)
_ (u32x4, u8, epu32, _mm, __m128i)
_ (u64x2, u8, epu64, _mm, __m128i)

_ (u8x32, u32, epu8, _mm256, __m256i)
_ (u16x16, u16, epu16, _mm256, __m256i)
_ (u32x8, u8, epu32, _mm256, __m256i)
_ (u64x4, u8, epu64, _mm256, __m256i)

_ (u8x64, u64, epu8, _mm512, __m512i)
_ (u16x32, u32, epu16, _mm512, __m512i)
_ (u32x16, u16, epu32, _mm512, __m512i)
_ (u64x8, u8, epu64, _mm512, __m512i)
#undef _

#define _(f, t, fn, it)                                                       \
  static_always_inline t t##_from_##f (f x) { return (t) fn ((it) x); }
_ (u16x16, u32x16, _mm512_cvtepi16_epi32, __m256i)
_ (u32x16, u16x16, _mm512_cvtusepi32_epi16, __m512i)
_ (u32x8, u16x8, _mm256_cvtusepi32_epi16, __m256i)
_ (u32x8, u64x8, _mm512_cvtepu32_epi64, __m256i)
#undef _

#define _(vt, mt, p, it, epi)                                                 \
  static_always_inline vt vt##_compress (vt a, mt mask)                       \
  {                                                                           \
    return (vt) p##_maskz_compress_##epi (mask, (it) a);                      \
  }                                                                           \
  static_always_inline vt vt##_expand (vt a, mt mask)                         \
  {                                                                           \
    return (vt) p##_maskz_expand_##epi (mask, (it) a);                        \
  }                                                                           \
  static_always_inline void vt##_compress_store (vt v, mt mask, void *p)      \
  {                                                                           \
    p##_mask_compressstoreu_##epi (p, mask, (it) v);                          \
  }

_ (u64x8, u8, _mm512, __m512i, epi64)
_ (u32x16, u16, _mm512, __m512i, epi32)
_ (u64x4, u8, _mm256, __m256i, epi64)
_ (u32x8, u8, _mm256, __m256i, epi32)
_ (u64x2, u8, _mm, __m128i, epi64)
_ (u32x4, u8, _mm, __m128i, epi32)
#ifdef __AVX512VBMI2__
_ (u16x32, u32, _mm512, __m512i, epi16)
_ (u8x64, u64, _mm512, __m512i, epi8)
_ (u16x16, u16, _mm256, __m256i, epi16)
_ (u8x32, u32, _mm256, __m256i, epi8)
_ (u16x8, u8, _mm, __m128i, epi16)
_ (u8x16, u16, _mm, __m128i, epi8)
#endif
#undef _

#ifdef CLIB_HAVE_VEC256
#define CLIB_HAVE_VEC256_COMPRESS
#ifdef __AVX512VBMI2__
#define CLIB_HAVE_VEC256_COMPRESS_U8_U16
#endif

#endif
#ifdef CLIB_HAVE_VEC512
#define CLIB_HAVE_VEC512_COMPRESS
#ifdef __AVX512VBMI2__
#define CLIB_HAVE_VEC512_COMPRESS_U8_U16
#endif

#endif

#ifndef __AVX512VBMI2__
static_always_inline u16x16
u16x16_compress (u16x16 v, u16 mask)
{
  return u16x16_from_u32x16 (u32x16_compress (u32x16_from_u16x16 (v), mask));
}

static_always_inline u16x8
u16x8_compress (u16x8 v, u8 mask)
{
  return u16x8_from_u32x8 (u32x8_compress (u32x8_from_u16x8 (v), mask));
}
#endif

static_always_inline u64
u64x8_hxor (u64x8 v)
{
  v ^= u64x8_align_right (v, v, 4);
  v ^= u64x8_align_right (v, v, 2);
  return v[0] ^ v[1];
}

static_always_inline void
u32x16_transpose (u32x16 m[16])
{
  __m512i r[16], a, b, c, d, x, y;

  /* *INDENT-OFF* */
  __m512i pm1 = (__m512i) (u64x8) { 0, 1, 8, 9, 4, 5, 12, 13};
  __m512i pm2 = (__m512i) (u64x8) { 2, 3, 10, 11, 6, 7, 14, 15};
  __m512i pm3 = (__m512i) (u64x8) { 0, 1, 2, 3, 8, 9, 10, 11};
  __m512i pm4 = (__m512i) (u64x8) { 4, 5, 6, 7, 12, 13, 14, 15};
  /* *INDENT-ON* */

  r[0] = _mm512_unpacklo_epi32 ((__m512i) m[0], (__m512i) m[1]);
  r[1] = _mm512_unpacklo_epi32 ((__m512i) m[2], (__m512i) m[3]);
  r[2] = _mm512_unpacklo_epi32 ((__m512i) m[4], (__m512i) m[5]);
  r[3] = _mm512_unpacklo_epi32 ((__m512i) m[6], (__m512i) m[7]);
  r[4] = _mm512_unpacklo_epi32 ((__m512i) m[8], (__m512i) m[9]);
  r[5] = _mm512_unpacklo_epi32 ((__m512i) m[10], (__m512i) m[11]);
  r[6] = _mm512_unpacklo_epi32 ((__m512i) m[12], (__m512i) m[13]);
  r[7] = _mm512_unpacklo_epi32 ((__m512i) m[14], (__m512i) m[15]);

  r[8] = _mm512_unpackhi_epi32 ((__m512i) m[0], (__m512i) m[1]);
  r[9] = _mm512_unpackhi_epi32 ((__m512i) m[2], (__m512i) m[3]);
  r[10] = _mm512_unpackhi_epi32 ((__m512i) m[4], (__m512i) m[5]);
  r[11] = _mm512_unpackhi_epi32 ((__m512i) m[6], (__m512i) m[7]);
  r[12] = _mm512_unpackhi_epi32 ((__m512i) m[8], (__m512i) m[9]);
  r[13] = _mm512_unpackhi_epi32 ((__m512i) m[10], (__m512i) m[11]);
  r[14] = _mm512_unpackhi_epi32 ((__m512i) m[12], (__m512i) m[13]);
  r[15] = _mm512_unpackhi_epi32 ((__m512i) m[14], (__m512i) m[15]);

  a = _mm512_unpacklo_epi64 (r[0], r[1]);
  b = _mm512_unpacklo_epi64 (r[2], r[3]);
  c = _mm512_unpacklo_epi64 (r[4], r[5]);
  d = _mm512_unpacklo_epi64 (r[6], r[7]);
  x = _mm512_permutex2var_epi64 (a, pm1, b);
  y = _mm512_permutex2var_epi64 (c, pm1, d);
  m[0] = (u32x16) _mm512_permutex2var_epi64 (x, pm3, y);
  m[8] = (u32x16) _mm512_permutex2var_epi64 (x, pm4, y);
  x = _mm512_permutex2var_epi64 (a, pm2, b);
  y = _mm512_permutex2var_epi64 (c, pm2, d);
  m[4] = (u32x16) _mm512_permutex2var_epi64 (x, pm3, y);
  m[12] = (u32x16) _mm512_permutex2var_epi64 (x, pm4, y);

  a = _mm512_unpacklo_epi64 (r[8], r[9]);
  b = _mm512_unpacklo_epi64 (r[10], r[11]);
  c = _mm512_unpacklo_epi64 (r[12], r[13]);
  d = _mm512_unpacklo_epi64 (r[14], r[15]);
  x = _mm512_permutex2var_epi64 (a, pm1, b);
  y = _mm512_permutex2var_epi64 (c, pm1, d);
  m[2] = (u32x16) _mm512_permutex2var_epi64 (x, pm3, y);
  m[10] = (u32x16) _mm512_permutex2var_epi64 (x, pm4, y);
  x = _mm512_permutex2var_epi64 (a, pm2, b);
  y = _mm512_permutex2var_epi64 (c, pm2, d);
  m[6] = (u32x16) _mm512_permutex2var_epi64 (x, pm3, y);
  m[14] = (u32x16) _mm512_permutex2var_epi64 (x, pm4, y);

  a = _mm512_unpackhi_epi64 (r[0], r[1]);
  b = _mm512_unpackhi_epi64 (r[2], r[3]);
  c = _mm512_unpackhi_epi64 (r[4], r[5]);
  d = _mm512_unpackhi_epi64 (r[6], r[7]);
  x = _mm512_permutex2var_epi64 (a, pm1, b);
  y = _mm512_permutex2var_epi64 (c, pm1, d);
  m[1] = (u32x16) _mm512_permutex2var_epi64 (x, pm3, y);
  m[9] = (u32x16) _mm512_permutex2var_epi64 (x, pm4, y);
  x = _mm512_permutex2var_epi64 (a, pm2, b);
  y = _mm512_permutex2var_epi64 (c, pm2, d);
  m[5] = (u32x16) _mm512_permutex2var_epi64 (x, pm3, y);
  m[13] = (u32x16) _mm512_permutex2var_epi64 (x, pm4, y);

  a = _mm512_unpackhi_epi64 (r[8], r[9]);
  b = _mm512_unpackhi_epi64 (r[10], r[11]);
  c = _mm512_unpackhi_epi64 (r[12], r[13]);
  d = _mm512_unpackhi_epi64 (r[14], r[15]);
  x = _mm512_permutex2var_epi64 (a, pm1, b);
  y = _mm512_permutex2var_epi64 (c, pm1, d);
  m[3] = (u32x16) _mm512_permutex2var_epi64 (x, pm3, y);
  m[11] = (u32x16) _mm512_permutex2var_epi64 (x, pm4, y);
  x = _mm512_permutex2var_epi64 (a, pm2, b);
  y = _mm512_permutex2var_epi64 (c, pm2, d);
  m[7] = (u32x16) _mm512_permutex2var_epi64 (x, pm3, y);
  m[15] = (u32x16) _mm512_permutex2var_epi64 (x, pm4, y);
}



static_always_inline void
u64x8_transpose (u64x8 m[8])
{
  __m512i r[8], x, y;

  /* *INDENT-OFF* */
  __m512i pm1 = (__m512i) (u64x8) { 0, 1, 8, 9, 4, 5, 12, 13};
  __m512i pm2 = (__m512i) (u64x8) { 2, 3, 10, 11, 6, 7, 14, 15};
  __m512i pm3 = (__m512i) (u64x8) { 0, 1, 2, 3, 8, 9, 10, 11};
  __m512i pm4 = (__m512i) (u64x8) { 4, 5, 6, 7, 12, 13, 14, 15};
  /* *INDENT-ON* */

  r[0] = _mm512_unpacklo_epi64 ((__m512i) m[0], (__m512i) m[1]);
  r[1] = _mm512_unpacklo_epi64 ((__m512i) m[2], (__m512i) m[3]);
  r[2] = _mm512_unpacklo_epi64 ((__m512i) m[4], (__m512i) m[5]);
  r[3] = _mm512_unpacklo_epi64 ((__m512i) m[6], (__m512i) m[7]);
  r[4] = _mm512_unpackhi_epi64 ((__m512i) m[0], (__m512i) m[1]);
  r[5] = _mm512_unpackhi_epi64 ((__m512i) m[2], (__m512i) m[3]);
  r[6] = _mm512_unpackhi_epi64 ((__m512i) m[4], (__m512i) m[5]);
  r[7] = _mm512_unpackhi_epi64 ((__m512i) m[6], (__m512i) m[7]);

  x = _mm512_permutex2var_epi64 (r[0], pm1, r[1]);
  y = _mm512_permutex2var_epi64 (r[2], pm1, r[3]);
  m[0] = (u64x8) _mm512_permutex2var_epi64 (x, pm3, y);
  m[4] = (u64x8) _mm512_permutex2var_epi64 (x, pm4, y);
  x = _mm512_permutex2var_epi64 (r[0], pm2, r[1]);
  y = _mm512_permutex2var_epi64 (r[2], pm2, r[3]);
  m[2] = (u64x8) _mm512_permutex2var_epi64 (x, pm3, y);
  m[6] = (u64x8) _mm512_permutex2var_epi64 (x, pm4, y);

  x = _mm512_permutex2var_epi64 (r[4], pm1, r[5]);
  y = _mm512_permutex2var_epi64 (r[6], pm1, r[7]);
  m[1] = (u64x8) _mm512_permutex2var_epi64 (x, pm3, y);
  m[5] = (u64x8) _mm512_permutex2var_epi64 (x, pm4, y);
  x = _mm512_permutex2var_epi64 (r[4], pm2, r[5]);
  y = _mm512_permutex2var_epi64 (r[6], pm2, r[7]);
  m[3] = (u64x8) _mm512_permutex2var_epi64 (x, pm3, y);
  m[7] = (u64x8) _mm512_permutex2var_epi64 (x, pm4, y);
}

#endif /* included_vector_avx512_h */
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
