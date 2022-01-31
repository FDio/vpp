/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef included_vector_avx2_h
#define included_vector_avx2_h

#include <vppinfra/clib.h>
#include <x86intrin.h>

/* *INDENT-OFF* */
#define foreach_avx2_vec256i \
  _(i,8,32,epi8) _(i,16,16,epi16) _(i,32,8,epi32)  _(i,64,4,epi64)
#define foreach_avx2_vec256u \
  _(u,8,32,epi8) _(u,16,16,epi16) _(u,32,8,epi32)  _(u,64,4,epi64)
#define foreach_avx2_vec256f \
  _(f,32,8,ps) _(f,64,4,pd)

#define _mm256_set1_epi64 _mm256_set1_epi64x

/* load_unaligned, store_unaligned, is_all_zero, is_equal,
   is_all_equal */
#define _(t, s, c, i) \
static_always_inline t##s##x##c						\
t##s##x##c##_load_unaligned (void *p)					\
{ return (t##s##x##c) _mm256_loadu_si256 (p); }				\
\
static_always_inline void						\
t##s##x##c##_store_unaligned (t##s##x##c v, void *p)			\
{ _mm256_storeu_si256 ((__m256i *) p, (__m256i) v); }			\
\
static_always_inline int						\
t##s##x##c##_is_all_zero (t##s##x##c x)					\
{ return _mm256_testz_si256 ((__m256i) x, (__m256i) x); }		\
\
static_always_inline int						\
t##s##x##c##_is_equal (t##s##x##c a, t##s##x##c b)			\
{ return t##s##x##c##_is_all_zero (a ^ b); }				\
\
static_always_inline int						\
t##s##x##c##_is_all_equal (t##s##x##c v, t##s x)			\
{ return t##s##x##c##_is_equal (v, t##s##x##c##_splat (x)); }		\
\
static_always_inline t##s##x##c                                         \
t##s##x##c##_interleave_lo (t##s##x##c a, t##s##x##c b)                 \
{ return (t##s##x##c) _mm256_unpacklo_##i ((__m256i) a, (__m256i) b); } \
\
static_always_inline t##s##x##c                                         \
t##s##x##c##_interleave_hi (t##s##x##c a, t##s##x##c b)                 \
{ return (t##s##x##c) _mm256_unpackhi_##i ((__m256i) a, (__m256i) b); } \


foreach_avx2_vec256i foreach_avx2_vec256u
#undef _
/* *INDENT-ON* */

always_inline u32x8
u32x8_permute (u32x8 v, u32x8 idx)
{
  return (u32x8) _mm256_permutevar8x32_epi32 ((__m256i) v, (__m256i) idx);
}

#define u64x4_permute(v, m0, m1, m2, m3)                                      \
  (u64x4) _mm256_permute4x64_epi64 (                                          \
    (__m256i) v, ((m0) | (m1) << 2 | (m2) << 4 | (m3) << 6))

/* _extract_lo, _extract_hi */
/* *INDENT-OFF* */
#define _(t1,t2) \
always_inline t1							\
t2##_extract_lo (t2 v)							\
{ return (t1) _mm256_extracti128_si256 ((__m256i) v, 0); }		\
\
always_inline t1							\
t2##_extract_hi (t2 v)							\
{ return (t1) _mm256_extracti128_si256 ((__m256i) v, 1); }		\
\
always_inline t2							\
t2##_insert_lo (t2 v1, t1 v2)						\
{ return (t2) _mm256_inserti128_si256 ((__m256i) v1, (__m128i) v2, 0); }\
\
always_inline t2							\
t2##_insert_hi (t2 v1, t1 v2)						\
{ return (t2) _mm256_inserti128_si256 ((__m256i) v1, (__m128i) v2, 1); }\

_(u8x16, u8x32)
_(u16x8, u16x16)
_(u32x4, u32x8)
_(u64x2, u64x4)
#undef _
/* *INDENT-ON* */

/* 256 bit packs. */
#define _(f, t, fn)                                                           \
  always_inline t t##_pack (f lo, f hi)                                       \
  {                                                                           \
    return (t) fn ((__m256i) lo, (__m256i) hi);                               \
  }

_ (i16x16, i8x32, _mm256_packs_epi16)
_ (i16x16, u8x32, _mm256_packus_epi16)
_ (i32x8, i16x16, _mm256_packs_epi32)
_ (i32x8, u16x16, _mm256_packus_epi32)

#undef _

static_always_inline u32
u8x32_msb_mask (u8x32 v)
{
  return _mm256_movemask_epi8 ((__m256i) v);
}

static_always_inline u32
i8x32_msb_mask (i8x32 v)
{
  return _mm256_movemask_epi8 ((__m256i) v);
}

/* _from_ */
/* *INDENT-OFF* */
#define _(f,t,i) \
static_always_inline t							\
t##_from_##f (f x)							\
{ return (t) _mm256_cvt##i ((__m128i) x); }

_(u16x8, u32x8, epu16_epi32)
_(u16x8, u64x4, epu16_epi64)
_(u32x4, u64x4, epu32_epi64)
_ (u8x16, u16x16, epu8_epi16)
_(u8x16, u32x8, epu8_epi32)
_(u8x16, u64x4, epu8_epi64)
_(i16x8, i32x8, epi16_epi32)
_(i16x8, i64x4, epi16_epi64)
_(i32x4, i64x4, epi32_epi64)
_ (i8x16, i16x16, epi8_epi16)
_(i8x16, i32x8, epi8_epi32)
_(i8x16, i64x4, epi8_epi64)
#undef _
/* *INDENT-ON* */

static_always_inline u64x4
u64x4_byte_swap (u64x4 v)
{
  u8x32 swap = {
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
    7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
  };
  return (u64x4) _mm256_shuffle_epi8 ((__m256i) v, (__m256i) swap);
}

static_always_inline u32x8
u32x8_byte_swap (u32x8 v)
{
  u8x32 swap = {
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
  };
  return (u32x8) _mm256_shuffle_epi8 ((__m256i) v, (__m256i) swap);
}

static_always_inline u16x16
u16x16_byte_swap (u16x16 v)
{
  u8x32 swap = {
    1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14,
    1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14
  };
  return (u16x16) _mm256_shuffle_epi8 ((__m256i) v, (__m256i) swap);
}

#define u8x32_align_right(a, b, imm) \
  (u8x32) _mm256_alignr_epi8 ((__m256i) a, (__m256i) b, imm)

#define u64x4_align_right(a, b, imm)                                          \
  (u64x4) _mm256_alignr_epi64 ((__m256i) a, (__m256i) b, imm)

static_always_inline u32
u32x8_sum_elts (u32x8 sum8)
{
  sum8 += (u32x8) u8x32_align_right (sum8, sum8, 8);
  sum8 += (u32x8) u8x32_align_right (sum8, sum8, 4);
  return sum8[0] + sum8[4];
}

static_always_inline u32x8
u32x8_hadd (u32x8 v1, u32x8 v2)
{
  return (u32x8) _mm256_hadd_epi32 ((__m256i) v1, (__m256i) v2);
}

static_always_inline u32
u32x8_hxor (u32x8 v)
{
  u32x4 v4;
  v4 = u32x8_extract_lo (v) ^ u32x8_extract_hi (v);
  v4 ^= (u32x4) u8x16_align_right (v4, v4, 8);
  v4 ^= (u32x4) u8x16_align_right (v4, v4, 4);
  return v4[0];
}

static_always_inline u16x16
u16x16_mask_last (u16x16 v, u8 n_last)
{
  const u16x16 masks[17] = {
    {0},
    {-1},
    {-1, -1},
    {-1, -1, -1},
    {-1, -1, -1, -1},
    {-1, -1, -1, -1, -1},
    {-1, -1, -1, -1, -1, -1},
    {-1, -1, -1, -1, -1, -1, -1},
    {-1, -1, -1, -1, -1, -1, -1, -1},
    {-1, -1, -1, -1, -1, -1, -1, -1, -1},
    {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
    {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
    {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
    {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
    {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
    {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
    {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1},
  };

  ASSERT (n_last < 17);

  return v & masks[16 - n_last];
}

static_always_inline f32x8
f32x8_from_u32x8 (u32x8 v)
{
  return (f32x8) _mm256_cvtepi32_ps ((__m256i) v);
}

static_always_inline u32x8
u32x8_from_f32x8 (f32x8 v)
{
  return (u32x8) _mm256_cvttps_epi32 ((__m256) v);
}

#define u32x8_blend(a,b,m) \
  (u32x8) _mm256_blend_epi32 ((__m256i) a, (__m256i) b, m)

#define u16x16_blend(v1, v2, mask) \
  (u16x16) _mm256_blend_epi16 ((__m256i) (v1), (__m256i) (v2), mask)

static_always_inline u64x4
u64x4_gather (void *p0, void *p1, void *p2, void *p3)
{
  u64x4 r = {
    *(u64 *) p0, *(u64 *) p1, *(u64 *) p2, *(u64 *) p3
  };
  return r;
}

static_always_inline u32x8
u32x8_gather (void *p0, void *p1, void *p2, void *p3, void *p4, void *p5,
	      void *p6, void *p7)
{
  u32x8 r = {
    *(u32 *) p0, *(u32 *) p1, *(u32 *) p2, *(u32 *) p3,
    *(u32 *) p4, *(u32 *) p5, *(u32 *) p6, *(u32 *) p7,
  };
  return r;
}


static_always_inline void
u64x4_scatter (u64x4 r, void *p0, void *p1, void *p2, void *p3)
{
  *(u64 *) p0 = r[0];
  *(u64 *) p1 = r[1];
  *(u64 *) p2 = r[2];
  *(u64 *) p3 = r[3];
}

static_always_inline void
u32x8_scatter (u32x8 r, void *p0, void *p1, void *p2, void *p3, void *p4,
	       void *p5, void *p6, void *p7)
{
  *(u32 *) p0 = r[0];
  *(u32 *) p1 = r[1];
  *(u32 *) p2 = r[2];
  *(u32 *) p3 = r[3];
  *(u32 *) p4 = r[4];
  *(u32 *) p5 = r[5];
  *(u32 *) p6 = r[6];
  *(u32 *) p7 = r[7];
}

static_always_inline void
u64x4_scatter_one (u64x4 r, int index, void *p)
{
  *(u64 *) p = r[index];
}

static_always_inline void
u32x8_scatter_one (u32x8 r, int index, void *p)
{
  *(u32 *) p = r[index];
}

static_always_inline u8x32
u8x32_is_greater (u8x32 v1, u8x32 v2)
{
  return (u8x32) _mm256_cmpgt_epi8 ((__m256i) v1, (__m256i) v2);
}

static_always_inline u8x32
u8x32_blend (u8x32 v1, u8x32 v2, u8x32 mask)
{
  return (u8x32) _mm256_blendv_epi8 ((__m256i) v1, (__m256i) v2,
				     (__m256i) mask);
}

#define u32x8_permute_lanes(a, b, m) \
  (u32x8) _mm256_permute2x128_si256 ((__m256i) a, (__m256i) b, m)
#define u64x4_permute_lanes(a, b, m) \
  (u64x4) _mm256_permute2x128_si256 ((__m256i) a, (__m256i) b, m)

static_always_inline u32x8
u32x8_min (u32x8 a, u32x8 b)
{
  return (u32x8) _mm256_min_epu32 ((__m256i) a, (__m256i) b);
}

static_always_inline u32
u32x8_min_scalar (u32x8 v)
{
  return u32x4_min_scalar (u32x4_min (u32x8_extract_lo (v),
				      u32x8_extract_hi (v)));
}

static_always_inline void
u32x8_transpose (u32x8 a[8])
{
  u64x4 r[8], x, y;

  r[0] = (u64x4) u32x8_interleave_lo (a[0], a[1]);
  r[1] = (u64x4) u32x8_interleave_hi (a[0], a[1]);
  r[2] = (u64x4) u32x8_interleave_lo (a[2], a[3]);
  r[3] = (u64x4) u32x8_interleave_hi (a[2], a[3]);
  r[4] = (u64x4) u32x8_interleave_lo (a[4], a[5]);
  r[5] = (u64x4) u32x8_interleave_hi (a[4], a[5]);
  r[6] = (u64x4) u32x8_interleave_lo (a[6], a[7]);
  r[7] = (u64x4) u32x8_interleave_hi (a[6], a[7]);

  x = u64x4_interleave_lo (r[0], r[2]);
  y = u64x4_interleave_lo (r[4], r[6]);
  a[0] = u32x8_permute_lanes (x, y, 0x20);
  a[4] = u32x8_permute_lanes (x, y, 0x31);

  x = u64x4_interleave_hi (r[0], r[2]);
  y = u64x4_interleave_hi (r[4], r[6]);
  a[1] = u32x8_permute_lanes (x, y, 0x20);
  a[5] = u32x8_permute_lanes (x, y, 0x31);

  x = u64x4_interleave_lo (r[1], r[3]);
  y = u64x4_interleave_lo (r[5], r[7]);
  a[2] = u32x8_permute_lanes (x, y, 0x20);
  a[6] = u32x8_permute_lanes (x, y, 0x31);

  x = u64x4_interleave_hi (r[1], r[3]);
  y = u64x4_interleave_hi (r[5], r[7]);
  a[3] = u32x8_permute_lanes (x, y, 0x20);
  a[7] = u32x8_permute_lanes (x, y, 0x31);
}

static_always_inline void
u64x4_transpose (u64x4 a[8])
{
  u64x4 r[4];

  r[0] = u64x4_interleave_lo (a[0], a[1]);
  r[1] = u64x4_interleave_hi (a[0], a[1]);
  r[2] = u64x4_interleave_lo (a[2], a[3]);
  r[3] = u64x4_interleave_hi (a[2], a[3]);

  a[0] = u64x4_permute_lanes (r[0], r[2], 0x20);
  a[1] = u64x4_permute_lanes (r[1], r[3], 0x20);
  a[2] = u64x4_permute_lanes (r[0], r[2], 0x31);
  a[3] = u64x4_permute_lanes (r[1], r[3], 0x31);
}

#endif /* included_vector_avx2_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
