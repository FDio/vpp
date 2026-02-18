/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2005 Eliot Dresselhaus
 */

#ifndef included_vector_sse2_h
#define included_vector_sse2_h

#include <vppinfra/error_bootstrap.h>	/* for ASSERT */
#include <x86intrin.h>

#define foreach_sse42_vec128i \
  _(i,8,16,epi8) _(i,16,8,epi16) _(i,32,4,epi32)  _(i,64,2,epi64x)
#define foreach_sse42_vec128u \
  _(u,8,16,epi8) _(u,16,8,epi16) _(u,32,4,epi32)  _(u,64,2,epi64x)
#define foreach_sse42_vec128f \
  _(f,32,4,ps) _(f,64,2,pd)

/* splat, load_unaligned, store_unaligned, is_all_zero, is_equal,
   is_all_equal */
#define _(t, s, c, i) \
static_always_inline t##s##x##c						\
t##s##x##c##_splat (t##s x)						\
{ return (t##s##x##c) _mm_set1_##i (x); }				\
\
static_always_inline t##s##x##c						\
t##s##x##c##_load_unaligned (void *p)					\
{ return (t##s##x##c) _mm_loadu_si128 (p); }				\
\
static_always_inline void						\
t##s##x##c##_store_unaligned (t##s##x##c v, void *p)			\
{ _mm_storeu_si128 ((__m128i *) p, (__m128i) v); }			\
\
static_always_inline int						\
t##s##x##c##_is_all_zero (t##s##x##c x)					\
{ return _mm_testz_si128 ((__m128i) x, (__m128i) x); }			\
\
static_always_inline int						\
t##s##x##c##_is_equal (t##s##x##c a, t##s##x##c b)			\
{ return t##s##x##c##_is_all_zero (a ^ b); }				\
\
static_always_inline int						\
t##s##x##c##_is_all_equal (t##s##x##c v, t##s x)			\
{ return t##s##x##c##_is_equal (v, t##s##x##c##_splat (x)); };		\

foreach_sse42_vec128i foreach_sse42_vec128u
#undef _

/* min, max */
#define _(t, s, c, i) \
static_always_inline t##s##x##c						\
t##s##x##c##_min (t##s##x##c a, t##s##x##c b)				\
{ return (t##s##x##c) _mm_min_##i ((__m128i) a, (__m128i) b); }		\
\
static_always_inline t##s##x##c						\
t##s##x##c##_max (t##s##x##c a, t##s##x##c b)				\
{ return (t##s##x##c) _mm_max_##i ((__m128i) a, (__m128i) b); }		\

_(i,8,16,epi8) _(i,16,8,epi16) _(i,32,4,epi32)  _(i,64,2,epi64)
_(u,8,16,epu8) _(u,16,8,epu16) _(u,32,4,epu32)  _(u,64,2,epu64)
#undef _

#define CLIB_VEC128_SPLAT_DEFINED
#define CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE

/* 128 bit interleaves. */
always_inline u8x16
u8x16_interleave_hi (u8x16 a, u8x16 b)
{
  return (u8x16) _mm_unpackhi_epi8 ((__m128i) a, (__m128i) b);
}

always_inline u8x16
u8x16_interleave_lo (u8x16 a, u8x16 b)
{
  return (u8x16) _mm_unpacklo_epi8 ((__m128i) a, (__m128i) b);
}

always_inline u16x8
u16x8_interleave_hi (u16x8 a, u16x8 b)
{
  return (u16x8) _mm_unpackhi_epi16 ((__m128i) a, (__m128i) b);
}

always_inline u16x8
u16x8_interleave_lo (u16x8 a, u16x8 b)
{
  return (u16x8) _mm_unpacklo_epi16 ((__m128i) a, (__m128i) b);
}

always_inline u32x4
u32x4_interleave_hi (u32x4 a, u32x4 b)
{
  return (u32x4) _mm_unpackhi_epi32 ((__m128i) a, (__m128i) b);
}

always_inline u32x4
u32x4_interleave_lo (u32x4 a, u32x4 b)
{
  return (u32x4) _mm_unpacklo_epi32 ((__m128i) a, (__m128i) b);
}

always_inline u64x2
u64x2_interleave_hi (u64x2 a, u64x2 b)
{
  return (u64x2) _mm_unpackhi_epi64 ((__m128i) a, (__m128i) b);
}

always_inline u64x2
u64x2_interleave_lo (u64x2 a, u64x2 b)
{
  return (u64x2) _mm_unpacklo_epi64 ((__m128i) a, (__m128i) b);
}

/* 128 bit packs. */
#define _(f, t, fn)                                                           \
  always_inline t t##_pack (f lo, f hi)                                       \
  {                                                                           \
    return (t) fn ((__m128i) lo, (__m128i) hi);                               \
  }

_ (i16x8, i8x16, _mm_packs_epi16)
_ (i16x8, u8x16, _mm_packus_epi16)
_ (i32x4, i16x8, _mm_packs_epi32)
_ (i32x4, u16x8, _mm_packus_epi32)

#undef _

#define _signed_binop(n,m,f,g)                                         \
  /* Unsigned */                                                       \
  always_inline u##n##x##m                                             \
  u##n##x##m##_##f (u##n##x##m x, u##n##x##m y)                        \
  { return (u##n##x##m) _mm_##g##n ((__m128i) x, (__m128i) y); } \
                                                                       \
  /* Signed */                                                         \
  always_inline i##n##x##m                                             \
  i##n##x##m##_##f (i##n##x##m x, i##n##x##m y)                        \
  { return (i##n##x##m) _mm_##g##n ((__m128i) x, (__m128i) y); }
/* Addition/subtraction with saturation. */
_signed_binop (8, 16, add_saturate, adds_epu)
_signed_binop (16, 8, add_saturate, adds_epu)
_signed_binop (8, 16, sub_saturate, subs_epu)
_signed_binop (16, 8, sub_saturate, subs_epu)
/* Multiplication. */
     always_inline i16x8 i16x8_mul_lo (i16x8 x, i16x8 y)
{
  return (i16x8) _mm_mullo_epi16 ((__m128i) x, (__m128i) y);
}

always_inline u16x8
u16x8_mul_lo (u16x8 x, u16x8 y)
{
  return (u16x8) _mm_mullo_epi16 ((__m128i) x, (__m128i) y);
}

always_inline i16x8
i16x8_mul_hi (i16x8 x, i16x8 y)
{
  return (i16x8) _mm_mulhi_epu16 ((__m128i) x, (__m128i) y);
}

always_inline u16x8
u16x8_mul_hi (u16x8 x, u16x8 y)
{
  return (u16x8) _mm_mulhi_epu16 ((__m128i) x, (__m128i) y);
}

/* 128 bit shifts. */

#define _(p,a,b,c,f)           \
  always_inline p##a##x##b p##a##x##b##_ishift_##c (p##a##x##b x, int i)       \
  { return (p##a##x##b) _mm_##f##i_epi##a ((__m128i) x, i); }                  \
                                                                               \
  always_inline p##a##x##b p##a##x##b##_shift_##c (p##a##x##b x, p##a##x##b y) \
  { return (p##a##x##b) _mm_##f##_epi##a ((__m128i) x, (__m128i) y); }

_(u, 16, 8, left, sll)
_(u, 32, 4, left, sll)
_(u, 64, 2, left, sll)
_(u, 16, 8, right, srl)
_(u, 32, 4, right, srl)
_(u, 64, 2, right, srl)
_(i, 16, 8, left, sll)
_(i, 32, 4, left, sll)
_(i, 64, 2, left, sll) _(i, 16, 8, right, sra) _(i, 32, 4, right, sra)
#undef _

#define u8x16_word_shift_left(a,n)  (u8x16) _mm_slli_si128((__m128i) a, n)
#define u8x16_word_shift_right(a,n) (u8x16) _mm_srli_si128((__m128i) a, n)

#define i8x16_word_shift_left(a,n) \
  ((i8x16) u8x16_word_shift_left((u8x16) (a), (n)))
#define i8x16_word_shift_right(a,n) \
  ((i8x16) u8x16_word_shift_right((u8x16) (a), (n)))

#define u16x8_word_shift_left(a,n) \
  ((u16x8) u8x16_word_shift_left((u8x16) (a), (n) * sizeof (u16)))
#define i16x8_word_shift_left(a,n) \
  ((u16x8) u8x16_word_shift_left((u8x16) (a), (n) * sizeof (u16)))
#define u16x8_word_shift_right(a,n) \
  ((u16x8) u8x16_word_shift_right((u8x16) (a), (n) * sizeof (u16)))
#define i16x8_word_shift_right(a,n) \
  ((i16x8) u8x16_word_shift_right((u8x16) (a), (n) * sizeof (u16)))

#define u32x4_word_shift_left(a,n) \
  ((u32x4) u8x16_word_shift_left((u8x16) (a), (n) * sizeof (u32)))
#define i32x4_word_shift_left(a,n) \
  ((u32x4) u8x16_word_shift_left((u8x16) (a), (n) * sizeof (u32)))
#define u32x4_word_shift_right(a,n) \
  ((u32x4) u8x16_word_shift_right((u8x16) (a), (n) * sizeof (u32)))
#define i32x4_word_shift_right(a,n) \
  ((i32x4) u8x16_word_shift_right((u8x16) (a), (n) * sizeof (u32)))

#define u64x2_word_shift_left(a,n) \
  ((u64x2) u8x16_word_shift_left((u8x16) (a), (n) * sizeof (u64)))
#define i64x2_word_shift_left(a,n) \
  ((u64x2) u8x16_word_shift_left((u8x16) (a), (n) * sizeof (u64)))
#define u64x2_word_shift_right(a,n) \
  ((u64x2) u8x16_word_shift_right((u8x16) (a), (n) * sizeof (u64)))
#define i64x2_word_shift_right(a,n) \
  ((i64x2) u8x16_word_shift_right((u8x16) (a), (n) * sizeof (u64)))

/* SSE2 has no rotate instructions: use shifts to simulate them. */
#define _(t,n,lr1,lr2)					\
  always_inline t##x##n					\
  t##x##n##_irotate_##lr1 (t##x##n w, int i)		\
  {							\
    ASSERT (i >= 0 && i <= BITS (t));			\
    return (t##x##n##_ishift_##lr1 (w, i)		\
	    | t##x##n##_ishift_##lr2 (w, BITS (t) - i)); \
  }							\
							\
  always_inline t##x##n					\
  t##x##n##_rotate_##lr1 (t##x##n w, t##x##n i)		\
  {							\
    t##x##n j = t##x##n##_splat (BITS (t));		\
    return (t##x##n##_shift_##lr1 (w, i)		\
	    | t##x##n##_shift_##lr2 (w, j - i));	\
  }

_(u16, 8, left, right);
_(u16, 8, right, left);
_(u32, 4, left, right);
_(u32, 4, right, left);
_(u64, 2, left, right);
_(u64, 2, right, left);

#undef _

always_inline u32
u8x16_max_scalar (u8x16 x)
{
  x = u8x16_max (x, u8x16_word_shift_right (x, 8));
  x = u8x16_max (x, u8x16_word_shift_right (x, 4));
  x = u8x16_max (x, u8x16_word_shift_right (x, 2));
  x = u8x16_max (x, u8x16_word_shift_right (x, 1));
  return _mm_extract_epi16 ((__m128i) x, 0) & 0xff;
}

always_inline u8
u8x16_min_scalar (u8x16 x)
{
  x = u8x16_min (x, u8x16_word_shift_right (x, 8));
  x = u8x16_min (x, u8x16_word_shift_right (x, 4));
  x = u8x16_min (x, u8x16_word_shift_right (x, 2));
  x = u8x16_min (x, u8x16_word_shift_right (x, 1));
  return _mm_extract_epi16 ((__m128i) x, 0) & 0xff;
}

always_inline i16
i16x8_max_scalar (i16x8 x)
{
  x = i16x8_max (x, i16x8_word_shift_right (x, 4));
  x = i16x8_max (x, i16x8_word_shift_right (x, 2));
  x = i16x8_max (x, i16x8_word_shift_right (x, 1));
  return _mm_extract_epi16 ((__m128i) x, 0);
}

always_inline i16
i16x8_min_scalar (i16x8 x)
{
  x = i16x8_min (x, i16x8_word_shift_right (x, 4));
  x = i16x8_min (x, i16x8_word_shift_right (x, 2));
  x = i16x8_min (x, i16x8_word_shift_right (x, 1));
  return _mm_extract_epi16 ((__m128i) x, 0);
}

#define u8x16_align_right(a, b, imm) \
  (u8x16) _mm_alignr_epi8 ((__m128i) a, (__m128i) b, imm)

static_always_inline u32
u32x4_min_scalar (u32x4 v)
{
  v = u32x4_min (v, (u32x4) u8x16_align_right ((u8x16) v, (u8x16) v, 8));
  v = u32x4_min (v, (u32x4) u8x16_align_right ((u8x16) v, (u8x16) v, 4));
  return v[0];
}

static_always_inline u32
u32x4_max_scalar (u32x4 v)
{
  v = u32x4_max (v, (u32x4) u8x16_align_right ((u8x16) v, (u8x16) v, 8));
  v = u32x4_max (v, (u32x4) u8x16_align_right ((u8x16) v, (u8x16) v, 4));
  return v[0];
}

static_always_inline u32
i32x4_min_scalar (i32x4 v)
{
  v = i32x4_min (v, (i32x4) u8x16_align_right ((u8x16) v, (u8x16) v, 8));
  v = i32x4_min (v, (i32x4) u8x16_align_right ((u8x16) v, (u8x16) v, 4));
  return v[0];
}

static_always_inline u32
i32x4_max_scalar (i32x4 v)
{
  v = i32x4_max (v, (i32x4) u8x16_align_right ((u8x16) v, (u8x16) v, 8));
  v = i32x4_max (v, (i32x4) u8x16_align_right ((u8x16) v, (u8x16) v, 4));
  return v[0];
}

static_always_inline u16
u8x16_msb_mask (u8x16 v)
{
  return _mm_movemask_epi8 ((__m128i) v);
}

static_always_inline u16
i8x16_msb_mask (i8x16 v)
{
  return _mm_movemask_epi8 ((__m128i) v);
}

#define CLIB_HAVE_VEC128_MSB_MASK

#undef _signed_binop

static_always_inline u32x4
u32x4_byte_swap (u32x4 v)
{
  u8x16 swap = {
    3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
  };
  return (u32x4) _mm_shuffle_epi8 ((__m128i) v, (__m128i) swap);
}

static_always_inline u16x8
u16x8_byte_swap (u16x8 v)
{
  u8x16 swap = {
    1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14,
  };
  return (u16x8) _mm_shuffle_epi8 ((__m128i) v, (__m128i) swap);
}

static_always_inline u8x16
u8x16_reflect (u8x16 v)
{
  u8x16 mask = {
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
  };
  return (u8x16) _mm_shuffle_epi8 ((__m128i) v, (__m128i) mask);
}

static_always_inline u8x16
u8x16_permute (u8x16 idx, u8x16 a)
{
  return (u8x16) _mm_shuffle_epi8 ((__m128i) a, (__m128i) idx);
}

static_always_inline u32x4
u32x4_hadd (u32x4 v1, u32x4 v2)
{
  return (u32x4) _mm_hadd_epi32 ((__m128i) v1, (__m128i) v2);
}

static_always_inline u32 __clib_unused
u32x4_sum_elts (u32x4 sum4)
{
  sum4 += (u32x4) u8x16_align_right (sum4, sum4, 8);
  sum4 += (u32x4) u8x16_align_right (sum4, sum4, 4);
  return sum4[0];
}

/* _from_ */
#define _(f,t,i) \
static_always_inline t							\
t##_from_##f (f x)							\
{ return (t) _mm_cvt##i ((__m128i) x); }

_(u8x16, u16x8, epu8_epi16)
_(u8x16, u32x4, epu8_epi32)
_(u8x16, u64x2, epu8_epi64)
_(u16x8, u32x4, epu16_epi32)
_(u16x8, u64x2, epu16_epi64)
_(u32x4, u64x2, epu32_epi64)

_(i8x16, i16x8, epi8_epi16)
_(i8x16, i32x4, epi8_epi32)
_(i8x16, i64x2, epi8_epi64)
_(i16x8, i32x4, epi16_epi32)
_(i16x8, i64x2, epi16_epi64)
_(i32x4, i64x2, epi32_epi64)
#undef _

static_always_inline u16x8
u16x8_from_u8x16_high (u8x16 v)
{
  return u16x8_from_u8x16 (u8x16_word_shift_right (v, 8));
}

static_always_inline u64x2
u64x2_gather (void *p0, void *p1)
{
  u64x2 r = { *(u64 *) p0, *(u64 *) p1 };
  return r;
}

static_always_inline u32x4
u32x4_gather (void *p0, void *p1, void *p2, void *p3)
{
  u32x4 r = { *(u32 *) p0, *(u32 *) p1, *(u32 *) p2, *(u32 *) p3 };
  return r;
}


static_always_inline void
u64x2_scatter (u64x2 r, void *p0, void *p1)
{
  *(u64 *) p0 = r[0];
  *(u64 *) p1 = r[1];
}

static_always_inline void
u32x4_scatter (u32x4 r, void *p0, void *p1, void *p2, void *p3)
{
  *(u32 *) p0 = r[0];
  *(u32 *) p1 = r[1];
  *(u32 *) p2 = r[2];
  *(u32 *) p3 = r[3];
}

static_always_inline void
u64x2_scatter_one (u64x2 r, int index, void *p)
{
  *(u64 *) p = r[index];
}

static_always_inline void
u32x4_scatter_one (u32x4 r, int index, void *p)
{
  *(u32 *) p = r[index];
}

static_always_inline u8x16
u8x16_blend (u8x16 v1, u8x16 v2, u8x16 mask)
{
  return (u8x16) _mm_blendv_epi8 ((__m128i) v1, (__m128i) v2, (__m128i) mask);
}

static_always_inline u8x16
u8x16_xor3 (u8x16 a, u8x16 b, u8x16 c)
{
#if __AVX512F__
  return (u8x16) _mm_ternarylogic_epi32 ((__m128i) a, (__m128i) b,
					 (__m128i) c, 0x96);
#endif
  return a ^ b ^ c;
}

static_always_inline u8x16
u8x16_load_partial (u8 *data, uword n)
{
  u8x16 r = {};
#if defined(CLIB_HAVE_VEC128_MASK_LOAD_STORE)
  return u8x16_mask_load_zero (data, pow2_mask (n));
#endif
  if (n > 7)
    {
      u64x2 r;
      r[1] = *(u64u *) (data + n - 8);
      r >>= (16 - n) * 8;
      r[0] = *(u64u *) data;
      return (u8x16) r;
    }
  else if (n > 3)
    {
      u32x4 r = {};
      r[1] = *(u32u *) (data + n - 4);
      r >>= (8 - n) * 8;
      r[0] = *(u32u *) data;
      return (u8x16) r;
    }
  else if (n > 1)
    {
      u16x8 r = {};
      r[1] = *(u16u *) (data + n - 2);
      r >>= (4 - n) * 8;
      r[0] = *(u16u *) data;
      return (u8x16) r;
    }
  else if (n > 0)
    r[0] = *data;
  return r;
}

static_always_inline void
u8x16_store_partial (u8x16 r, u8 *data, uword n)
{
#if defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
  u8x16_mask_store (r, data, pow2_mask (n));
#else
  if (n > 7)
    {
      *(u64u *) (data + n - 8) = ((u64x2) r)[1] << ((16 - n) * 8);
      *(u64u *) data = ((u64x2) r)[0];
    }
  else if (n > 3)
    {
      *(u32u *) (data + n - 4) = ((u32x4) r)[1] << ((8 - n) * 8);
      *(u32u *) data = ((u32x4) r)[0];
    }
  else if (n > 1)
    {
      *(u16u *) (data + n - 2) = ((u16x8) r)[1] << ((4 - n) * 8);
      *(u16u *) data = ((u16x8) r)[0];
    }
  else if (n > 0)
    data[0] = r[0];
#endif
}

#ifdef __PCLMUL__
static_always_inline u64x2
u64x2_clmul64 (u64x2 a, const int a_hi, u64x2 b, const int b_hi)
{
  u64x2 p;

  switch (a_hi + 2 * b_hi)
    {
    case 0:
      p = (u64x2) _mm_clmulepi64_si128 ((__m128i) a, (__m128i) b, 0x00);
      break;
    case 1:
      p = (u64x2) _mm_clmulepi64_si128 ((__m128i) a, (__m128i) b, 0x01);
      break;
    case 2:
      p = (u64x2) _mm_clmulepi64_si128 ((__m128i) a, (__m128i) b, 0x10);
      break;
    case 3:
      p = (u64x2) _mm_clmulepi64_si128 ((__m128i) a, (__m128i) b, 0x11);
      break;
    default:
      __builtin_unreachable ();
    }

  return p;
}
#endif
#define CLIB_VEC128_INSERT_DEFINED

#define u8x16_insert(v, x, i) (u8x16) _mm_insert_epi8 ((__m128i) v, x, i)
#define u16x8_insert(v, x, i) (u16x8) _mm_insert_epi16 ((__m128i) v, x, i)
#define u32x4_insert(v, x, i) (u32x4) _mm_insert_epi32 ((__m128i) v, x, i)
#define u64x2_insert(v, x, i) (u64x2) _mm_insert_epi64 ((__m128i) v, x, i)

#define CLIB_VEC64_DYNAMIC_SHUFFLE_DEFINED
static_always_inline u8x8
u8x8_shuffle_dynamic (u8x8 v, u8x8 indices)
{
  return (u8x8) _mm_shuffle_pi8 ((__m64) v, (__m64) indices);
}

static_always_inline u16x4
u16x4_shuffle_dynamic (u16x4 v, u16x4 indices)
{
  u16x8 res;
  /* indices_16 = {i0, i1, i2, i3}
     indices_8  = {2*i0, 2*i0 + 1,
		   2*i1, 2*i1 + 1,
		   2*i2, 2*i2 + 1,
		   2*i3, 2*i3 + 1}
  */
  u16x8 v2 = (u16x8) _mm_set1_epi64 ((__m64) v);
  u16x8 indices2 = (u16x8) _mm_set1_epi64 ((__m64) indices);
  u16x8 dbled = indices2 << 1;
  u16x8 plus_one = dbled + 1;
  u8x16 dbled_u8 = (u8x16) _mm_packs_epi16 ((__m128i) dbled, (__m128i) dbled);
  u8x16 plus_one_u8 =
    (u8x16) _mm_packs_epi16 ((__m128i) plus_one, (__m128i) plus_one);
  u8x16 indices_8 =
    (u8x16) _mm_unpacklo_epi8 ((__m128i) dbled_u8, (__m128i) plus_one_u8);
  res = (u16x8) _mm_shuffle_epi8 ((__m128i) v2, (__m128i) indices_8);
  return (u16x4) _mm_movepi64_pi64 ((__m128i) res);
}

#define CLIB_VEC128_DYNAMIC_SHUFFLE_DEFINED
#define u8x16_shuffle_dynamic(v, i)                                           \
  (u8x16) _mm_shuffle_epi8 ((__m128i) v, (__m128i) i)

static_always_inline u16x8
u16x8_shuffle_dynamic (u16x8 v, u16x8 indices)
{
  u16x8 res;
  /* indices_16 = {i0, i1, i2, i3, i4, i5, i6, i7}
     indices_8  = {2*i0, 2*i0 + 1,
		   2*i1, 2*i1 + 1,
		   2*i2, 2*i2 + 1,
		   2*i3, 2*i3 + 1,
		   2*i4, 2*i4 + 1,
		   2*i5, 2*i5 + 1,
		   2*i6, 2*i6 + 1,
		   2*i7, 2*i7 + 1}
  */
  u16x8 dbled = indices << 1;
  u16x8 plus_one = dbled + 1;
  u8x16 dbled_u8 = (u8x16) _mm_packs_epi16 ((__m128i) dbled, (__m128i) dbled);
  u8x16 plus_one_u8 =
    (u8x16) _mm_packs_epi16 ((__m128i) plus_one, (__m128i) plus_one);
  u8x16 indices_8 =
    (u8x16) _mm_unpacklo_epi8 ((__m128i) dbled_u8, (__m128i) plus_one_u8);
  res = (u16x8) _mm_shuffle_epi8 ((__m128i) v, (__m128i) indices_8);
  return res;
}

static_always_inline u32x4
u32x4_shuffle_dynamic (u32x4 v, u32x4 indices)
{
  u32x4 fourtupled = indices << 2;
  const u8x16 mask1 = { 0, 0, 0, 0, 4, 4, 4, 4, 8, 8, 8, 8, 12, 12, 12, 12 };
  const u8x16 offset = { 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3 };
  u8x16 new_mask =
    (u8x16) _mm_shuffle_epi8 ((__m128i) fourtupled, (__m128i) mask1);
  new_mask += offset;
  return (u32x4) _mm_shuffle_epi8 ((__m128i) v, (__m128i) new_mask);
}

#endif /* included_vector_sse2_h */
