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

#ifndef included_vector_sse2_h
#define included_vector_sse2_h

#include <vppinfra/error_bootstrap.h>	/* for ASSERT */
#include <x86intrin.h>

/* *INDENT-OFF* */
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
/* *INDENT-ON* */

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

/* 64 bit interleaves. */
always_inline u8x8
u8x8_interleave_hi (u8x8 a, u8x8 b)
{
  return (u8x8) _m_punpckhbw ((__m64) a, (__m64) b);
}

always_inline u8x8
u8x8_interleave_lo (u8x8 a, u8x8 b)
{
  return (u8x8) _m_punpcklbw ((__m64) a, (__m64) b);
}

always_inline u16x4
u16x4_interleave_hi (u16x4 a, u16x4 b)
{
  return (u16x4) _m_punpckhwd ((__m64) a, (__m64) b);
}

always_inline u16x4
u16x4_interleave_lo (u16x4 a, u16x4 b)
{
  return (u16x4) _m_punpcklwd ((__m64) a, (__m64) b);
}

always_inline u32x2
u32x2_interleave_hi (u32x2 a, u32x2 b)
{
  return (u32x2) _m_punpckhdq ((__m64) a, (__m64) b);
}

always_inline u32x2
u32x2_interleave_lo (u32x2 a, u32x2 b)
{
  return (u32x2) _m_punpckldq ((__m64) a, (__m64) b);
}

/* 128 bit packs. */
always_inline u8x16
u16x8_pack (u16x8 lo, u16x8 hi)
{
  return (u8x16) _mm_packus_epi16 ((__m128i) lo, (__m128i) hi);
}

always_inline i8x16
i16x8_pack (i16x8 lo, i16x8 hi)
{
  return (i8x16) _mm_packs_epi16 ((__m128i) lo, (__m128i) hi);
}

always_inline u16x8
u32x4_pack (u32x4 lo, u32x4 hi)
{
  return (u16x8) _mm_packs_epi32 ((__m128i) lo, (__m128i) hi);
}

/* 64 bit packs. */
always_inline u8x8
u16x4_pack (u16x4 lo, u16x4 hi)
{
  return (u8x8) _m_packuswb ((__m64) lo, (__m64) hi);
}

always_inline i8x8
i16x4_pack (i16x4 lo, i16x4 hi)
{
  return (i8x8) _m_packsswb ((__m64) lo, (__m64) hi);
}

always_inline u16x4
u32x2_pack (u32x2 lo, u32x2 hi)
{
  return (u16x4) _m_packssdw ((__m64) lo, (__m64) hi);
}

always_inline i16x4
i32x2_pack (i32x2 lo, i32x2 hi)
{
  return (i16x4) _m_packssdw ((__m64) lo, (__m64) hi);
}

#ifndef __ICC
always_inline u64x2
u64x2_read_lo (u64x2 x, u64 * a)
{
  return (u64x2) _mm_loadl_pi ((__m128) x, (__m64 *) a);
}

always_inline u64x2
u64x2_read_hi (u64x2 x, u64 * a)
{
  return (u64x2) _mm_loadh_pi ((__m128) x, (__m64 *) a);
}

always_inline void
u64x2_write_lo (u64x2 x, u64 * a)
{
  _mm_storel_pi ((__m64 *) a, (__m128) x);
}

always_inline void
u64x2_write_hi (u64x2 x, u64 * a)
{
  _mm_storeh_pi ((__m64 *) a, (__m128) x);
}
#endif

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
/* 64 bit shifts. */
  always_inline u16x4
u16x4_shift_left (u16x4 x, u16x4 i)
{
  return (u16x4) _m_psllw ((__m64) x, (__m64) i);
};

always_inline u32x2
u32x2_shift_left (u32x2 x, u32x2 i)
{
  return (u32x2) _m_pslld ((__m64) x, (__m64) i);
};

always_inline u16x4
u16x4_shift_right (u16x4 x, u16x4 i)
{
  return (u16x4) _m_psrlw ((__m64) x, (__m64) i);
};

always_inline u32x2
u32x2_shift_right (u32x2 x, u32x2 i)
{
  return (u32x2) _m_psrld ((__m64) x, (__m64) i);
};

always_inline i16x4
i16x4_shift_left (i16x4 x, i16x4 i)
{
  return (i16x4) _m_psllw ((__m64) x, (__m64) i);
};

always_inline i32x2
i32x2_shift_left (i32x2 x, i32x2 i)
{
  return (i32x2) _m_pslld ((__m64) x, (__m64) i);
};

always_inline i16x4
i16x4_shift_right (i16x4 x, i16x4 i)
{
  return (i16x4) _m_psraw ((__m64) x, (__m64) i);
};

always_inline i32x2
i32x2_shift_right (i32x2 x, i32x2 i)
{
  return (i32x2) _m_psrad ((__m64) x, (__m64) i);
};

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

#ifndef __clang__
#define _(t,n,lr1,lr2)						\
  always_inline t##x##n						\
  t##x##n##_word_rotate2_##lr1 (t##x##n w0, t##x##n w1, int i)	\
  {								\
    int m = sizeof (t##x##n) / sizeof (t);			\
    ASSERT (i >= 0 && i < m);					\
    return (t##x##n##_word_shift_##lr1 (w0, i)			\
	    | t##x##n##_word_shift_##lr2 (w1, m - i));		\
  }								\
								\
  always_inline t##x##n						\
  t##x##n##_word_rotate_##lr1 (t##x##n w0, int i)		\
  { return t##x##n##_word_rotate2_##lr1 (w0, w0, i); }

_(u8, 16, left, right);
_(u8, 16, right, left);
_(u16, 8, left, right);
_(u16, 8, right, left);
_(u32, 4, left, right);
_(u32, 4, right, left);
_(u64, 2, left, right);
_(u64, 2, right, left);

#undef _
#endif

#define u32x4_select(A,MASK)						\
({									\
  u32x4 _x, _y;								\
  _x = (A);								\
  asm volatile ("pshufd %[mask], %[x], %[y]"				\
		: /* outputs */ [y] "=x" (_y)				\
		: /* inputs */  [x] "x" (_x), [mask] "i" (MASK));	\
  _y;									\
})

#define u32x4_splat_word(x,i)			\
  u32x4_select ((x), (((i) << (2*0))		\
		      | ((i) << (2*1))		\
		      | ((i) << (2*2))		\
		      | ((i) << (2*3))))

/* Extract low order 32 bit word. */
always_inline u32
u32x4_get0 (u32x4 x)
{
  u32 result;
  asm volatile ("movd %[x], %[result]": /* outputs */ [result] "=r" (result)
		: /* inputs */ [x] "x" (x));
  return result;
}

always_inline u32x4
u32x4_set0 (u32 x)
{
  u32x4 result;
  asm volatile ("movd %[x], %[result]": /* outputs */ [result] "=x" (result)
		: /* inputs */ [x] "r" (x));
  return result;
}

always_inline i32x4
i32x4_set0 (i32 x)
{
  return (i32x4) u32x4_set0 ((u32) x);
}

always_inline i32
i32x4_get0 (i32x4 x)
{
  return (i32) u32x4_get0 ((u32x4) x);
}

/* Converts all ones/zeros compare mask to bitmap. */
always_inline u32
u8x16_compare_byte_mask (u8x16 x)
{
  return _mm_movemask_epi8 ((__m128i) x);
}

extern u8 u32x4_compare_word_mask_table[256];

always_inline u32
u32x4_compare_word_mask (u32x4 x)
{
  u32 m = u8x16_compare_byte_mask ((u8x16) x);
  return (u32x4_compare_word_mask_table[(m >> 0) & 0xff]
	  | (u32x4_compare_word_mask_table[(m >> 8) & 0xff] << 2));
}

always_inline u32
u8x16_zero_byte_mask (u8x16 x)
{
  u8x16 zero = { 0 };
  return u8x16_compare_byte_mask (x == zero);
}

always_inline u32
u16x8_zero_byte_mask (u16x8 x)
{
  u16x8 zero = { 0 };
  return u8x16_compare_byte_mask ((u8x16) (x == zero));
}

always_inline u32
u32x4_zero_byte_mask (u32x4 x)
{
  u32x4 zero = { 0 };
  return u8x16_compare_byte_mask ((u8x16) (x == zero));
}

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

static_always_inline u8x16
u8x16_shuffle (u8x16 v, u8x16 m)
{
  return (u8x16) _mm_shuffle_epi8 ((__m128i) v, (__m128i) m);
}

static_always_inline u32x4
u32x4_shuffle (u32x4 v, const int a, const int b, const int c, const int d)
{
#if defined(__clang__) || !__OPTIMIZE__
  u32x4 r = { v[a], v[b], v[c], v[d] };
  return r;
#else
  return (u32x4) _mm_shuffle_epi32 ((__m128i) v,
				    a | b << 2 | c << 4 | d << 6);
#endif
}

/* _from_ */
/* *INDENT-OFF* */
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
/* *INDENT-ON* */

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
u8x16_is_greater (u8x16 v1, u8x16 v2)
{
  return (u8x16) _mm_cmpgt_epi8 ((__m128i) v1, (__m128i) v2);
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

#ifdef __AVX512F__
static_always_inline u8x16
u8x16_mask_load (u8x16 a, void *p, u16 mask)
{
  return (u8x16) _mm_mask_loadu_epi8 ((__m128i) a, mask, p);
}
#endif

#endif /* included_vector_sse2_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
