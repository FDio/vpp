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

/* Splats: replicate scalar value into vector. */
always_inline u64x2
u64x2_splat (u64 a)
{
  u64x2 x = { a, a };
  return x;
}

always_inline u32x4
u32x4_splat (u32 a)
{
  u32x4 x = { a, a, a, a };
  return x;
}

always_inline u16x8
u16x8_splat (u16 a)
{
  u16x8 x = { a, a, a, a, a, a, a, a };
  return x;
}

always_inline u8x16
u8x16_splat (u8 a)
{
  u8x16 x = { a, a, a, a, a, a, a, a, a, a, a, a, a, a, a, a };
  return x;
}

always_inline u32x2
u32x2_splat (u32 a)
{
  u32x2 x = { a, a };
  return x;
}

always_inline u16x4
u16x4_splat (u16 a)
{
  u16x4 x = { a, a, a, a };
  return x;
}

always_inline u8x8
u8x8_splat (u8 a)
{
  u8x8 x = { a, a, a, a, a, a, a, a };
  return x;
}

#define i64x2_splat u64x2_splat
#define i32x4_splat u32x4_splat
#define i16x8_splat u16x8_splat
#define i8x16_splat u8x16_splat
#define i32x2_splat u32x2_splat
#define i16x4_splat u16x4_splat
#define i8x8_splat u8x8_splat

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

/* Unaligned loads/stores. */

#define _(t)						\
  always_inline void t##_store_unaligned (t x, t * a)	\
  { _mm_storeu_si128 ((__m128i *) a, (__m128i) x); }	\
  always_inline t t##_load_unaligned (t * a)		\
  { return (t) _mm_loadu_si128 ((__m128i *) a); }

_(u8x16) _(u16x8) _(u32x4) _(u64x2) _(i8x16) _(i16x8) _(i32x4) _(i64x2)
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
/* Addition/subtraction. */
  _signed_binop (8, 16, add, add_epi)
_signed_binop (16, 8, add, add_epi)
_signed_binop (32, 4, add, add_epi)
_signed_binop (64, 2, add, add_epi)
_signed_binop (8, 16, sub, sub_epi)
_signed_binop (16, 8, sub, sub_epi)
_signed_binop (32, 4, sub, sub_epi) _signed_binop (64, 2, sub, sub_epi)
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

/* Compare operations. */
always_inline u8x16
u8x16_is_equal (u8x16 x, u8x16 y)
{
  return (u8x16) _mm_cmpeq_epi8 ((__m128i) x, (__m128i) y);
}

always_inline i8x16
i8x16_is_equal (i8x16 x, i8x16 y)
{
  return (i8x16) _mm_cmpeq_epi8 ((__m128i) x, (__m128i) y);
}

always_inline u16x8
u16x8_is_equal (u16x8 x, u16x8 y)
{
  return (u16x8) _mm_cmpeq_epi16 ((__m128i) x, (__m128i) y);
}

always_inline i16x8
i16x8_is_equal (i16x8 x, i16x8 y)
{
  return (i16x8) _mm_cmpeq_epi16 ((__m128i) x, (__m128i) y);
}

always_inline u32x4
u32x4_is_equal (u32x4 x, u32x4 y)
{
  return (u32x4) _mm_cmpeq_epi32 ((__m128i) x, (__m128i) y);
}

always_inline i32x4
i32x4_is_equal (i32x4 x, i32x4 y)
{
  return (i32x4) _mm_cmpeq_epi32 ((__m128i) x, (__m128i) y);
}

always_inline u8x16
i8x16_is_greater (i8x16 x, i8x16 y)
{
  return (u8x16) _mm_cmpgt_epi8 ((__m128i) x, (__m128i) y);
}

always_inline u16x8
i16x8_is_greater (i16x8 x, i16x8 y)
{
  return (u16x8) _mm_cmpgt_epi16 ((__m128i) x, (__m128i) y);
}

always_inline u32x4
i32x4_is_greater (i32x4 x, i32x4 y)
{
  return (u32x4) _mm_cmpgt_epi32 ((__m128i) x, (__m128i) y);
}

always_inline u8x16
u8x16_is_zero (u8x16 x)
{
  u8x16 zero = { 0 };
  return u8x16_is_equal (x, zero);
}

always_inline u16x8
u16x8_is_zero (u16x8 x)
{
  u16x8 zero = { 0 };
  return u16x8_is_equal (x, zero);
}

always_inline u32x4
u32x4_is_zero (u32x4 x)
{
  u32x4 zero = { 0 };
  return u32x4_is_equal (x, zero);
}

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
  return u8x16_compare_byte_mask (u8x16_is_equal (x, zero));
}

always_inline u32
u16x8_zero_byte_mask (u16x8 x)
{
  u16x8 zero = { 0 };
  return u8x16_compare_byte_mask ((u8x16) u16x8_is_equal (x, zero));
}

always_inline u32
u32x4_zero_byte_mask (u32x4 x)
{
  u32x4 zero = { 0 };
  return u8x16_compare_byte_mask ((u8x16) u32x4_is_equal (x, zero));
}

always_inline u8x16
u8x16_max (u8x16 x, u8x16 y)
{
  return (u8x16) _mm_max_epu8 ((__m128i) x, (__m128i) y);
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

always_inline u8x16
u8x16_min (u8x16 x, u8x16 y)
{
  return (u8x16) _mm_min_epu8 ((__m128i) x, (__m128i) y);
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

always_inline i16x8
i16x8_max (i16x8 x, i16x8 y)
{
  return (i16x8) _mm_max_epi16 ((__m128i) x, (__m128i) y);
}

always_inline i16
i16x8_max_scalar (i16x8 x)
{
  x = i16x8_max (x, i16x8_word_shift_right (x, 4));
  x = i16x8_max (x, i16x8_word_shift_right (x, 2));
  x = i16x8_max (x, i16x8_word_shift_right (x, 1));
  return _mm_extract_epi16 ((__m128i) x, 0);
}

always_inline i16x8
i16x8_min (i16x8 x, i16x8 y)
{
  return (i16x8) _mm_min_epi16 ((__m128i) x, (__m128i) y);
}

always_inline i16
i16x8_min_scalar (i16x8 x)
{
  x = i16x8_min (x, i16x8_word_shift_right (x, 4));
  x = i16x8_min (x, i16x8_word_shift_right (x, 2));
  x = i16x8_min (x, i16x8_word_shift_right (x, 1));
  return _mm_extract_epi16 ((__m128i) x, 0);
}

#undef _signed_binop

#endif /* included_vector_sse2_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
