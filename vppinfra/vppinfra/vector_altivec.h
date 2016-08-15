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
  Copyright (c) 2009 Eliot Dresselhaus

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

#ifndef included_vector_altivec_h
#define included_vector_altivec_h

/* Splats. */
#define _(t,n,ti,fi,tr,fr)						\
  always_inline t##x##n t##x##n##_splat (t v)				\
  { return (t##x##n) __builtin_altivec_##fi ((ti) v); }			\
									\
  always_inline t##x##n t##x##n##_splat_word (t##x##n x, int word_index) \
  { return (t##x##n) __builtin_altivec_##fr ((tr) x, word_index); }

#define u16x8_splat(i) ((u16x8) __builtin_altivec_vspltish (i))
#define i16x8_splat(i) ((i16x8) __builtin_altivec_vspltish (i))
#define u32x4_splat(i) ((u32x4) __builtin_altivec_vspltisw (i))
#define i32x4_splat(i) ((i32x4) __builtin_altivec_vspltisw (i))

#define u16x8_splat_word(x,i) ((u16x8) __builtin_altivec_vsplth ((i16x8) (x), (i)))
#define i16x8_splat_word(x,i) ((i16x8) __builtin_altivec_vsplth ((i16x8) (x), (i)))
#define u32x4_splat_word(x,i) ((u32x4) __builtin_altivec_vspltw ((i32x4) (x), (i)))
#define i32x4_splat_word(x,i) ((i32x4) __builtin_altivec_vspltw ((i32x4) (x), (i)))

#undef _

/* 128 bit shifts. */
#define _(t,ti,lr,f)						\
  always_inline t t##_##lr (t x, t y)				\
  { return (t) __builtin_altivec_##f ((ti) x, (ti) y); }	\
								\
  always_inline t t##_i##lr (t x, int i)			\
  {								\
    t j = {i,i,i,i}; \
    return t##_##lr (x, j);					\
  }

_(u16x8, i16x8, shift_left, vslh);
_(u32x4, i32x4, shift_left, vslw);
_(u16x8, i16x8, shift_right, vsrh);
_(u32x4, i32x4, shift_right, vsrw);
_(i16x8, i16x8, shift_right, vsrah);
_(i32x4, i32x4, shift_right, vsraw);
_(u16x8, i16x8, rotate_left, vrlh);
_(i16x8, i16x8, rotate_left, vrlh);
_(u32x4, i32x4, rotate_left, vrlw);
_(i32x4, i32x4, rotate_left, vrlw);

#undef _

#define _(t,it,lr,f)						\
  always_inline t t##_word_shift_##lr (t x, int n_words)	\
  {								\
    i32x4 n_bits = {0,0,0,n_words * BITS (it)};			\
    return (t) __builtin_altivec_##f ((i32x4) x, n_bits);	\
  }

_(u32x4, u32, left, vslo)
_(i32x4, i32, left, vslo)
_(u32x4, u32, right, vsro)
_(i32x4, i32, right, vsro)
_(u16x8, u16, left, vslo)
_(i16x8, i16, left, vslo)
_(u16x8, u16, right, vsro) _(i16x8, i16, right, vsro)
#undef _
     always_inline
       u32
     u32x4_get0 (u32x4 x)
{
  u32x4_union_t y;
  y.as_u32x4 = x;
  return y.as_u32[3];
}

/* Interleave. */
#define _(t,it,lh,f)						\
  always_inline t t##_interleave_##lh (t x, t y)		\
  { return (t) __builtin_altivec_##f ((it) x, (it) y); }

_(u32x4, i32x4, lo, vmrglw)
_(i32x4, i32x4, lo, vmrglw)
_(u16x8, i16x8, lo, vmrglh)
_(i16x8, i16x8, lo, vmrglh)
_(u32x4, i32x4, hi, vmrghw)
_(i32x4, i32x4, hi, vmrghw)
_(u16x8, i16x8, hi, vmrghh) _(i16x8, i16x8, hi, vmrghh)
#undef _
/* Unaligned loads/stores. */
#ifndef __cplusplus
#define _(t)						\
  always_inline void t##_store_unaligned (t x, t * a)	\
  { clib_mem_unaligned (a, t) = x; }			\
  always_inline t t##_load_unaligned (t * a)		\
  { return clib_mem_unaligned (a, t); }
  _(u8x16) _(u16x8) _(u32x4) _(u64x2) _(i8x16) _(i16x8) _(i32x4) _(i64x2)
#undef _
#endif
#define _signed_binop(n,m,f,g)						\
  /* Unsigned */							\
  always_inline u##n##x##m						\
  u##n##x##m##_##f (u##n##x##m x, u##n##x##m y)				\
  { return (u##n##x##m) __builtin_altivec_##g ((i##n##x##m) x, (i##n##x##m) y); } \
									\
  /* Signed */								\
  always_inline i##n##x##m						\
  i##n##x##m##_##f (i##n##x##m x, i##n##x##m y)				\
  { return (i##n##x##m) __builtin_altivec_##g ((i##n##x##m) x, (i##n##x##m) y); }
/* Compare operations. */
  _signed_binop (16, 8, is_equal, vcmpequh)
_signed_binop (32, 4, is_equal, vcmpequw)
#undef _signed_binop
     always_inline u16x8 u16x8_is_zero (u16x8 x)
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

always_inline u32
u32x4_zero_byte_mask (u32x4 x)
{
  u32x4 cmp = u32x4_is_zero (x);
  u32x4 tmp = { 0x000f, 0x00f0, 0x0f00, 0xf000, };
  cmp &= tmp;
  cmp |= u32x4_word_shift_right (cmp, 2);
  cmp |= u32x4_word_shift_right (cmp, 1);
  return u32x4_get0 (cmp);
}

#endif /* included_vector_altivec_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
