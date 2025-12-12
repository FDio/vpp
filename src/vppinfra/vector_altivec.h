/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2009 Eliot Dresselhaus
 */

#ifndef included_vector_altivec_h
#define included_vector_altivec_h

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

#endif /* included_vector_altivec_h */
