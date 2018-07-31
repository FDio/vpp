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

#ifndef included_vector_neon_h
#define included_vector_neon_h
#include <arm_neon.h>

/* Arithmetic */
#define u16x8_sub_saturate(a,b) vsubq_u16(a,b)
#define i16x8_sub_saturate(a,b) vsubq_s16(a,b)

/* Converts all ones/zeros compare mask to bitmap. */
always_inline u32
u8x16_compare_byte_mask (u8x16 x)
{
  uint8x16_t mask_shift =
    { -7, -6, -5, -4, -3, -2, -1, 0, -7, -6, -5, -4, -3, -2, -1, 0 };
  uint8x16_t mask_and = vdupq_n_u8 (0x80);
  x = vandq_u8 (x, mask_and);
  x = vshlq_u8 (x, vreinterpretq_s8_u8 (mask_shift));
  x = vpaddq_u8 (x, x);
  x = vpaddq_u8 (x, x);
  x = vpaddq_u8 (x, x);
  return vgetq_lane_u8 (x, 0) | (vgetq_lane_u8 (x, 1) << 8);
}

always_inline u32
u16x8_zero_byte_mask (u16x8 input)
{
  u8x16 vall_one = vdupq_n_u8 (0x0);
  u8x16 res_values = { 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80
  };

  /* input --> [0x80, 0x40, 0x01, 0xf0, ... ] */
  u8x16 test_result =
    vreinterpretq_u8_u16 (vceqq_u16 (input, vreinterpretq_u16_u8 (vall_one)));
  u8x16 before_merge = vminq_u8 (test_result, res_values);
  /*before_merge--> [0x80, 0x00, 0x00, 0x10, ... ] */
  /* u8x16 --> [a,b,c,d, e,f,g,h, i,j,k,l, m,n,o,p] */
  /* pair add until we have 2 uint64_t  */
  u16x8 merge1 = vpaddlq_u8 (before_merge);
  /* u16x8-->  [a+b,c+d, e+f,g+h, i+j,k+l, m+n,o+p] */
  u32x4 merge2 = vpaddlq_u16 (merge1);
  /* u32x4-->  [a+b+c+d, e+f+g+h, i+j+k+l, m+n+o+p] */
  u64x2 merge3 = vpaddlq_u32 (merge2);
  /* u64x2-->  [a+b+c+d+e+f+g+h,  i+j+k+l+m+n+o+p]  */
  return (u32) (vgetq_lane_u64 (merge3, 1) << 8) + vgetq_lane_u64 (merge3, 0);
}

always_inline u32
u8x16_zero_byte_mask (u8x16 input)
{
  return u16x8_zero_byte_mask ((u16x8) input);
}

always_inline u32
u32x4_zero_byte_mask (u32x4 input)
{
  return u16x8_zero_byte_mask ((u16x8) input);
}

always_inline u32
u64x2_zero_byte_mask (u64x2 input)
{
  return u16x8_zero_byte_mask ((u16x8) input);
}

/* *INDENT-OFF* */
#define foreach_neon_vec128i \
  _(i,8,16,s8) _(i,16,8,s16) _(i,32,4,s32)  _(i,64,2,s64)
#define foreach_neon_vec128u \
  _(u,8,16,u8) _(u,16,8,u16) _(u,32,4,u32)  _(u,64,2,u64)
#define foreach_neon_vec128f \
  _(f,32,4,f32) _(f,64,2,f64)

#define _(t, s, c, i) \
static_always_inline t##s##x##c						\
t##s##x##c##_splat (t##s x)						\
{ return (t##s##x##c) vdupq_n_##i (x); }				\
\
static_always_inline t##s##x##c						\
t##s##x##c##_load_unaligned (void *p)					\
{ return (t##s##x##c) vld1q_##i (p); }					\
\
static_always_inline void						\
t##s##x##c##_store_unaligned (t##s##x##c v, void *p)			\
{ vst1q_##i (p, v); }							\
\
static_always_inline int						\
t##s##x##c##_is_all_zero (t##s##x##c x)					\
{ return !(vaddvq_##i (x)); }						\
\
static_always_inline int						\
t##s##x##c##_is_equal (t##s##x##c a, t##s##x##c b)			\
{ return t##s##x##c##_is_all_zero (a ^ b); }				\
\
static_always_inline int						\
t##s##x##c##_is_all_equal (t##s##x##c v, t##s x)			\
{ return t##s##x##c##_is_equal (v, t##s##x##c##_splat (x)); };		\

foreach_neon_vec128i foreach_neon_vec128u

#undef _
/* *INDENT-ON* */

static_always_inline u16x8
u16x8_byte_swap (u16x8 v)
{
  const u8 swap_pattern[] = {
    1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14,
  };
  u8x16 swap = vld1q_u8 (swap_pattern);
  return (u16x8) vqtbl1q_u8 ((u8x16) v, swap);
}

static_always_inline u8x16
u8x16_shuffle (u8x16 v, u8x16 m)
{
  return (u8x16) vqtbl1q_u8 (v, m);
}

#define CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE
#define CLIB_VEC128_SPLAT_DEFINED
#endif /* included_vector_neon_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
