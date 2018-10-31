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
/* Dummy. Aid making uniform macros */
#define vreinterpretq_u8_u8(a)  a

/* Converts all ones/zeros compare mask to bitmap. */
always_inline u32
u8x16_compare_byte_mask (u8x16 v)
{
  uint8x16_t mask = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80
  };
  /* v --> [0xFF, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0x00, ... ] */
  uint8x16_t x = vandq_u8 (v, mask);
  /* after v & mask,
   * x --> [0x01, 0x00, 0x04, 0x08, 0x10, 0x00, 0x40, 0x00, ... ] */
  uint64x2_t x64 = vpaddlq_u32 (vpaddlq_u16 (vpaddlq_u8 (x)));
  /* after merge, x64 --> [0x5D, 0x.. ] */
  return (u32) (vgetq_lane_u64 (x64, 0) + (vgetq_lane_u64 (x64, 1) << 8));
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
\
static_always_inline u32						\
t##s##x##c##_zero_byte_mask (t##s##x##c x)			\
{ uint8x16_t v = vreinterpretq_u8_u##s (vceqq_##i (vdupq_n_##i(0), x));  \
  return u8x16_compare_byte_mask (v); } \

foreach_neon_vec128i foreach_neon_vec128u

#undef _
/* *INDENT-ON* */

static_always_inline u16x8
u16x8_byte_swap (u16x8 v)
{
  return (u16x8) vrev16q_u8 ((u8x16) v);
}

static_always_inline u8x16
u8x16_shuffle (u8x16 v, u8x16 m)
{
  return (u8x16) vqtbl1q_u8 (v, m);
}

static_always_inline u32x4
u32x4_hadd (u32x4 v1, u32x4 v2)
{
  return (u32x4) vpaddq_u32 (v1, v2);
}

static_always_inline u64x2
u32x4_extend_to_u64x2 (u32x4 v)
{
  return vmovl_u32 (vget_low_u32 (v));
}

static_always_inline u64x2
u32x4_extend_to_u64x2_high (u32x4 v)
{
  return vmovl_high_u32 (v);
}

/* Creates a mask made up of the MSB of each byte of the source vector */
static_always_inline u16
u8x16_msb_mask (u8x16 v)
{
  int8x16_t shift =
    { -7, -6, -5, -4, -3, -2, -1, 0, -7, -6, -5, -4, -3, -2, -1, 0 };
  /* v --> [0x80, 0x7F, 0xF0, 0xAF, 0xF0, 0x00, 0xF2, 0x00, ... ] */
  uint8x16_t x = vshlq_u8 (vandq_u8 (v, vdupq_n_u8 (0x80)), shift);
  /* after (v & 0x80) >> shift,
   * x --> [0x01, 0x00, 0x04, 0x08, 0x10, 0x00, 0x40, 0x00, ... ] */
  uint64x2_t x64 = vpaddlq_u32 (vpaddlq_u16 (vpaddlq_u8 (x)));
  /* after merge, x64 --> [0x5D, 0x.. ] */
  return (u16) (vgetq_lane_u64 (x64, 0) + (vgetq_lane_u64 (x64, 1) << 8));
}

#define CLIB_HAVE_VEC128_MSB_MASK

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
