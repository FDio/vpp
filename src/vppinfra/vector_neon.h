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

/* Dummy. Aid making uniform macros */
#define vreinterpretq_u8_u8(a)  a
/* Implement the missing intrinsics to make uniform macros */
#define vminvq_u64(x)   \
({  \
  u64 x0 = vgetq_lane_u64(x, 0);    \
  u64 x1 = vgetq_lane_u64(x, 1);    \
  x0 < x1 ? x0 : x1;    \
})

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

#define _(t, s, c, i)                                                         \
  static_always_inline t##s##x##c t##s##x##c##_load_unaligned (void *p)       \
  {                                                                           \
    return (t##s##x##c) vld1q_##i (p);                                        \
  }                                                                           \
                                                                              \
  static_always_inline void t##s##x##c##_store_unaligned (t##s##x##c v,       \
							  void *p)            \
  {                                                                           \
    vst1q_##i (p, v);                                                         \
  }                                                                           \
                                                                              \
  static_always_inline int t##s##x##c##_is_all_zero (t##s##x##c x)            \
  {                                                                           \
    return !!(vminvq_u##s (vceqq_##i (vdupq_n_##i (0), x)));                  \
  }                                                                           \
                                                                              \
  static_always_inline int t##s##x##c##_is_equal (t##s##x##c a, t##s##x##c b) \
  {                                                                           \
    return !!(vminvq_u##s (vceqq_##i (a, b)));                                \
  }                                                                           \
  static_always_inline int t##s##x##c##_is_all_equal (t##s##x##c v, t##s x)   \
  {                                                                           \
    return t##s##x##c##_is_equal (v, t##s##x##c##_splat (x));                 \
  };                                                                          \
                                                                              \
  static_always_inline u32 t##s##x##c##_zero_byte_mask (t##s##x##c x)         \
  {                                                                           \
    uint8x16_t v = vreinterpretq_u8_u##s (vceqq_##i (vdupq_n_##i (0), x));    \
    return u8x16_compare_byte_mask (v);                                       \
  }                                                                           \
                                                                              \
  static_always_inline u##s##x##c t##s##x##c##_is_greater (t##s##x##c a,      \
							   t##s##x##c b)      \
  {                                                                           \
    return (u##s##x##c) vcgtq_##i (a, b);                                     \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_add_saturate (t##s##x##c a,    \
							     t##s##x##c b)    \
  {                                                                           \
    return (t##s##x##c) vqaddq_##i (a, b);                                    \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_sub_saturate (t##s##x##c a,    \
							     t##s##x##c b)    \
  {                                                                           \
    return (t##s##x##c) vqsubq_##i (a, b);                                    \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_blend (                        \
    t##s##x##c dst, t##s##x##c src, u##s##x##c mask)                          \
  {                                                                           \
    return (t##s##x##c) vbslq_##i (mask, src, dst);                           \
  }

foreach_neon_vec128i foreach_neon_vec128u

#undef _
/* *INDENT-ON* */

static_always_inline u16x8
u16x8_byte_swap (u16x8 v)
{
  return (u16x8) vrev16q_u8 ((u8x16) v);
}

static_always_inline u32x4
u32x4_byte_swap (u32x4 v)
{
  return (u32x4) vrev32q_u8 ((u8x16) v);
}

static_always_inline u32x4
u32x4_hadd (u32x4 v1, u32x4 v2)
{
  return (u32x4) vpaddq_u32 (v1, v2);
}

static_always_inline u64x2
u64x2_from_u32x4 (u32x4 v)
{
  return vmovl_u32 (vget_low_u32 (v));
}

static_always_inline u64x2
u64x2_from_u32x4_high (u32x4 v)
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

static_always_inline u64x2
u64x2_gather (void *p0, void *p1)
{
  u64x2 r = vdupq_n_u64 (*(u64 *) p0);
  r = vsetq_lane_u64 (*(u64 *) p1, r, 1);
  return r;
}

static_always_inline u32x4
u32x4_gather (void *p0, void *p1, void *p2, void *p3)
{
  u32x4 r = vdupq_n_u32 (*(u32 *) p0);
  r = vsetq_lane_u32 (*(u32 *) p1, r, 1);
  r = vsetq_lane_u32 (*(u32 *) p2, r, 2);
  r = vsetq_lane_u32 (*(u32 *) p3, r, 3);
  return r;
}

static_always_inline void
u64x2_scatter (u64x2 r, void *p0, void *p1)
{
  *(u64 *) p0 = vgetq_lane_u64 (r, 0);
  *(u64 *) p1 = vgetq_lane_u64 (r, 1);
}

static_always_inline void
u32x4_scatter (u32x4 r, void *p0, void *p1, void *p2, void *p3)
{
  *(u32 *) p0 = vgetq_lane_u32 (r, 0);
  *(u32 *) p1 = vgetq_lane_u32 (r, 1);
  *(u32 *) p2 = vgetq_lane_u32 (r, 2);
  *(u32 *) p3 = vgetq_lane_u32 (r, 3);
}

static_always_inline u32
u32x4_min_scalar (u32x4 v)
{
  return vminvq_u32 (v);
}

#define u8x16_word_shift_left(x,n)  vextq_u8(u8x16_splat (0), x, 16 - n)
#define u8x16_word_shift_right(x,n) vextq_u8(x, u8x16_splat (0), n)

always_inline u32x4
u32x4_interleave_hi (u32x4 a, u32x4 b)
{
  return (u32x4) vzip2q_u32 (a, b);
}

always_inline u32x4
u32x4_interleave_lo (u32x4 a, u32x4 b)
{
  return (u32x4) vzip1q_u32 (a, b);
}

static_always_inline u8x16
u8x16_reflect (u8x16 v)
{
  u8x16 mask = {
    15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
  };
  return (u8x16) vqtbl1q_u8 (v, mask);
}

static_always_inline u8x16
u8x16_xor3 (u8x16 a, u8x16 b, u8x16 c)
{
#if __GNUC__ == 8 && __ARM_FEATURE_SHA3 == 1
  u8x16 r;
__asm__ ("eor3 %0.16b,%1.16b,%2.16b,%3.16b": "=w" (r): "0" (a), "w" (b), "w" (c):);
  return r;
#endif
  return a ^ b ^ c;
}

#define CLIB_HAVE_VEC128_MSB_MASK

#define CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE
#endif /* included_vector_neon_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
