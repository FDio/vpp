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

/* Splats. */

#define u8x16_splat(i) vdupq_n_u8(i)
#define u16x8_splat(i) vdupq_n_u16(i)
#define i16x8_splat(i) vdupq_n_s16(i)
#define u32x4_splat(i) vdupq_n_u32(i)
#define i32x4_splat(i) vdupq_n_s32(i)

/* Arithmetic */
#define u16x8_add(a,b) vaddq_u16(a,b)
#define i16x8_add(a,b) vaddq_s16(a,b)
#define u16x8_sub_saturate(a,b) vsubq_u16(a,b)
#define i16x8_sub_saturate(a,b) vsubq_s16(a,b)


/* Compare operations. */
#define u8x16_is_equal(a,b) vceqq_u8(a,b)
#define i8x16_is_equal(a,b) vceqq_s8(a,b)
#define u16x8_is_equal(a,b) vceqq_u16(a,b)
#define i16x8_is_equal(a,b) vceqq_i16(a,b)
#define u32x4_is_equal(a,b) vceqq_u32(a,b)
#define i32x4_is_equal(a,b) vceqq_s32(a,b)
#define i8x16_is_greater(a,b) vcgtq_s8(a,b)
#define i16x8_is_greater(a,b) vcgtq_u8(a,b)
#define i32x4_is_greater(a,b) vcgtq_s32(a,b)

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

/* Converts all ones/zeros compare mask to bitmap. */
always_inline u32
u8x16_compare_byte_mask (u8x16 x)
{
  static int8_t const __attribute__ ((aligned (16))) xr[8] =
  {
  -7, -6, -5, -4, -3, -2, -1, 0};
  uint8x8_t mask_and = vdup_n_u8 (0x80);
  int8x8_t mask_shift = vld1_s8 (xr);

  uint8x8_t lo = vget_low_u8 (x);
  uint8x8_t hi = vget_high_u8 (x);

  lo = vand_u8 (lo, mask_and);
  lo = vshl_u8 (lo, mask_shift);

  hi = vand_u8 (hi, mask_and);
  hi = vshl_u8 (hi, mask_shift);

  lo = vpadd_u8 (lo, lo);
  lo = vpadd_u8 (lo, lo);
  lo = vpadd_u8 (lo, lo);

  hi = vpadd_u8 (hi, hi);
  hi = vpadd_u8 (hi, hi);
  hi = vpadd_u8 (hi, hi);

  return ((hi[0] << 8) | (lo[0] & 0xff));
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

#define u32x4_zero_byte_mask(x) u16x8_zero_byte_mask((u16x8) x)

#endif /* included_vector_neon_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
