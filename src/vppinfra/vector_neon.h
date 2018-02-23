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

always_inline int
u8x16_is_all_zero (u8x16 x)
{
  return !(vaddvq_u8 (x));
}

always_inline int
u16x8_is_all_zero (u16x8 x)
{
  return !(vaddvq_u16 (x));
}

always_inline int
u32x4_is_all_zero (u32x4 x)
{
  return !(vaddvq_u32 (x));
}

always_inline int
u64x2_is_all_zero (u64x2 x)
{
  return !(vaddvq_u64 (x));
}

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



#endif /* included_vector_neon_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
