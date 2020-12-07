/*
 * Copyright (c) 2020 Arm Limited. and/or its affiliates.
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

#ifndef included_vector_sve256_h
#define included_vector_sve256_h
#include <arm_sve.h>
#include <stdbool.h>

#if __ARM_FEATURE_SVE_BITS != 256
#error incorrect __ARM_FEATURE_SVE_BITS
#endif

// GNU __attribute__((vector_size)) extension is used to define
// fix-size vector type, e.g.,
// u8x32, u16x16, u32x8, u64x4,
// i8x32, i16x16, i32x8, i64x4

// only when __ARM_FEATURE_SVE_VECTOR_OPERATORS not defined
#if 0
typedef svuint8_t u8x32
  __attribute__ ((arm_sve_vector_bits (__ARM_FEATURE_SVE_BITS)));
typedef svuint16_t u16x16
  __attribute__ ((arm_sve_vector_bits (__ARM_FEATURE_SVE_BITS)));
typedef svuint32_t u32x8
  __attribute__ ((arm_sve_vector_bits (__ARM_FEATURE_SVE_BITS)));
typedef svuint64_t u64x4
  __attribute__ ((arm_sve_vector_bits (__ARM_FEATURE_SVE_BITS)));
typedef svint8_t i8x32
  __attribute__ ((arm_sve_vector_bits (__ARM_FEATURE_SVE_BITS)));
typedef svint16_t i16x16
  __attribute__ ((arm_sve_vector_bits (__ARM_FEATURE_SVE_BITS)));
typedef svint32_t i32x8
  __attribute__ ((arm_sve_vector_bits (__ARM_FEATURE_SVE_BITS)));
typedef svint64_t i64x4
  __attribute__ ((arm_sve_vector_bits (__ARM_FEATURE_SVE_BITS)));
#endif

static svbool_t alltrue
  __attribute__ ((arm_sve_vector_bits (__ARM_FEATURE_SVE_BITS)));
static_always_inline void __activate_all_elements (void)
  __attribute__ ((__constructor__));
static_always_inline void
__activate_all_elements (void)
{
  alltrue = svptrue_b8 ();
}

/* *INDENT-OFF* */
#define foreach_sve_vec256i \
  _(i,8,32,s8) _(i,16,16,s16) _(i,32,8,s32)  _(i,64,4,s64)
#define foreach_sve_vec256u \
  _(u,8,32,u8) _(u,16,16,u16) _(u,32,8,u32)  _(u,64,4,u64)

#define _(t, s, c, i) \
static_always_inline t##s##x##c \
t##s##x##c##_splat (t##s x)	\
{ return (t##s##x##c) svdup_n_##i (x); } \
\
static_always_inline t##s##x##c \
t##s##x##c##_load_unaligned (void *p) \
{ return (t##s##x##c) svld1_##i (alltrue, p); } \

foreach_sve_vec256i foreach_sve_vec256u

#undef _
/* *INDENT-ON* */

static_always_inline u32
u8x32_msb_mask (u8x32 x)
{
  u8 b0, b1, b2, b3;
  u8x32 v;
  u8x32 m = svdup_n_u8 (0x80);
  u8x32 m0 = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  u8x32 m1 = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  u8x32 m2 = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  u8x32 m3 = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
  };
  u8x32 s = {
    7, 6, 5, 4, 3, 2, 1, 0,
    7, 6, 5, 4, 3, 2, 1, 0,
    7, 6, 5, 4, 3, 2, 1, 0,
    7, 6, 5, 4, 3, 2, 1, 0
  };
  v = svand_u8_z (alltrue, x, m);
  v = svlsr_u8_z (alltrue, v, s);
  b0 = svorv_u8 (alltrue, svand_u8_z (alltrue, v, m0));
  b1 = svorv_u8 (alltrue, svand_u8_z (alltrue, v, m1));
  b2 = svorv_u8 (alltrue, svand_u8_z (alltrue, v, m2));
  b3 = svorv_u8 (alltrue, svand_u8_z (alltrue, v, m3));
  return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

#endif /* included_vector_sve256_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
