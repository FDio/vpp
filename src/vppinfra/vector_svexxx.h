/*
 * Copyright (c) 2021 Arm Limited. and/or its affiliates.
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

/* do not include vector_sve_fixed.h directly */
#ifndef included_vector_svexxx_h
#define included_vector_svexxx_h

#include <arm_sve.h>
#include <arm_neon.h>
#include <stdbool.h>

#define svrevb_u8_z(pg, op) (op)
#define svrevb_s8_z(pg, op) (op)

static svbool_t alltrue
  __attribute__ ((arm_sve_vector_bits (__ARM_FEATURE_SVE_BITS)));

static_always_inline void __activate_all_elements (void)
  __attribute__ ((__constructor__));
static_always_inline void
__activate_all_elements (void)
{
  alltrue = svptrue_b8 ();
}

#define foreach_sve_vec128i                                                   \
  _ (i, 8, 16, s8) _ (i, 16, 8, s16) _ (i, 32, 4, s32) _ (i, 64, 2, s64)
#define foreach_sve_vec128u                                                   \
  _ (u, 8, 16, u8) _ (u, 16, 8, u16) _ (u, 32, 4, u32) _ (u, 64, 2, u64)

#define foreach_sve_vec256i                                                   \
  _ (i, 8, 32, s8) _ (i, 16, 16, s16) _ (i, 32, 8, s32) _ (i, 64, 4, s64)
#define foreach_sve_vec256u                                                   \
  _ (u, 8, 32, u8) _ (u, 16, 16, u16) _ (u, 32, 8, u32) _ (u, 64, 4, u64)

#define foreach_sve_vec512i                                                   \
  _ (i, 8, 64, s8) _ (i, 16, 32, s16) _ (i, 32, 16, s32) _ (i, 64, 8, s64)
#define foreach_sve_vec512u                                                   \
  _ (u, 8, 64, u8) _ (u, 16, 32, u16) _ (u, 32, 16, u32) _ (u, 64, 8, u64)

#define _(t, s, c, i)                                                         \
  static_always_inline t##s##x##c t##s##x##c##_splat (t##s x)                 \
  {                                                                           \
    return (t##s##x##c) svdup_n_##i (x);                                      \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_load_unaligned (void *p)       \
  {                                                                           \
    return (t##s##x##c) svld1_##i (alltrue, p);                               \
  }                                                                           \
                                                                              \
  static_always_inline void t##s##x##c##_store_unaligned (t##s##x##c v,       \
							  void *p)            \
  {                                                                           \
    svst1_##i (alltrue, p, v);                                                \
  }                                                                           \
                                                                              \
  static_always_inline int t##s##x##c##_is_all_zero (t##s##x##c x)            \
  {                                                                           \
    int max = svmaxv_##i (alltrue, x);                                        \
    int min = svminv_##i (alltrue, x);                                        \
    return ((0 == max) && (0 == min));                                        \
  }                                                                           \
                                                                              \
  static_always_inline int t##s##x##c##_is_equal (t##s##x##c a, t##s##x##c b) \
  {                                                                           \
    svbool_t ne = svcmpne_##i (alltrue, a, b);                                \
    return (false == svptest_any (svptrue_b##s (), ne));                      \
  }                                                                           \
                                                                              \
  static_always_inline int t##s##x##c##_is_all_equal (t##s##x##c v, t##s x)   \
  {                                                                           \
    svbool_t ne = svcmpne_n_##i (alltrue, v, x);                              \
    return (false == svptest_any (svptrue_b##s (), ne));                      \
  }                                                                           \
                                                                              \
  static_always_inline u64 t##s##x##c##_zero_byte_mask (t##s##x##c x)         \
  {                                                                           \
    t##s##x##c allone = (t##s##x##c) svdup_n_##i ((t##s) ~0);                 \
    svbool_t eq = svcmpeq_n_##i (alltrue, x, (t##s) 0);                       \
    t##s##x##c a = svand_n_##i##_z (eq, allone, (t##s) ~0);                   \
    svuint8_t v = svreinterpret_u8_##i (a);                                   \
    svbool_t m = svcmpeq_u8 (alltrue, v, svdup_n_u8 (0xFF));                  \
    u64 mask = (0x01L << svcntb ()) - 1;                                      \
    void *r = &m;                                                             \
    return *((u64 *) r) & mask;                                               \
  }                                                                           \
                                                                              \
  static_always_inline u64 t##s##x##c##_msb_mask (t##s##x##c x)               \
  {                                                                           \
    svuint8_t v = svreinterpret_u8_##i (x);                                   \
    v = svand_u8_z (alltrue, v, svdup_n_u8 (0x80));                           \
    svbool_t eq = svcmpeq_u8 (alltrue, v, svdup_n_u8 (0x80));                 \
    u64 mask = (0x01L << svcntb ()) - 1;                                      \
    void *r = &eq;                                                            \
    return *((u64 *) r) & mask;                                               \
  }                                                                           \
                                                                              \
  static_always_inline u##s##x##c t##s##x##c##_is_greater (t##s##x##c a,      \
							   t##s##x##c b)      \
  {                                                                           \
    svbool_t gt = svcmpgt_##i (alltrue, a, b);                                \
    return (u##s##x##c) svdup_n_##i##_z (gt, (t##s) ~0);                      \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_blend (                        \
    t##s##x##c dst, t##s##x##c src, t##s##x##c mask)                          \
  {                                                                           \
    svbool_t ne = svcmpne_n_##i (alltrue, mask, (t##s) 0);                    \
    return (t##s##x##c) svsel_##i (ne, src, dst);                             \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_byte_swap (t##s##x##c v)       \
  {                                                                           \
    return (t##s##x##c) svrevb_##i##_z (alltrue, v);                          \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_shuffle (t##s##x##c v,         \
							u##s##x##c m)         \
  {                                                                           \
    return (t##s##x##c) svtbl_##i (v, m);                                     \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_permute (t##s##x##c v,         \
							u##s##x##c idx)       \
  {                                                                           \
    return (t##s##x##c) svtbl_##i (v, idx);                                   \
  }

#if (__ARM_FEATURE_SVE_BITS == 128)
foreach_sve_vec128i foreach_sve_vec128u
#elif (__ARM_FEATURE_SVE_BITS == 256)
foreach_sve_vec256i foreach_sve_vec256u
#elif (__ARM_FEATURE_SVE_BITS == 512)
foreach_sve_vec512i foreach_sve_vec512u
#endif

#undef foreach_sve_vec128i
#undef foreach_sve_vec128u
#undef foreach_sve_vec256i
#undef foreach_sve_vec256u
#undef foreach_sve_vec512i
#undef foreach_sve_vec512u
#undef _

#define foreach_sve_vec128i                                                   \
  _ (i, 8, 16, s8, 16, 8, s16)                                                \
  _ (i, 16, 8, s16, 32, 4, s32) _ (i, 32, 4, s32, 64, 2, s64)
#define foreach_sve_vec128u                                                   \
  _ (u, 8, 16, u8, 16, 8, u16)                                                \
  _ (u, 16, 8, u16, 32, 4, u32) _ (u, 32, 4, u32, 64, 2, u64)

#define foreach_sve_vec256i                                                   \
  _ (i, 8, 32, s8, 16, 16, s16)                                               \
  _ (i, 16, 16, s16, 32, 8, s32) _ (i, 32, 8, s32, 64, 4, s64)
#define foreach_sve_vec256u                                                   \
  _ (u, 8, 32, u8, 16, 16, u16)                                               \
  _ (u, 16, 16, u16, 32, 8, u32) _ (u, 32, 8, u32, 64, 4, u64)

#define foreach_sve_vec512i                                                   \
  _ (i, 8, 64, s8, 16, 32, s16)                                               \
  _ (i, 16, 32, s16, 32, 16, s32) _ (i, 32, 16, s32, 64, 8, s64)
#define foreach_sve_vec512u                                                   \
  _ (u, 8, 64, u8, 16, 32, u16)                                               \
  _ (u, 16, 32, u16, 32, 16, u32) _ (u, 32, 16, u32, 64, 8, u64)

#define _(t, s, c, i, s2, c2, i2)                                             \
  static_always_inline t##s2##x##c2 t##s2##x##c2##_from_##t##s##x##c (        \
    t##s##x##c x)                                                             \
  {                                                                           \
    return (t##s2##x##c2) svunpklo_##i2 (x);                                  \
  }                                                                           \
                                                                              \
  static_always_inline t##s2##x##c2 t##s2##x##c2##_from_##t##s##x##c##_high ( \
    t##s##x##c x)                                                             \
  {                                                                           \
    return (t##s2##x##c2) svunpkhi_##i2 (x);                                  \
  }

#if (__ARM_FEATURE_SVE_BITS == 128)
  foreach_sve_vec128i foreach_sve_vec128u
#elif (__ARM_FEATURE_SVE_BITS == 256)
  foreach_sve_vec256i foreach_sve_vec256u
#elif (__ARM_FEATURE_SVE_BITS == 512)
  foreach_sve_vec512i foreach_sve_vec512u
#endif

#undef foreach_sve_vec128i
#undef foreach_sve_vec128u
#undef foreach_sve_vec256i
#undef foreach_sve_vec256u
#undef foreach_sve_vec512i
#undef foreach_sve_vec512u
#undef _

#define foreach_sve_vec256i                                                   \
  _ (i, 8, 16, s8, 8, 32, s8)                                                 \
  _ (i, 16, 8, s16, 16, 16, s16)                                              \
  _ (i, 32, 4, s32, 32, 8, s32) _ (i, 64, 2, s64, 64, 4, s64)
#define foreach_sve_vec256u                                                   \
  _ (u, 8, 16, u8, 8, 32, u8)                                                 \
  _ (u, 16, 8, u16, 16, 16, u16)                                              \
  _ (u, 32, 4, u32, 32, 8, u32) _ (u, 64, 2, u64, 64, 4, u64)

#define _(t, s, c, i, s2, c2, i2)                                             \
  static_always_inline t##s##x##c t##s2##x##c2##_extract_lo (t##s2##x##c2 x)  \
  {                                                                           \
    t##s2 p[c2];                                                              \
    svst1_##i2 (alltrue, (void *) p, x);                                      \
    return (t##s##x##c) vld1q_##i ((void *) (p + 0));                         \
  }                                                                           \
                                                                              \
  static_always_inline t##s##x##c t##s2##x##c2##_extract_hi (t##s2##x##c2 x)  \
  {                                                                           \
    t##s2 p[c2];                                                              \
    svst1_##i2 (alltrue, (void *) p, x);                                      \
    return (t##s##x##c) vld1q_##i ((void *) (p + c));                         \
  }                                                                           \
                                                                              \
  static_always_inline t##s2##x##c2 t##s2##x##c2##_insert_lo (                \
    t##s2##x##c2 v1, t##s##x##c v2)                                           \
  {                                                                           \
    t##s2 p[c2];                                                              \
    svst1_##i2 (alltrue, (void *) p, v1);                                     \
    vst1q_##i ((void *) (p + 0), v2);                                         \
    return (t##s2##x##c2) svld1_##i2 (alltrue, (void *) p);                   \
  }                                                                           \
                                                                              \
  static_always_inline t##s2##x##c2 t##s2##x##c2##_insert_hi (                \
    t##s2##x##c2 v1, t##s##x##c v2)                                           \
  {                                                                           \
    t##s2 p[c2];                                                              \
    svst1_##i2 (alltrue, (void *) p, v1);                                     \
    vst1q_##i ((void *) (p + c), v2);                                         \
    return (t##s2##x##c2) svld1_##i2 (alltrue, (void *) p);                   \
  }

#if (__ARM_FEATURE_SVE_BITS == 256)
    foreach_sve_vec256i foreach_sve_vec256u
#endif

#undef foreach_sve_vec256i
#undef foreach_sve_vec256u
#undef foreach_sve_vec512i
#undef foreach_sve_vec512u
#undef _

#endif /* included_vector_svexxx_h */

  /*
   * fd.io coding-style-patch-verification: ON
   *
   * Local Variables:
   * eval: (c-set-style "gnu")
   * End:
   */
