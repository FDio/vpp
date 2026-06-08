/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef included_vector_lasx_h
#define included_vector_lasx_h

#include <lasxintrin.h>

#define foreach_lasx_vec256i _ (i, 8, 32, b) _ (i, 16, 16, h) _ (i, 32, 8, w) _ (i, 64, 4, d)
#define foreach_lasx_vec256u _ (u, 8, 32, b) _ (u, 16, 16, h) _ (u, 32, 8, w) _ (u, 64, 4, d)

#define _(t, s, c, i)                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_splat (t##s x)                                      \
  {                                                                                                \
    return (t##s##x##c) __lasx_xvreplgr2vr_##i ((long int) x);                                     \
  }                                                                                                \
                                                                                                   \
  static_always_inline t##s##x##c t##s##x##c##_load_unaligned (void *p)                            \
  {                                                                                                \
    return (t##s##x##c) __lasx_xvld (p, 0);                                                        \
  }                                                                                                \
                                                                                                   \
  static_always_inline void t##s##x##c##_store_unaligned (t##s##x##c v, void *p)                   \
  {                                                                                                \
    __lasx_xvst ((__m256i) v, p, 0);                                                               \
  }                                                                                                \
                                                                                                   \
  static_always_inline int t##s##x##c##_is_all_zero (t##s##x##c x)                                 \
  {                                                                                                \
    __m256i m = __lasx_xvmsknz_b ((__m256i) x);                                                    \
    return (__lasx_xvpickve2gr_wu (m, 0) | __lasx_xvpickve2gr_wu (m, 4)) == 0;                     \
  }                                                                                                \
                                                                                                   \
  static_always_inline int t##s##x##c##_is_equal (t##s##x##c a, t##s##x##c b)                      \
  {                                                                                                \
    return t##s##x##c##_is_all_zero ((t##s##x##c) __lasx_xvxor_v ((__m256i) a, (__m256i) b));      \
  }                                                                                                \
                                                                                                   \
  static_always_inline int t##s##x##c##_is_all_equal (t##s##x##c v, t##s x)                        \
  {                                                                                                \
    return t##s##x##c##_is_equal (v, t##s##x##c##_splat (x));                                      \
  }                                                                                                \
                                                                                                   \
  static_always_inline t##s##x##c t##s##x##c##_interleave_lo (t##s##x##c a, t##s##x##c b)          \
  {                                                                                                \
    return (t##s##x##c) __lasx_xvilvl_##i ((__m256i) b, (__m256i) a);                              \
  }                                                                                                \
                                                                                                   \
  static_always_inline t##s##x##c t##s##x##c##_interleave_hi (t##s##x##c a, t##s##x##c b)          \
  {                                                                                                \
    return (t##s##x##c) __lasx_xvilvh_##i ((__m256i) b, (__m256i) a);                              \
  }

foreach_lasx_vec256i foreach_lasx_vec256u
#undef _

#define _(t, s, c, i)                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_min (t##s##x##c a, t##s##x##c b)                    \
  {                                                                                                \
    return (t##s##x##c) __lasx_xvmin_##i ((__m256i) a, (__m256i) b);                               \
  }                                                                                                \
                                                                                                   \
  static_always_inline t##s##x##c t##s##x##c##_max (t##s##x##c a, t##s##x##c b)                    \
  {                                                                                                \
    return (t##s##x##c) __lasx_xvmax_##i ((__m256i) a, (__m256i) b);                               \
  }

  foreach_lasx_vec256i
#undef _

#define _(t, s, c, i)                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_min (t##s##x##c a, t##s##x##c b)                    \
  {                                                                                                \
    return (t##s##x##c) __lasx_xvmin_##i##u ((__m256i) a, (__m256i) b);                            \
  }                                                                                                \
                                                                                                   \
  static_always_inline t##s##x##c t##s##x##c##_max (t##s##x##c a, t##s##x##c b)                    \
  {                                                                                                \
    return (t##s##x##c) __lasx_xvmax_##i##u ((__m256i) a, (__m256i) b);                            \
  }

    foreach_lasx_vec256u
#undef _

/* 256 bit packs. */
#define _(f, t, fn)                                                                                \
  static_always_inline t t##_pack (f lo, f hi) { return (t) fn ((__m256i) hi, (__m256i) lo, 0); }

    _ (i16x16, i8x32, __lasx_xvssrani_b_h) _ (i16x16, u8x32, __lasx_xvssrani_bu_h)
      _ (i32x8, i16x16, __lasx_xvssrani_h_w) _ (i32x8, u16x16, __lasx_xvssrani_hu_w)

#undef _

#define CLIB_HAVE_VEC256_UNALIGNED_LOAD_STORE

#define u8x32_word_shift_left(a, n)                                                                \
  ((u8x32) ((n) > 15 ? __lasx_xvreplgr2vr_d (0) : __lasx_xvbsll_v ((__m256i) (a), (n))))
#define u8x32_word_shift_right(a, n)                                                               \
  ((u8x32) ((n) > 15 ? __lasx_xvreplgr2vr_d (0) : __lasx_xvbsrl_v ((__m256i) (a), (n))))

	static_always_inline u32 u8x32_msb_mask (u8x32 v)
{
  __m256i m = __lasx_xvmskltz_b ((__m256i) v);
  return __lasx_xvpickve2gr_wu (m, 0) | (__lasx_xvpickve2gr_wu (m, 4) << 16);
}

static_always_inline u32
i8x32_msb_mask (i8x32 v)
{
  return u8x32_msb_mask ((u8x32) v);
}

static_always_inline u8x32
u8x32_blend (u8x32 dst, u8x32 src, u8x32 mask)
{
  return (u8x32) __lasx_xvbitsel_v ((__m256i) dst, (__m256i) src, (__m256i) mask);
}

static_always_inline u16x16
u16x16_blend (u16x16 dst, u16x16 src, int mask)
{
  const u16x16 m = { (mask & 0x01) ? 0xffff : 0, (mask & 0x02) ? 0xffff : 0,
		     (mask & 0x04) ? 0xffff : 0, (mask & 0x08) ? 0xffff : 0,
		     (mask & 0x10) ? 0xffff : 0, (mask & 0x20) ? 0xffff : 0,
		     (mask & 0x40) ? 0xffff : 0, (mask & 0x80) ? 0xffff : 0,
		     (mask & 0x01) ? 0xffff : 0, (mask & 0x02) ? 0xffff : 0,
		     (mask & 0x04) ? 0xffff : 0, (mask & 0x08) ? 0xffff : 0,
		     (mask & 0x10) ? 0xffff : 0, (mask & 0x20) ? 0xffff : 0,
		     (mask & 0x40) ? 0xffff : 0, (mask & 0x80) ? 0xffff : 0 };
  return (u16x16) __lasx_xvbitsel_v ((__m256i) dst, (__m256i) src, (__m256i) m);
}

static_always_inline u32x8
u32x8_blend (u32x8 dst, u32x8 src, int mask)
{
  const u32x8 m = { (mask & 0x01) ? ~0U : 0, (mask & 0x02) ? ~0U : 0, (mask & 0x04) ? ~0U : 0,
		    (mask & 0x08) ? ~0U : 0, (mask & 0x10) ? ~0U : 0, (mask & 0x20) ? ~0U : 0,
		    (mask & 0x40) ? ~0U : 0, (mask & 0x80) ? ~0U : 0 };
  return (u32x8) __lasx_xvbitsel_v ((__m256i) dst, (__m256i) src, (__m256i) m);
}

static_always_inline u32x8
u32x8_permute (u32x8 v, u32x8 idx)
{
  return (u32x8) __lasx_xvperm_w ((__m256i) v, (__m256i) idx);
}

static_always_inline u8x32
u8x32_xor3 (u8x32 a, u8x32 b, u8x32 c)
{
  return (u8x32) __lasx_xvxor_v (__lasx_xvxor_v ((__m256i) a, (__m256i) b), (__m256i) c);
}

#define u64x4_permute(v, m0, m1, m2, m3)                                                           \
  (u64x4) __lasx_xvpermi_d ((__m256i) (v), ((m0) | (m1) << 2 | (m2) << 4 | (m3) << 6))

/* _extract_lo, _extract_hi, _insert_lo, _insert_hi */
#define _(t1, t2)                                                                                  \
  static_always_inline t1 t2##_extract_lo (t2 v)                                                   \
  {                                                                                                \
    union                                                                                          \
    {                                                                                              \
      t2 v;                                                                                        \
      t1 e[2];                                                                                     \
    } u = { .v = v };                                                                              \
    return u.e[0];                                                                                 \
  }                                                                                                \
                                                                                                   \
  static_always_inline t1 t2##_extract_hi (t2 v)                                                   \
  {                                                                                                \
    union                                                                                          \
    {                                                                                              \
      t2 v;                                                                                        \
      t1 e[2];                                                                                     \
    } u = { .v = v };                                                                              \
    return u.e[1];                                                                                 \
  }                                                                                                \
                                                                                                   \
  static_always_inline t2 t2##_insert_lo (t2 v1, t1 v2)                                            \
  {                                                                                                \
    union                                                                                          \
    {                                                                                              \
      t2 v;                                                                                        \
      t1 e[2];                                                                                     \
    } u = { .v = v1 };                                                                             \
    u.e[0] = v2;                                                                                   \
    return u.v;                                                                                    \
  }                                                                                                \
                                                                                                   \
  static_always_inline t2 t2##_insert_hi (t2 v1, t1 v2)                                            \
  {                                                                                                \
    union                                                                                          \
    {                                                                                              \
      t2 v;                                                                                        \
      t1 e[2];                                                                                     \
    } u = { .v = v1 };                                                                             \
    u.e[1] = v2;                                                                                   \
    return u.v;                                                                                    \
  }

_ (u8x16, u8x32)
_ (u16x8, u16x16)
_ (u32x4, u32x8)
_ (u64x2, u64x4)
#undef _

static_always_inline u8x32
u8x32_splat_u8x16 (u8x16 a)
{
  union
  {
    __m256i v256;
    __m128i v128[2];
  } u;
  u.v128[0] = u.v128[1] = (__m128i) a;
  return (u8x32) u.v256;
}

static_always_inline u32x8
u32x8_splat_u32x4 (u32x4 a)
{
  union
  {
    __m256i v256;
    __m128i v128[2];
  } u;
  u.v128[0] = u.v128[1] = (__m128i) a;
  return (u32x8) u.v256;
}

static_always_inline u64x4
u64x4_splat_u64x2 (u64x2 a)
{
  union
  {
    __m256i v256;
    __m128i v128[2];
  } u;
  u.v128[0] = u.v128[1] = (__m128i) a;
  return (u64x4) u.v256;
}

static_always_inline u8x32
u8x32_load_partial (u8 *data, uword n)
{
  u8x32 r = {};
  if (n > 16)
    {
      r = u8x32_insert_lo (r, *(u8x16u *) data);
      r = u8x32_insert_hi (r, u8x16_load_partial (data + 16, n - 16));
    }
  else
    r = u8x32_insert_lo (r, u8x16_load_partial (data, n));
  return r;
}

static_always_inline void
u8x32_store_partial (u8x32 r, u8 *data, uword n)
{
  if (n > 16)
    {
      *(u8x16u *) data = u8x32_extract_lo (r);
      u8x16_store_partial (u8x32_extract_hi (r), data + 16, n - 16);
    }
  else
    u8x16_store_partial (u8x32_extract_lo (r), data, n);
}

static_always_inline u16x16
u16x16_from_u8x16 (u8x16 v)
{
  union
  {
    __m256i v256;
    __m128i v128[2];
  } u = {};
  u.v128[0] = (__m128i) v;
  return (u16x16) __lasx_xvsllwil_hu_bu (__lasx_xvpermi_d (u.v256, 0xd8), 0);
}

static_always_inline u32x8
u32x8_from_u16x8 (u16x8 v)
{
  union
  {
    __m256i v256;
    __m128i v128[2];
  } u = {};
  u.v128[0] = (__m128i) v;
  return (u32x8) __lasx_xvsllwil_wu_hu (__lasx_xvpermi_d (u.v256, 0xd8), 0);
}

static_always_inline u64x4
u64x4_from_u32x4 (u32x4 v)
{
  union
  {
    __m256i v256;
    __m128i v128[2];
  } u = {};
  u.v128[0] = (__m128i) v;
  return (u64x4) __lasx_xvsllwil_du_wu (__lasx_xvpermi_d (u.v256, 0xd8), 0);
}

static_always_inline u64x4
u64x4_gather (void *p0, void *p1, void *p2, void *p3)
{
  __m256i r = __lasx_xvldrepl_d (p0, 0);
  r = __lasx_xvinsgr2vr_d (r, *(u64 *) p1, 1);
  r = __lasx_xvinsgr2vr_d (r, *(u64 *) p2, 2);
  r = __lasx_xvinsgr2vr_d (r, *(u64 *) p3, 3);
  return (u64x4) r;
}

static_always_inline u32x8
u32x8_gather (void *p0, void *p1, void *p2, void *p3, void *p4, void *p5, void *p6, void *p7)
{
  __m256i r = __lasx_xvldrepl_w (p0, 0);
  r = __lasx_xvinsgr2vr_w (r, *(u32 *) p1, 1);
  r = __lasx_xvinsgr2vr_w (r, *(u32 *) p2, 2);
  r = __lasx_xvinsgr2vr_w (r, *(u32 *) p3, 3);
  r = __lasx_xvinsgr2vr_w (r, *(u32 *) p4, 4);
  r = __lasx_xvinsgr2vr_w (r, *(u32 *) p5, 5);
  r = __lasx_xvinsgr2vr_w (r, *(u32 *) p6, 6);
  r = __lasx_xvinsgr2vr_w (r, *(u32 *) p7, 7);
  return (u32x8) r;
}

static_always_inline void
u64x4_scatter (u64x4 r, void *p0, void *p1, void *p2, void *p3)
{
  *(u64 *) p0 = __lasx_xvpickve2gr_du ((__m256i) r, 0);
  *(u64 *) p1 = __lasx_xvpickve2gr_du ((__m256i) r, 1);
  *(u64 *) p2 = __lasx_xvpickve2gr_du ((__m256i) r, 2);
  *(u64 *) p3 = __lasx_xvpickve2gr_du ((__m256i) r, 3);
}

static_always_inline void
u32x8_scatter (u32x8 r, void *p0, void *p1, void *p2, void *p3, void *p4, void *p5, void *p6,
	       void *p7)
{
  *(u32 *) p0 = __lasx_xvpickve2gr_wu ((__m256i) r, 0);
  *(u32 *) p1 = __lasx_xvpickve2gr_wu ((__m256i) r, 1);
  *(u32 *) p2 = __lasx_xvpickve2gr_wu ((__m256i) r, 2);
  *(u32 *) p3 = __lasx_xvpickve2gr_wu ((__m256i) r, 3);
  *(u32 *) p4 = __lasx_xvpickve2gr_wu ((__m256i) r, 4);
  *(u32 *) p5 = __lasx_xvpickve2gr_wu ((__m256i) r, 5);
  *(u32 *) p6 = __lasx_xvpickve2gr_wu ((__m256i) r, 6);
  *(u32 *) p7 = __lasx_xvpickve2gr_wu ((__m256i) r, 7);
}

static_always_inline void
u64x4_scatter_one (u64x4 r, int index, void *p)
{
  switch (index)
    {
    case 0:
      *(u64 *) p = __lasx_xvpickve2gr_du ((__m256i) r, 0);
      break;
    case 1:
      *(u64 *) p = __lasx_xvpickve2gr_du ((__m256i) r, 1);
      break;
    case 2:
      *(u64 *) p = __lasx_xvpickve2gr_du ((__m256i) r, 2);
      break;
    case 3:
      *(u64 *) p = __lasx_xvpickve2gr_du ((__m256i) r, 3);
      break;
    default:
      __builtin_unreachable ();
    }
}

static_always_inline void
u32x8_scatter_one (u32x8 r, int index, void *p)
{
  switch (index)
    {
    case 0:
      *(u32 *) p = __lasx_xvpickve2gr_wu ((__m256i) r, 0);
      break;
    case 1:
      *(u32 *) p = __lasx_xvpickve2gr_wu ((__m256i) r, 1);
      break;
    case 2:
      *(u32 *) p = __lasx_xvpickve2gr_wu ((__m256i) r, 2);
      break;
    case 3:
      *(u32 *) p = __lasx_xvpickve2gr_wu ((__m256i) r, 3);
      break;
    case 4:
      *(u32 *) p = __lasx_xvpickve2gr_wu ((__m256i) r, 4);
      break;
    case 5:
      *(u32 *) p = __lasx_xvpickve2gr_wu ((__m256i) r, 5);
      break;
    case 6:
      *(u32 *) p = __lasx_xvpickve2gr_wu ((__m256i) r, 6);
      break;
    case 7:
      *(u32 *) p = __lasx_xvpickve2gr_wu ((__m256i) r, 7);
      break;
    default:
      __builtin_unreachable ();
    }
}

static_always_inline u64x4
u64x4_byte_swap (u64x4 v)
{
  const u8x32 mask = { 7,  6,  5,  4,  3,  2,  1,  0,  15, 14, 13, 12, 11, 10, 9,  8,
		       23, 22, 21, 20, 19, 18, 17, 16, 31, 30, 29, 28, 27, 26, 25, 24 };
  return (u64x4) __lasx_xvshuf_b ((__m256i) v, (__m256i) v, (__m256i) mask);
}

static_always_inline u32x8
u32x8_byte_swap (u32x8 v)
{
  const u8x32 mask = { 3,  2,  1,  0,  7,  6,  5,  4,  11, 10, 9,  8,  15, 14, 13, 12,
		       19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28 };
  return (u32x8) __lasx_xvshuf_b ((__m256i) v, (__m256i) v, (__m256i) mask);
}

static_always_inline u16x16
u16x16_byte_swap (u16x16 v)
{
  const u8x32 mask = { 1,  0,  3,  2,  5,  4,  7,  6,  9,  8,  11, 10, 13, 12, 15, 14,
		       17, 16, 19, 18, 21, 20, 23, 22, 25, 24, 27, 26, 29, 28, 31, 30 };
  return (u16x16) __lasx_xvshuf_b ((__m256i) v, (__m256i) v, (__m256i) mask);
}

static_always_inline u8x32
u8x32_reflect_u8x16 (u8x32 v)
{
  const u8x32 mask = { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
		       15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
  return (u8x32) __lasx_xvshuf_b ((__m256i) v, (__m256i) v, (__m256i) mask);
}

static_always_inline u32
u32x8_sum_elts (u32x8 v)
{
  __m256i x = (__m256i) v;
  x = __lasx_xvadd_w (x, __lasx_xvbsrl_v (x, 8));
  x = __lasx_xvadd_w (x, __lasx_xvbsrl_v (x, 4));
  return __lasx_xvpickve2gr_wu (x, 0) + __lasx_xvpickve2gr_wu (x, 4);
}

static_always_inline u32
u32x8_min_scalar (u32x8 v)
{
  return u32x4_min_scalar (u32x4_min (u32x8_extract_lo (v), u32x8_extract_hi (v)));
}

static_always_inline u32x8
u32x8_hadd (u32x8 v1, u32x8 v2)
{
  u32x8 s1 = v1 + (u32x8) __lasx_xvbsrl_v ((__m256i) v1, 4);
  u32x8 s2 = v2 + (u32x8) __lasx_xvbsrl_v ((__m256i) v2, 4);
  return (u32x8) { s1[0], s1[2], s2[0], s2[2], s1[4], s1[6], s2[4], s2[6] };
}

#endif /* included_vector_lasx_h */
