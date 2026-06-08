/*
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#ifndef included_vector_lsx_h
#define included_vector_lsx_h

#include <lsxintrin.h>

#define foreach_lsx_vec128i _ (i, 8, 16, b) _ (i, 16, 8, h) _ (i, 32, 4, w) _ (i, 64, 2, d)
#define foreach_lsx_vec128u _ (u, 8, 16, b) _ (u, 16, 8, h) _ (u, 32, 4, w) _ (u, 64, 2, d)

#define _(t, s, c, i)                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_splat (t##s x)                                      \
  {                                                                                                \
    return (t##s##x##c) __lsx_vreplgr2vr_##i ((long int) x);                                       \
  }                                                                                                \
                                                                                                   \
  static_always_inline t##s##x##c t##s##x##c##_load_unaligned (void *p)                            \
  {                                                                                                \
    return (t##s##x##c) __lsx_vld (p, 0);                                                          \
  }                                                                                                \
                                                                                                   \
  static_always_inline void t##s##x##c##_store_unaligned (t##s##x##c v, void *p)                   \
  {                                                                                                \
    __lsx_vst ((__m128i) v, p, 0);                                                                 \
  }                                                                                                \
                                                                                                   \
  static_always_inline int t##s##x##c##_is_all_zero (t##s##x##c x)                                 \
  {                                                                                                \
    return __lsx_vpickve2gr_du (__lsx_vmsknz_b ((__m128i) x), 0) == 0;                             \
  }                                                                                                \
                                                                                                   \
  static_always_inline int t##s##x##c##_is_equal (t##s##x##c a, t##s##x##c b)                      \
  {                                                                                                \
    return t##s##x##c##_is_all_zero ((t##s##x##c) __lsx_vxor_v ((__m128i) a, (__m128i) b));        \
  }                                                                                                \
                                                                                                   \
  static_always_inline int t##s##x##c##_is_all_equal (t##s##x##c v, t##s x)                        \
  {                                                                                                \
    return t##s##x##c##_is_equal (v, t##s##x##c##_splat (x));                                      \
  }

foreach_lsx_vec128i foreach_lsx_vec128u
#undef _

#define _(t, s, c, i)                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_min (t##s##x##c a, t##s##x##c b)                    \
  {                                                                                                \
    return (t##s##x##c) __lsx_vmin_##i ((__m128i) a, (__m128i) b);                                 \
  }                                                                                                \
                                                                                                   \
  static_always_inline t##s##x##c t##s##x##c##_max (t##s##x##c a, t##s##x##c b)                    \
  {                                                                                                \
    return (t##s##x##c) __lsx_vmax_##i ((__m128i) a, (__m128i) b);                                 \
  }

  foreach_lsx_vec128i
#undef _

#define _(t, s, c, i)                                                                              \
  static_always_inline t##s##x##c t##s##x##c##_min (t##s##x##c a, t##s##x##c b)                    \
  {                                                                                                \
    return (t##s##x##c) __lsx_vmin_##i##u ((__m128i) a, (__m128i) b);                              \
  }                                                                                                \
                                                                                                   \
  static_always_inline t##s##x##c t##s##x##c##_max (t##s##x##c a, t##s##x##c b)                    \
  {                                                                                                \
    return (t##s##x##c) __lsx_vmax_##i##u ((__m128i) a, (__m128i) b);                              \
  }

    foreach_lsx_vec128u
#undef _

/* 128 bit packs. */
#define _(f, t, fn)                                                                                \
  static_always_inline t t##_pack (f lo, f hi) { return (t) fn ((__m128i) hi, (__m128i) lo, 0); }

    _ (i16x8, i8x16, __lsx_vssrani_b_h) _ (i16x8, u8x16, __lsx_vssrani_bu_h)
      _ (i32x4, i16x8, __lsx_vssrani_h_w) _ (i32x4, u16x8, __lsx_vssrani_hu_w)

#undef _

#define CLIB_VEC128_SPLAT_DEFINED
#define CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE
#define CLIB_HAVE_VEC128_MSB_MASK

#define u8x16_word_shift_left(x, n)                                                                \
  ((u8x16) ((n) > 15 ? __lsx_vldi (0) : __lsx_vbsll_v ((__m128i) (x), (n))))

#define u8x16_word_shift_right(x, n)                                                               \
  ((u8x16) ((n) > 15 ? __lsx_vldi (0) : __lsx_vbsrl_v ((__m128i) (x), (n))))

	static_always_inline u16 u8x16_msb_mask (u8x16 v)
{
  return (u16) __lsx_vpickve2gr_du (__lsx_vmskltz_b ((__m128i) v), 0);
}

static_always_inline u16
i8x16_msb_mask (i8x16 v)
{
  return u8x16_msb_mask ((u8x16) v);
}

static_always_inline u8x16
u8x16_blend (u8x16 dst, u8x16 src, u8x16 mask)
{
  return (u8x16) __lsx_vbitsel_v ((__m128i) dst, (__m128i) src, (__m128i) mask);
}

static_always_inline u32x4
u32x4_interleave_lo (u32x4 a, u32x4 b)
{
  return (u32x4) __lsx_vilvl_w ((__m128i) b, (__m128i) a);
}

static_always_inline u32x4
u32x4_interleave_hi (u32x4 a, u32x4 b)
{
  return (u32x4) __lsx_vilvh_w ((__m128i) b, (__m128i) a);
}

static_always_inline u64x2
u64x2_interleave_lo (u64x2 a, u64x2 b)
{
  return (u64x2) __lsx_vilvl_d ((__m128i) b, (__m128i) a);
}

static_always_inline u64x2
u64x2_interleave_hi (u64x2 a, u64x2 b)
{
  return (u64x2) __lsx_vilvh_d ((__m128i) b, (__m128i) a);
}

static_always_inline u64x2
u64x2_from_u32x4 (u32x4 v)
{
  return (u64x2) __lsx_vilvl_w (__lsx_vldi (0), (__m128i) v);
}

static_always_inline u64x2
u64x2_from_u32x4_high (u32x4 v)
{
  return (u64x2) __lsx_vilvh_w (__lsx_vldi (0), (__m128i) v);
}

static_always_inline u16x8
u16x8_from_u8x16 (u8x16 v)
{
  return (u16x8) __lsx_vilvl_b (__lsx_vldi (0), (__m128i) v);
}

static_always_inline u16x8
u16x8_from_u8x16_high (u8x16 v)
{
  return (u16x8) __lsx_vilvh_b (__lsx_vldi (0), (__m128i) v);
}

static_always_inline u64x2
u64x2_gather (void *p0, void *p1)
{
  __m128i r = __lsx_vldrepl_d (p0, 0);
  return (u64x2) __lsx_vinsgr2vr_d (r, *(u64 *) p1, 1);
}

static_always_inline u32x4
u32x4_gather (void *p0, void *p1, void *p2, void *p3)
{
  __m128i r = __lsx_vldrepl_w (p0, 0);
  r = __lsx_vinsgr2vr_w (r, *(u32 *) p1, 1);
  r = __lsx_vinsgr2vr_w (r, *(u32 *) p2, 2);
  r = __lsx_vinsgr2vr_w (r, *(u32 *) p3, 3);
  return (u32x4) r;
}

static_always_inline void
u64x2_scatter (u64x2 r, void *p0, void *p1)
{
  *(u64 *) p0 = __lsx_vpickve2gr_du ((__m128i) r, 0);
  *(u64 *) p1 = __lsx_vpickve2gr_du ((__m128i) r, 1);
}

static_always_inline void
u32x4_scatter (u32x4 r, void *p0, void *p1, void *p2, void *p3)
{
  *(u32 *) p0 = __lsx_vpickve2gr_wu ((__m128i) r, 0);
  *(u32 *) p1 = __lsx_vpickve2gr_wu ((__m128i) r, 1);
  *(u32 *) p2 = __lsx_vpickve2gr_wu ((__m128i) r, 2);
  *(u32 *) p3 = __lsx_vpickve2gr_wu ((__m128i) r, 3);
}

static_always_inline void
u64x2_scatter_one (u64x2 r, int index, void *p)
{
  switch (index)
    {
    case 0:
      *(u64 *) p = __lsx_vpickve2gr_du ((__m128i) r, 0);
      break;
    case 1:
      *(u64 *) p = __lsx_vpickve2gr_du ((__m128i) r, 1);
      break;
    default:
      __builtin_unreachable ();
    }
}

static_always_inline void
u32x4_scatter_one (u32x4 r, int index, void *p)
{
  switch (index)
    {
    case 0:
      *(u32 *) p = __lsx_vpickve2gr_wu ((__m128i) r, 0);
      break;
    case 1:
      *(u32 *) p = __lsx_vpickve2gr_wu ((__m128i) r, 1);
      break;
    case 2:
      *(u32 *) p = __lsx_vpickve2gr_wu ((__m128i) r, 2);
      break;
    case 3:
      *(u32 *) p = __lsx_vpickve2gr_wu ((__m128i) r, 3);
      break;
    default:
      __builtin_unreachable ();
    }
}

static_always_inline u32
u32x4_sum_elts (u32x4 v)
{
  __m128i x = (__m128i) v;
  x = __lsx_vadd_w (x, __lsx_vbsrl_v (x, 8));
  x = __lsx_vadd_w (x, __lsx_vbsrl_v (x, 4));
  return __lsx_vpickve2gr_wu (x, 0);
}

static_always_inline u16
u16x8_sum_elts (u16x8 v)
{
  __m128i x = (__m128i) v;
  x = __lsx_vadd_h (x, __lsx_vbsrl_v (x, 8));
  x = __lsx_vadd_h (x, __lsx_vbsrl_v (x, 4));
  x = __lsx_vadd_h (x, __lsx_vbsrl_v (x, 2));
  return (u16) __lsx_vpickve2gr_hu (x, 0);
}

static_always_inline u32
u32x4_min_scalar (u32x4 v)
{
  __m128i x = (__m128i) v;
  x = __lsx_vmin_wu (x, __lsx_vbsrl_v (x, 8));
  x = __lsx_vmin_wu (x, __lsx_vbsrl_v (x, 4));
  return __lsx_vpickve2gr_wu (x, 0);
}

static_always_inline u32
u32x4_max_scalar (u32x4 v)
{
  __m128i x = (__m128i) v;
  x = __lsx_vmax_wu (x, __lsx_vbsrl_v (x, 8));
  x = __lsx_vmax_wu (x, __lsx_vbsrl_v (x, 4));
  return __lsx_vpickve2gr_wu (x, 0);
}

static_always_inline i32
i32x4_min_scalar (i32x4 v)
{
  __m128i x = (__m128i) v;
  x = __lsx_vmin_w (x, __lsx_vbsrl_v (x, 8));
  x = __lsx_vmin_w (x, __lsx_vbsrl_v (x, 4));
  return __lsx_vpickve2gr_w ((__m128i) x, 0);
}

static_always_inline i32
i32x4_max_scalar (i32x4 v)
{
  __m128i x = (__m128i) v;
  x = __lsx_vmax_w (x, __lsx_vbsrl_v (x, 8));
  x = __lsx_vmax_w (x, __lsx_vbsrl_v (x, 4));
  return __lsx_vpickve2gr_w ((__m128i) x, 0);
}

static_always_inline u32x4
u32x4_hadd (u32x4 v1, u32x4 v2)
{
  __m128i s1 = __lsx_vadd_w ((__m128i) v1, __lsx_vbsrl_v ((__m128i) v1, 4));
  __m128i s2 = __lsx_vadd_w ((__m128i) v2, __lsx_vbsrl_v ((__m128i) v2, 4));
  return (u32x4) __lsx_vpickev_w (s2, s1);
}

static_always_inline u32x4
u32x4_byte_swap (u32x4 v)
{
  const u8x16 mask = { 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12 };
  return (u32x4) __lsx_vshuf_b ((__m128i) v, (__m128i) v, (__m128i) mask);
}

static_always_inline u16x8
u16x8_byte_swap (u16x8 v)
{
  const u8x16 mask = { 1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14 };
  return (u16x8) __lsx_vshuf_b ((__m128i) v, (__m128i) v, (__m128i) mask);
}

static_always_inline u8x16
u8x16_reflect (u8x16 v)
{
  const u8x16 mask = { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
  return (u8x16) __lsx_vshuf_b ((__m128i) v, (__m128i) v, (__m128i) mask);
}

static_always_inline u8x16
u8x16_xor3 (u8x16 a, u8x16 b, u8x16 c)
{
  return (u8x16) __lsx_vxor_v (__lsx_vxor_v ((__m128i) a, (__m128i) b), (__m128i) c);
}

static_always_inline u8x16
u8x16_load_partial (u8 *data, uword n)
{
  u8x16 r = {};
  /*
   * The overlap-and-shift cases below use per-lane C vector shifts.  For
   * exact 2/4/8 byte loads the shift count would equal the lane width
   * (16/32/64), which is undefined and has been observed to duplicate the
   * loaded lane on LoongArch.
   */
  if (n > 7)
    {
      if (n == 8)
	{
	  u64x2 r = {};
	  r[0] = *(u64u *) data;
	  return (u8x16) r;
	}
      u64x2 r = {};
      r[1] = *(u64u *) (data + n - 8);
      r >>= (16 - n) * 8;
      r[0] = *(u64u *) data;
      return (u8x16) r;
    }
  else if (n > 3)
    {
      if (n == 4)
	{
	  u32x4 r = {};
	  r[0] = *(u32u *) data;
	  return (u8x16) r;
	}
      u32x4 r = {};
      r[1] = *(u32u *) (data + n - 4);
      r >>= (8 - n) * 8;
      r[0] = *(u32u *) data;
      return (u8x16) r;
    }
  else if (n > 1)
    {
      if (n == 2)
	{
	  u16x8 r = {};
	  r[0] = *(u16u *) data;
	  return (u8x16) r;
	}
      u16x8 r = {};
      r[1] = *(u16u *) (data + n - 2);
      r >>= (4 - n) * 8;
      r[0] = *(u16u *) data;
      return (u8x16) r;
    }
  else if (n > 0)
    r[0] = *data;
  return r;
}

static_always_inline void
u8x16_store_partial (u8x16 r, u8 *data, uword n)
{
  /*
   * Keep exact 2/4/8 byte stores off the overlap-and-shift path for the same
   * reason as u8x16_load_partial: shifting a lane by its width is undefined.
   */
  if (n > 7)
    {
      if (n == 8)
	{
	  *(u64u *) data = ((u64x2) r)[0];
	  return;
	}
      *(u64u *) (data + n - 8) = ((u64x2) r)[1] << ((16 - n) * 8);
      *(u64u *) data = ((u64x2) r)[0];
    }
  else if (n > 3)
    {
      if (n == 4)
	{
	  *(u32u *) data = ((u32x4) r)[0];
	  return;
	}
      *(u32u *) (data + n - 4) = ((u32x4) r)[1] << ((8 - n) * 8);
      *(u32u *) data = ((u32x4) r)[0];
    }
  else if (n > 1)
    {
      if (n == 2)
	{
	  *(u16u *) data = ((u16x8) r)[0];
	  return;
	}
      *(u16u *) (data + n - 2) = ((u16x8) r)[1] << ((4 - n) * 8);
      *(u16u *) data = ((u16x8) r)[0];
    }
  else if (n > 0)
    data[0] = r[0];
}

#endif /* included_vector_lsx_h */
