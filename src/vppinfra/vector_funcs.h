/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_funcs_h
#define included_vector_funcs_h
#include <vppinfra/clib.h>

/** \brief Compare 64 16-bit elemments with provied value and return bitmap

    @param v value to compare elements with
    @param a array of 64 u16 elements
    @return u64 bitmap where each bit represents result of comparison
*/

static_always_inline u64
clib_compare_u16_x64 (u16 v, u16 *a)
{
  u64 mask = 0;
#if defined(CLIB_HAVE_VEC512) && !defined(__aarch64__)
  u16x32 v32 = u16x32_splat (v);
  u16x32u *av = (u16x32u *) a;
  mask = ((u64) u16x32_is_equal_mask (av[0], v32) |
	  (u64) u16x32_is_equal_mask (av[1], v32) << 32);
#elif defined(CLIB_HAVE_VEC256)
  u16x16 v16 = u16x16_splat (v);
  u16x16u *av = (u16x16u *) a;
  i8x32 x;

  x = i16x16_pack (v16 == av[0], v16 == av[1]);
  mask = i8x32_msb_mask ((i8x32) u64x4_permute (x, 0, 2, 1, 3));
  x = i16x16_pack (v16 == av[2], v16 == av[3]);
  mask |= (u64) i8x32_msb_mask ((i8x32) u64x4_permute (x, 0, 2, 1, 3)) << 32;
#elif defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_MSB_MASK)
  u16x8 idx8 = u16x8_splat (v);
  u16x8u *av = (u16x8u *) a;
  mask =
    ((u64) i8x16_msb_mask (i16x8_pack (idx8 == av[0], idx8 == av[1])) |
     (u64) i8x16_msb_mask (i16x8_pack (idx8 == av[2], idx8 == av[3])) << 16 |
     (u64) i8x16_msb_mask (i16x8_pack (idx8 == av[4], idx8 == av[5])) << 32 |
     (u64) i8x16_msb_mask (i16x8_pack (idx8 == av[6], idx8 == av[7])) << 48);
#else
  for (int i = 0; i < 64; i++)
    if (a[i] == v)
      mask |= 1ULL << i;
#endif
  return mask;
}

#endif
