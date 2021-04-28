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
#if defined(CLIB_HAVE_VEC512)
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
#elif defined(CLIB_HAVE_VEC128) && defined(__ARM_NEON)
  u16x8 idx8 = u16x8_splat (v);
  u16x8 m = { 1, 2, 4, 8, 16, 32, 64, 128 };
  u16x8u *av = (u16x8u *) a;

  /* compare each u16 elemment with idx8, result gives 0xffff in each element
     of the resulting vector if comparison result is true.
     Bitwise AND with m will give us one bit set for true result and offset
     of that bit represend element index. Finally vaddvq_u16() gives us sum
     of all elements of the vector which will give us u8 bitmap. */

  mask = ((u64) vaddvq_u16 ((av[0] == idx8) & m) |
	  (u64) vaddvq_u16 ((av[1] == idx8) & m) << 8 |
	  (u64) vaddvq_u16 ((av[2] == idx8) & m) << 16 |
	  (u64) vaddvq_u16 ((av[3] == idx8) & m) << 24 |
	  (u64) vaddvq_u16 ((av[4] == idx8) & m) << 32 |
	  (u64) vaddvq_u16 ((av[5] == idx8) & m) << 40 |
	  (u64) vaddvq_u16 ((av[6] == idx8) & m) << 48 |
	  (u64) vaddvq_u16 ((av[7] == idx8) & m) << 56);
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
