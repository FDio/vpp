/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_mask_compare_h
#define included_vector_mask_compare_h
#include <vppinfra/clib.h>
#include <vppinfra/memcpy.h>

static_always_inline u64
clib_mask_compare_u16_x64 (u16 v, u16 *a, u32 n_elts)
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

  x = i8x32_pack (v16 == av[0], v16 == av[1]);
  mask = i8x32_msb_mask ((i8x32) u64x4_permute (x, 0, 2, 1, 3));
  x = i8x32_pack (v16 == av[2], v16 == av[3]);
  mask |= (u64) i8x32_msb_mask ((i8x32) u64x4_permute (x, 0, 2, 1, 3)) << 32;
#elif defined(CLIB_HAVE_VEC128) && defined(__ARM_NEON)
  u16x8 v8 = u16x8_splat (v);
  u16x8 m = { 1, 2, 4, 8, 16, 32, 64, 128 };
  u16x8u *av = (u16x8u *) a;

  /* compare each u16 elemment with v8, result gives 0xffff in each element
     of the resulting vector if comparison result is true.
     Bitwise AND with m will give us one bit set for true result and offset
     of that bit represend element index. Finally vaddvq_u16() gives us sum
     of all elements of the vector which will give us u8 bitmap. */

  for (int i = 0; i < 8; i++)
    mask |= (u64) vaddvq_u16 ((av[i] == v8) & m) << (i * 8);

#elif defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_MSB_MASK)
  u16x8 v8 = u16x8_splat (v);
  u16x8u *av = (u16x8u *) a;
  mask = ((u64) i8x16_msb_mask (i8x16_pack (v8 == av[0], v8 == av[1])) |
	  (u64) i8x16_msb_mask (i8x16_pack (v8 == av[2], v8 == av[3])) << 16 |
	  (u64) i8x16_msb_mask (i8x16_pack (v8 == av[4], v8 == av[5])) << 32 |
	  (u64) i8x16_msb_mask (i8x16_pack (v8 == av[6], v8 == av[7])) << 48);
#else
  for (int i = 0; i < n_elts; i++)
    if (a[i] == v)
      mask |= 1ULL << i;
#endif
  return mask;
}

/** \brief Compare 16-bit elemments with provied value and return bitmap

    @param v value to compare elements with
    @param a array of u16 elements
    @param mask array of u64 where reuslting mask will be stored
    @param n_elts number of elements in the array
    @return none
*/

static_always_inline void
clib_mask_compare_u16 (u16 v, u16 *a, u64 *mask, u32 n_elts)
{
  while (n_elts >= 64)
    {
      mask++[0] = clib_mask_compare_u16_x64 (v, a, 64);
      n_elts -= 64;
      a += 64;
    }

  if (PREDICT_TRUE (n_elts == 0))
    return;

  mask[0] = clib_mask_compare_u16_x64 (v, a, n_elts) & pow2_mask (n_elts);
}

static_always_inline u64
clib_mask_compare_u32_x64 (u32 v, u32 *a, u32 n_elts)
{
  u64 mask = 0;
#if defined(CLIB_HAVE_VEC512)
  u32x16 v16 = u32x16_splat (v);
  u32x16u *av = (u32x16u *) a;
  mask = ((u64) u32x16_is_equal_mask (av[0], v16) |
	  (u64) u32x16_is_equal_mask (av[1], v16) << 16 |
	  (u64) u32x16_is_equal_mask (av[2], v16) << 32 |
	  (u64) u32x16_is_equal_mask (av[3], v16) << 48);
#elif defined(CLIB_HAVE_VEC256)
  u32x8 v8 = u32x8_splat (v);
  u32x8u *av = (u32x8u *) a;
  u32x8 m = { 0, 4, 1, 5, 2, 6, 3, 7 };
  i8x32 c;

  c = i8x32_pack (i16x16_pack ((i32x8) (v8 == av[0]), (i32x8) (v8 == av[1])),
		  i16x16_pack ((i32x8) (v8 == av[2]), (i32x8) (v8 == av[3])));
  mask = i8x32_msb_mask ((i8x32) u32x8_permute ((u32x8) c, m));

  c = i8x32_pack (i16x16_pack ((i32x8) (v8 == av[4]), (i32x8) (v8 == av[5])),
		  i16x16_pack ((i32x8) (v8 == av[6]), (i32x8) (v8 == av[7])));
  mask |= (u64) i8x32_msb_mask ((i8x32) u32x8_permute ((u32x8) c, m)) << 32;

#elif defined(CLIB_HAVE_VEC128) && defined(__ARM_NEON)
  u32x4 v4 = u32x4_splat (v);
  u32x4 m = { 1, 2, 4, 8 };
  u32x4u *av = (u32x4u *) a;

  /* compare each u32 elemment with v4, result gives -1 in each element
     of the resulting vector if comparison result is true.
     Bitwise AND with m will give us one bit set for true result and offset
     of that bit represend element index. Finally vaddvq_u32() gives us sum
     of all elements of the vector which will give us u8 bitmap. */

  for (int i = 0; i < 16; i++)
    mask |= (u64) vaddvq_u32 ((av[i] == v4) & m) << (i * 4);

#elif defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_MSB_MASK)
  u32x4 v4 = u32x4_splat (v);
  u32x4u *av = (u32x4u *) a;

  for (int i = 0; i < 4; i++)
    {
      i16x8 p1 = i16x8_pack (v4 == av[0], v4 == av[1]);
      i16x8 p2 = i16x8_pack (v4 == av[2], v4 == av[3]);
      mask |= (u64) i8x16_msb_mask (i8x16_pack (p1, p2)) << (i * 16);
      av += 4;
    }

#else
  for (int i = 0; i < n_elts; i++)
    if (a[i] == v)
      mask |= 1ULL << i;
#endif
  return mask;
}

/** \brief Compare 32-bit elemments with provied value and return bitmap

    @param v value to compare elements with
    @param a array of u32 elements
    @param mask array of u64 where reuslting mask will be stored
    @param n_elts number of elements in the array
    @return none
*/

static_always_inline void
clib_mask_compare_u32 (u32 v, u32 *a, u64 *bitmap, u32 n_elts)
{
  while (n_elts >= 64)
    {
      bitmap++[0] = clib_mask_compare_u32_x64 (v, a, 64);
      n_elts -= 64;
      a += 64;
    }

  if (PREDICT_TRUE (n_elts == 0))
    return;

  bitmap[0] = clib_mask_compare_u32_x64 (v, a, n_elts) & pow2_mask (n_elts);
}

static_always_inline u64
clib_mask_compare_u64_x64 (u64 v, u64 *a, u32 n_elts)
{
  u64 mask = 0;
#if defined(CLIB_HAVE_VEC512)
  u64x8 v8 = u64x8_splat (v);
  u64x8u *av = (u64x8u *) a;
  mask = ((u64) u64x8_is_equal_mask (av[0], v8) |
	  (u64) u64x8_is_equal_mask (av[1], v8) << 8 |
	  (u64) u64x8_is_equal_mask (av[2], v8) << 16 |
	  (u64) u64x8_is_equal_mask (av[3], v8) << 24 |
	  (u64) u64x8_is_equal_mask (av[4], v8) << 32 |
	  (u64) u64x8_is_equal_mask (av[5], v8) << 40 |
	  (u64) u64x8_is_equal_mask (av[6], v8) << 48 |
	  (u64) u64x8_is_equal_mask (av[7], v8) << 56);

#elif defined(CLIB_HAVE_VEC256) && defined(__BMI2__)
  u64x4 v4 = u64x4_splat (v);
  u64x4u *av = (u64x4u *) a;

  for (int i = 0; i < 16; i += 2)
    {
      u64 l = u8x32_msb_mask (v4 == av[i]);
      u64 h = u8x32_msb_mask (v4 == av[i + 1]);
      mask |= _pext_u64 (l | h << 32, 0x0101010101010101) << (i * 4);
    }
#else
  for (int i = 0; i < n_elts; i++)
    if (a[i] == v)
      mask |= 1ULL << i;
#endif
  return mask;
}

/** \brief Compare 64-bit elemments with provied value and return bitmap

    @param v value to compare elements with
    @param a array of u64 elements
    @param mask array of u64 where reuslting mask will be stored
    @param n_elts number of elements in the array
    @return none
*/

static_always_inline void
clib_mask_compare_u64 (u64 v, u64 *a, u64 *bitmap, u32 n_elts)
{
  while (n_elts >= 64)
    {
      bitmap++[0] = clib_mask_compare_u64_x64 (v, a, 64);
      n_elts -= 64;
      a += 64;
    }

  if (PREDICT_TRUE (n_elts == 0))
    return;

  bitmap[0] = clib_mask_compare_u64_x64 (v, a, n_elts) & pow2_mask (n_elts);
}

#endif
