/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_mask_array_h
#define included_vector_mask_array_h
#include <vppinfra/clib.h>

/** \brief Mask array of 32-bit elemments

    @param src source array of u32 elements
    @param mask use to mask the values of source array
    @param n_elts number of elements in the source array
    @return masked values are return in source array
*/

static_always_inline void
clib_mask_array_u32 (u32 *src, u32 mask, u32 n_elts)
{
  u32 i;
#if defined(CLIB_HAVE_VEC512)
  u32x16 mask16 = u32x16_splat (mask);

  for (i = 0; i + 16 <= n_elts; i += 16)
    *((u32x16u *) (src + i)) &= mask16;
  n_elts -= i;
  if (n_elts)
    {
      u16 m = pow2_mask (n_elts);
      u32x16_mask_store (u32x16_mask_load_zero (src + i, m) & mask16, src + i,
			 m);
    }
#elif defined(CLIB_HAVE_VEC256)
  u32x8 mask8 = u32x8_splat (mask);

  for (i = 0; i + 8 <= n_elts; i += 8)
    *((u32x8u *) (src + i)) &= mask8;
  n_elts -= i;
#if defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
  if (n_elts)
    {
      u8 m = pow2_mask (n_elts);
      u32x8_mask_store (u32x8_mask_load_zero (src + i, m) & mask8, src + i, m);
    }
#endif
#elif defined(CLIB_HAVE_VEC128)
  u32x4 mask4 = u32x4_splat (mask);

  for (i = 0; i + 4 <= n_elts; i += 4)
    *((u32x4u *) (src + i)) &= mask4;
  n_elts -= i;
  switch (n_elts)
    {
    case 3:
      src[2] &= mask;
      n_elts--;
    case 2:
      src[1] &= mask;
      n_elts--;
    case 1:
      src[0] &= mask;
      n_elts--;
    case 0:
    default:;
    }
#endif
  while (n_elts > 0)
    {
      src[0] &= mask;
      src++;
      n_elts--;
    }
}

#endif
