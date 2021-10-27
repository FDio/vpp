/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_array_mask_h
#define included_vector_array_mask_h
#include <vppinfra/clib.h>

/** \brief Mask array of 32-bit elemments

    @param src source array of u32 elements
    @param mask use to mask the values of source array
    @param n_elts number of elements in the source array
    @return masked values are return in source array
*/

static_always_inline void
clib_array_mask_u32 (u32 *src, u32 mask, u32 n_elts)
{
#if defined(CLIB_HAVE_VEC512)
  u32x16 mask16 = u32x16_splat (mask);
  if (n_elts <= 16)
    {
      u32 m = pow2_mask (n_elts);
      u32x16 r = u32x16_mask_load_zero (src, m);
      u32x16_mask_store (r & mask16, src, m);
      return;
    }
  for (int i = 0; i < n_elts; i += 16)
    *((u32x16u *) (src + i)) &= mask16;
  *((u32x16u *) (src + n_elts - 16)) &= mask16;
#elif defined(CLIB_HAVE_VEC256)
  u32x8 mask8 = u32x8_splat (mask);
#if defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
  if (n_elts <= 8)
    {
      u32 m = pow2_mask (n_elts);
      u32x8 r = u32x8_mask_load_zero (src, m);
      u32x8_mask_store (r & mask8, src, m);
      return;
    }
#else
  if (PREDICT_FALSE (n_elts < 4))
    {
      if (n_elts & 2)
	{
	  src[0] &= mask;
	  src[1] &= mask;
	  src += 2;
	}
      if (n_elts & 1)
	src[0] &= mask;
      return;
    }
  if (n_elts <= 8)
    {
      u32x4 mask4 = u32x4_splat (mask);
      *(u32x4u *) src &= mask4;
      *(u32x4u *) (src + n_elts - 4) &= mask4;
    }
#endif

  for (int i = 0; i < n_elts; i += 8)
    *((u32x8u *) (src + i)) &= mask8;
  *((u32x8u *) (src + n_elts - 8)) &= mask8;
#elif defined(CLIB_HAVE_VEC128)
  u32x4 mask4 = u32x4_splat (mask);

  if (PREDICT_FALSE (n_elts < 4))
    {
      if (n_elts & 2)
	{
	  src[0] &= mask;
	  src[1] &= mask;
	  src += 2;
	}
      if (n_elts & 1)
	src[0] &= mask;
      return;
    }

  for (int i = 0; i < n_elts; i += 4)
    *((u32x4u *) (src + i)) &= mask4;
  *((u32x4u *) (src + n_elts - 4)) &= mask4;
  return;
#else
  while (n_elts > 0)
    {
      src[0] &= mask;
      src++;
      n_elts--;
    }
#endif
}

#endif
