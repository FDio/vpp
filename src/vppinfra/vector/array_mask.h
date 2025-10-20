/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_array_mask_h
#define included_vector_array_mask_h
#include <vppinfra/clib.h>

/** \brief Mask array of 16-bit elemments

    @param src source array of u16 elements
    @param mask use to mask the values of source array
    @param n_elts number of elements in the source array
    @return masked values are return in source array
*/

static_always_inline void
clib_array_mask_u16 (u16 *src, u16 mask, u32 n_elts)
{
#if defined(CLIB_HAVE_VEC512)
  u16x32 mask32 = u16x32_splat (mask);
  if (n_elts <= 32)
    {
      u32 m = pow2_mask (n_elts);
      u16x32 r = u16x32_mask_load_zero (src, m);
      u16x32_mask_store (r & mask32, src, m);
      return;
    }
  for (; n_elts >= 32; n_elts -= 32, src += 32)
    *((u16x32u *) src) &= mask32;
  *((u16x32u *) (src + n_elts - 32)) &= mask32;
#elif defined(CLIB_HAVE_VEC256)
  u16x16 mask16 = u16x16_splat (mask);
#if defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
  if (n_elts <= 16)
    {
      u32 m = pow2_mask (n_elts);
      u16x16 r = u16x16_mask_load_zero (src, m);
      u16x16_mask_store (r & mask16, src, m);
      return;
    }
#else
  if (PREDICT_FALSE (n_elts < 8))
    {
      if (n_elts & 4)
	{
	  src[0] &= mask;
	  src[1] &= mask;
	  src[2] &= mask;
	  src[3] &= mask;
	  src += 4;
	}
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
  if (n_elts <= 16)
    {
      u16x8 mask8 = u16x8_splat (mask);
      *(u16x8u *) src &= mask8;
      *(u16x8u *) (src + n_elts - 8) &= mask8;
      return;
    }
#endif
  for (; n_elts >= 16; n_elts -= 16, src += 16)
    *((u16x16u *) src) &= mask16;
  *((u16x16u *) (src + n_elts - 16)) &= mask16;
#elif defined(CLIB_HAVE_VEC128)
  u16x8 mask8 = u16x8_splat (mask);

  if (PREDICT_FALSE (n_elts < 8))
    {
      if (n_elts & 4)
	{
	  src[0] &= mask;
	  src[1] &= mask;
	  src[2] &= mask;
	  src[3] &= mask;
	  src += 4;
	}
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

  for (; n_elts >= 8; n_elts -= 8, src += 8)
    *((u16x8u *) src) &= mask8;
  *((u16x8u *) (src + n_elts - 8)) &= mask8;
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
  for (; n_elts >= 16; n_elts -= 16, src += 16)
    *((u32x16u *) src) &= mask16;
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
      return;
    }
#endif

  for (; n_elts >= 8; n_elts -= 8, src += 8)
    *((u32x8u *) src) &= mask8;
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

  for (; n_elts >= 4; n_elts -= 4, src += 4)
    *((u32x4u *) src) &= mask4;
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

static_always_inline void
clib_array_mask_set_u32_x64 (u32 *a, u32 v, uword bmp, int n_elts)
{
#if defined(CLIB_HAVE_VEC512_MASK_LOAD_STORE)
  u32x16 r = u32x16_splat (v);
  for (; n_elts > 0; n_elts -= 16, a += 16, bmp >>= 16)
    u32x16_mask_store (r, a, bmp);
#elif defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
  u32x8 r = u32x8_splat (v);
  for (; n_elts > 0; n_elts -= 8, a += 8, bmp >>= 8)
    u32x8_mask_store (r, a, bmp);
#else
  while (bmp)
    {
      a[get_lowest_set_bit_index (bmp)] = v;
      bmp = clear_lowest_set_bit (bmp);
    }
#endif
}

static_always_inline void
clib_array_mask_set_u32 (u32 *a, u32 v, uword *bmp, u32 n_elts)
{
  while (n_elts >= uword_bits)
    {
      clib_array_mask_set_u32_x64 (a, v, bmp++[0], uword_bits);
      a += uword_bits;
      n_elts -= uword_bits;
    }

  clib_array_mask_set_u32_x64 (a, v, bmp[0] & pow2_mask (n_elts), n_elts);
}

#endif
