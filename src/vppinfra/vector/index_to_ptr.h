/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_index_to_ptr_h
#define included_vector_index_to_ptr_h
#include <vppinfra/clib.h>

#ifdef CLIB_HAVE_VEC128
static_always_inline void
clib_index_to_ptr_u32_vec128 (u32 *indices, void **ptrs, i32 i, u64x2 ov,
			      u8 shift)
{
  u32x4u *iv = (u32x4u *) (indices + i);
  u64x2u *pv = (u64x2u *) (ptrs + i);
  u32x4 iv4 = iv[0];
  u64x2 pv2;
  pv2 = u64x2_from_u32x4 (iv4);
  pv[0] = (pv2 << shift) + ov;
#ifdef __aarch64__
  pv2 = u64x2_from_u32x4_high (iv4);
#else
  pv2 = u64x2_from_u32x4 ((u32x4) u8x16_word_shift_right (iv4, 8));
#endif
  pv[1] = (pv2 << shift) + ov;
}
#endif

/** \brief Convert array of indices to pointers with base and shift

    @param indices source array of u32 indices
    @param base base pointer
    @param shift numbers of bits to be shifted
    @param ptrs destinatin array of pointers
    @param n_elts number of elements in the source array
*/

static_always_inline void
clib_index_to_ptr_u32 (u32 *indices, void *base, u8 shift, void **ptrs,
		       u32 n_elts)
{
#ifdef CLIB_HAVE_VEC512
  if (PREDICT_TRUE (n_elts > 8))
    {
      u32x8u *iv = (u32x8u *) indices;
      u64x8u *pv = (u64x8u *) ptrs;
      u64x8 ov = u64x8_splat ((u64) base);
      u32 n = n_elts;

      while (n >= 64)
	{
	  pv[0] = (u64x8_from_u32x8 (iv[0]) << shift) + ov;
	  pv[1] = (u64x8_from_u32x8 (iv[1]) << shift) + ov;
	  pv[2] = (u64x8_from_u32x8 (iv[2]) << shift) + ov;
	  pv[3] = (u64x8_from_u32x8 (iv[3]) << shift) + ov;
	  pv[4] = (u64x8_from_u32x8 (iv[4]) << shift) + ov;
	  pv[5] = (u64x8_from_u32x8 (iv[5]) << shift) + ov;
	  pv[6] = (u64x8_from_u32x8 (iv[6]) << shift) + ov;
	  pv[7] = (u64x8_from_u32x8 (iv[7]) << shift) + ov;
	  pv += 8;
	  iv += 8;
	  n -= 64;
	}

      if (n == 0)
	return;

      if (n >= 32)
	{
	  pv[0] = (u64x8_from_u32x8 (iv[0]) << shift) + ov;
	  pv[1] = (u64x8_from_u32x8 (iv[1]) << shift) + ov;
	  pv[2] = (u64x8_from_u32x8 (iv[2]) << shift) + ov;
	  pv[3] = (u64x8_from_u32x8 (iv[3]) << shift) + ov;
	  pv += 4;
	  iv += 4;
	  n -= 32;
	}

      if (n >= 16)
	{
	  pv[0] = (u64x8_from_u32x8 (iv[0]) << shift) + ov;
	  pv[1] = (u64x8_from_u32x8 (iv[1]) << shift) + ov;
	  pv += 2;
	  iv += 2;
	  n -= 16;
	}

      if (n > 8)
	pv[0] = (u64x8_from_u32x8 (iv[0]) << shift) + ov;

      iv = (u32x8u *) (indices + n_elts - 8);
      pv = (u64x8u *) (ptrs + n_elts - 8);
      pv[0] = (u64x8_from_u32x8 (iv[0]) << shift) + ov;
      return;
    }
#ifdef CLIB_HAVE_VEC256_MASK_LOAD_STORE
  else
    {
      u32 mask = pow2_mask (n_elts);
      u64x8 r = u64x8_from_u32x8 (u32x8_mask_load_zero (indices, mask));
      u64x8_mask_store ((r << shift) + u64x8_splat ((u64) base), ptrs, mask);
      return;
    }
#endif
#elif defined(CLIB_HAVE_VEC256)
  if (PREDICT_TRUE (n_elts > 4))
    {
      u64x4 ov = u64x4_splat ((u64) base);
      u32x4u *iv = (u32x4u *) indices;
      u64x4u *pv = (u64x4u *) ptrs;
      u32 n = n_elts;

      while (n >= 32)
	{
	  pv[0] = (u64x4_from_u32x4 (iv[0]) << shift) + ov;
	  pv[1] = (u64x4_from_u32x4 (iv[1]) << shift) + ov;
	  pv[2] = (u64x4_from_u32x4 (iv[2]) << shift) + ov;
	  pv[3] = (u64x4_from_u32x4 (iv[3]) << shift) + ov;
	  pv[4] = (u64x4_from_u32x4 (iv[4]) << shift) + ov;
	  pv[5] = (u64x4_from_u32x4 (iv[5]) << shift) + ov;
	  pv[6] = (u64x4_from_u32x4 (iv[6]) << shift) + ov;
	  pv[7] = (u64x4_from_u32x4 (iv[7]) << shift) + ov;
	  pv += 8;
	  iv += 8;
	  n -= 32;
	}

      if (n == 0)
	return;

      if (n >= 16)
	{
	  pv[0] = (u64x4_from_u32x4 (iv[0]) << shift) + ov;
	  pv[1] = (u64x4_from_u32x4 (iv[1]) << shift) + ov;
	  pv[2] = (u64x4_from_u32x4 (iv[2]) << shift) + ov;
	  pv[3] = (u64x4_from_u32x4 (iv[3]) << shift) + ov;
	  pv += 4;
	  iv += 4;
	  n -= 16;
	}

      if (n >= 8)
	{
	  pv[0] = (u64x4_from_u32x4 (iv[0]) << shift) + ov;
	  pv[1] = (u64x4_from_u32x4 (iv[1]) << shift) + ov;
	  pv += 2;
	  iv += 2;
	  n -= 8;
	}

      if (n > 4)
	pv[0] = (u64x4_from_u32x4 (iv[0]) << shift) + ov;

      iv = (u32x4u *) (indices + n_elts - 4);
      pv = (u64x4u *) (ptrs + n_elts - 4);
      pv[0] = (u64x4_from_u32x4 (iv[0]) << shift) + ov;
    }
#ifdef CLIB_HAVE_VEC256_MASK_LOAD_STORE
  else
    {
      u32 mask = pow2_mask (n_elts);
      u64x4 r = u64x4_from_u32x4 (u32x4_mask_load_zero (indices, mask));
      u64x4_mask_store ((r << shift) + u64x4_splat ((u64) base), ptrs, mask);
      return;
    }
#endif
#elif defined(CLIB_HAVE_VEC1x28)
  if (n_elts >= 4)
    {
      u64x2 ov = u64x2_splat ((u64) base);
      u32 n = n_elts;

      while (n >= 32)
	{
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 0, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 4, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 8, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 12, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 16, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 20, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 24, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 28, ov, shift);
	  indices += 32;
	  ptrs += 32;
	  n -= 32;
	}

      if (n == 0)
	return;

      if (n >= 16)
	{
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 0, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 4, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 8, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 12, ov, shift);
	  indices += 16;
	  ptrs += 16;
	  n -= 16;
	}

      if (n >= 8)
	{
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 0, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, 4, ov, shift);
	  indices += 8;
	  ptrs += 8;
	  n -= 8;
	}

      if (n > 4)
	clib_index_to_ptr_u32_vec128 (indices, ptrs, 0, ov, shift);

      clib_index_to_ptr_u32_vec128 (indices, ptrs, n_elts - 4, ov, shift);
      return;
    }
#endif
  while (n_elts)
    {
      ptrs[0] = base + ((u64) indices[0] << shift);
      ptrs++;
      indices++;
      n_elts--;
    }
}

#endif
