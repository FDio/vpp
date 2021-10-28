/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_index_to_ptr_h
#define included_vector_index_to_ptr_h
#include <vppinfra/clib.h>

#ifdef CLIB_HAVE_VEC128
static_always_inline void
clib_index_to_ptr_u32_vec128 (u32 *indices, void **ptrs, u32 i, u64x2 ov,
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
  if (n_elts >= 8)
    {
      u32x8u *iv = (u32x8u *) indices;
      u64x8u *pv = (u64x8u *) ptrs;
      u64x8 ov = u64x8_splat ((u64) base);
      u32 i, n = round_pow2 (n_elts - 8, 8) / 8;

      for (i = 0; i + 7 < n; i += 8)
	{
	  pv[i + 0] = (u64x8_from_u32x8 (iv[i + 0]) << shift) + ov;
	  pv[i + 1] = (u64x8_from_u32x8 (iv[i + 1]) << shift) + ov;
	  pv[i + 2] = (u64x8_from_u32x8 (iv[i + 2]) << shift) + ov;
	  pv[i + 3] = (u64x8_from_u32x8 (iv[i + 3]) << shift) + ov;
	  pv[i + 4] = (u64x8_from_u32x8 (iv[i + 4]) << shift) + ov;
	  pv[i + 5] = (u64x8_from_u32x8 (iv[i + 5]) << shift) + ov;
	  pv[i + 6] = (u64x8_from_u32x8 (iv[i + 6]) << shift) + ov;
	  pv[i + 7] = (u64x8_from_u32x8 (iv[i + 7]) << shift) + ov;
	}
      if (i + 3 < n)
	{
	  pv[i + 0] = (u64x8_from_u32x8 (iv[i + 0]) << shift) + ov;
	  pv[i + 1] = (u64x8_from_u32x8 (iv[i + 1]) << shift) + ov;
	  pv[i + 2] = (u64x8_from_u32x8 (iv[i + 2]) << shift) + ov;
	  pv[i + 3] = (u64x8_from_u32x8 (iv[i + 3]) << shift) + ov;
	  i += 4;
	}

      if (i + 1 < n)
	{
	  pv[i + 0] = (u64x8_from_u32x8 (iv[i + 0]) << shift) + ov;
	  pv[i + 1] = (u64x8_from_u32x8 (iv[i + 1]) << shift) + ov;
	  i += 2;
	}

      if (i < n)
	pv[i + 0] = (u64x8_from_u32x8 (iv[i + 0]) << shift) + ov;

      iv = (u32x8u *) (indices + n_elts - 8);
      pv = (u64x8u *) (ptrs + n_elts - 8);
      pv[0] = (u64x8_from_u32x8 (iv[0]) << shift) + ov;
      return;
    }
#elif defined(CLIB_HAVE_VEC256)
  if (n_elts >= 4)
    {
      u64x4 ov = u64x4_splat ((u64) base);
      u32x4u *iv = (u32x4u *) indices;
      u64x4u *pv = (u64x4u *) ptrs;
      u32 n = round_pow2 (n_elts - 4, 4) / 4;
      u32 i;

      for (i = 0; i + 7 < n; i += 8)
	{
	  pv[i + 0] = (u64x4_from_u32x4 (iv[i + 0]) << shift) + ov;
	  pv[i + 1] = (u64x4_from_u32x4 (iv[i + 1]) << shift) + ov;
	  pv[i + 2] = (u64x4_from_u32x4 (iv[i + 2]) << shift) + ov;
	  pv[i + 3] = (u64x4_from_u32x4 (iv[i + 3]) << shift) + ov;
	  pv[i + 4] = (u64x4_from_u32x4 (iv[i + 4]) << shift) + ov;
	  pv[i + 5] = (u64x4_from_u32x4 (iv[i + 5]) << shift) + ov;
	  pv[i + 6] = (u64x4_from_u32x4 (iv[i + 6]) << shift) + ov;
	  pv[i + 7] = (u64x4_from_u32x4 (iv[i + 7]) << shift) + ov;
	}

      if (i + 3 < n)
	{
	  pv[i + 0] = (u64x4_from_u32x4 (iv[i + 0]) << shift) + ov;
	  pv[i + 1] = (u64x4_from_u32x4 (iv[i + 1]) << shift) + ov;
	  pv[i + 2] = (u64x4_from_u32x4 (iv[i + 2]) << shift) + ov;
	  pv[i + 3] = (u64x4_from_u32x4 (iv[i + 3]) << shift) + ov;
	  i += 4;
	}

      if (i + 1 < n)
	{
	  pv[i + 0] = (u64x4_from_u32x4 (iv[i + 0]) << shift) + ov;
	  pv[i + 1] = (u64x4_from_u32x4 (iv[i + 1]) << shift) + ov;
	  i += 2;
	}

      if (i < n)
	pv[i + 0] = (u64x4_from_u32x4 (iv[i + 0]) << shift) + ov;

      iv = (u32x4u *) (indices + n_elts - 4);
      pv = (u64x4u *) (ptrs + n_elts - 4);
      pv[0] = (u64x4_from_u32x4 (iv[0]) << shift) + ov;
      return;
    }
#elif defined(CLIB_HAVE_VEC128)
  if (n_elts >= 4)
    {
      u64x2 ov = u64x2_splat ((u64) base);
      u32 n = round_pow2 (n_elts - 4, 4);
      u32 i;

      for (i = 0; i + 31 < n; i += 32)
	{
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 0, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 4, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 8, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 12, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 16, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 20, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 24, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 28, ov, shift);
	}

      if (i + 15 < n)
	{
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 0, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 4, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 8, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 12, ov, shift);
	  i += 16;
	}

      if (i + 7 < n)
	{
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 0, ov, shift);
	  clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 4, ov, shift);
	  i += 8;
	}

      if (i < n)
	clib_index_to_ptr_u32_vec128 (indices, ptrs, i + 0, ov, shift);

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
