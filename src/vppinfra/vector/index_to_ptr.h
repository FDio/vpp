/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_index_to_ptr_h
#define included_vector_index_to_ptr_h
#include <vppinfra/clib.h>

#ifdef CLIB_HAVE_VEC128
static_always_inline void
clib_index_to_ptr_u32x4 (u32 *indices, void **ptrs, i32 i, u64x2 ov, u8 shift)
{
  u32x4 iv4 = u32x4_load_unaligned (indices + i);
  u64x2 pv2;
  pv2 = u64x2_from_u32x4 (iv4);
  u64x2_store_unaligned ((pv2 << shift) + ov, ptrs + i);
#ifdef __aarch64__
  pv2 = u64x2_from_u32x4_high (iv4);
#else
  pv2 = u64x2_from_u32x4 ((u32x4) u8x16_word_shift_right (iv4, 8));
#endif
  u64x2_store_unaligned ((pv2 << shift) + ov, ptrs + i + 2);
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
#if defined CLIB_HAVE_VEC512
  if (n_elts >= 8)
    {
      u64x8 off = u64x8_splat ((u64) base);
      u64x8 b0, b1, b2, b3, b4, b5, b6, b7;

      while (n_elts >= 64)
	{
	  b0 = u64x8_from_u32x8 (u32x8_load_unaligned (indices));
	  b1 = u64x8_from_u32x8 (u32x8_load_unaligned (indices + 8));
	  b2 = u64x8_from_u32x8 (u32x8_load_unaligned (indices + 16));
	  b3 = u64x8_from_u32x8 (u32x8_load_unaligned (indices + 24));
	  b4 = u64x8_from_u32x8 (u32x8_load_unaligned (indices + 32));
	  b5 = u64x8_from_u32x8 (u32x8_load_unaligned (indices + 40));
	  b6 = u64x8_from_u32x8 (u32x8_load_unaligned (indices + 48));
	  b7 = u64x8_from_u32x8 (u32x8_load_unaligned (indices + 56));
	  u64x8_store_unaligned ((b0 << shift) + off, ptrs);
	  u64x8_store_unaligned ((b1 << shift) + off, ptrs + 8);
	  u64x8_store_unaligned ((b2 << shift) + off, ptrs + 16);
	  u64x8_store_unaligned ((b3 << shift) + off, ptrs + 24);
	  u64x8_store_unaligned ((b4 << shift) + off, ptrs + 32);
	  u64x8_store_unaligned ((b5 << shift) + off, ptrs + 40);
	  u64x8_store_unaligned ((b6 << shift) + off, ptrs + 48);
	  u64x8_store_unaligned ((b7 << shift) + off, ptrs + 56);
	  ptrs += 64;
	  indices += 64;
	  n_elts -= 64;
	}

      if (n_elts == 0)
	return;

      if (n_elts >= 32)
	{
	  b0 = u64x8_from_u32x8 (u32x8_load_unaligned (indices));
	  b1 = u64x8_from_u32x8 (u32x8_load_unaligned (indices + 8));
	  b2 = u64x8_from_u32x8 (u32x8_load_unaligned (indices + 16));
	  b3 = u64x8_from_u32x8 (u32x8_load_unaligned (indices + 24));
	  u64x8_store_unaligned ((b0 << shift) + off, ptrs);
	  u64x8_store_unaligned ((b1 << shift) + off, ptrs + 8);
	  u64x8_store_unaligned ((b2 << shift) + off, ptrs + 16);
	  u64x8_store_unaligned ((b3 << shift) + off, ptrs + 24);
	  ptrs += 32;
	  indices += 32;
	  n_elts -= 32;
	}
      if (n_elts >= 16)
	{
	  b0 = u64x8_from_u32x8 (u32x8_load_unaligned (indices));
	  b1 = u64x8_from_u32x8 (u32x8_load_unaligned (indices + 8));
	  u64x8_store_unaligned ((b0 << shift) + off, ptrs);
	  u64x8_store_unaligned ((b1 << shift) + off, ptrs + 8);
	  ptrs += 16;
	  indices += 16;
	  n_elts -= 16;
	}
      if (n_elts >= 8)
	{
	  b0 = u64x8_from_u32x8 (u32x8_load_unaligned (indices));
	  u64x8_store_unaligned ((b0 << shift) + off, ptrs);
	  ptrs += 8;
	  indices += 8;
	  n_elts -= 8;
	}

      if (n_elts == 0)
	return;

      b0 = u64x8_from_u32x8 (u32x8_load_unaligned (indices + n_elts - 8));
      u64x8_store_unaligned ((b0 << shift) + off, ptrs + n_elts - 8);
    }
  else
    {
      u32 mask = pow2_mask (n_elts);
      u64x8 r = u64x8_from_u32x8 (u32x8_mask_load_zero (indices, mask));
      u64x8_mask_store ((r << shift) + u64x8_splat ((u64) base), ptrs, mask);
      return;
    }
#elif defined CLIB_HAVE_VEC256
  if (n_elts >= 4)
    {
      u64x4 off = u64x4_splat ((u64) base);
      u64x4 b0, b1, b2, b3, b4, b5, b6, b7;

      while (n_elts >= 32)
	{
	  b0 = u64x4_from_u32x4 (u32x4_load_unaligned (indices));
	  b1 = u64x4_from_u32x4 (u32x4_load_unaligned (indices + 4));
	  b2 = u64x4_from_u32x4 (u32x4_load_unaligned (indices + 8));
	  b3 = u64x4_from_u32x4 (u32x4_load_unaligned (indices + 12));
	  b4 = u64x4_from_u32x4 (u32x4_load_unaligned (indices + 16));
	  b5 = u64x4_from_u32x4 (u32x4_load_unaligned (indices + 20));
	  b6 = u64x4_from_u32x4 (u32x4_load_unaligned (indices + 24));
	  b7 = u64x4_from_u32x4 (u32x4_load_unaligned (indices + 28));
	  u64x4_store_unaligned ((b0 << shift) + off, ptrs);
	  u64x4_store_unaligned ((b1 << shift) + off, ptrs + 4);
	  u64x4_store_unaligned ((b2 << shift) + off, ptrs + 8);
	  u64x4_store_unaligned ((b3 << shift) + off, ptrs + 12);
	  u64x4_store_unaligned ((b4 << shift) + off, ptrs + 16);
	  u64x4_store_unaligned ((b5 << shift) + off, ptrs + 20);
	  u64x4_store_unaligned ((b6 << shift) + off, ptrs + 24);
	  u64x4_store_unaligned ((b7 << shift) + off, ptrs + 28);
	  ptrs += 32;
	  indices += 32;
	  n_elts -= 32;
	}

      if (n_elts == 0)
	return;

      if (n_elts >= 16)
	{
	  b0 = u64x4_from_u32x4 (u32x4_load_unaligned (indices));
	  b1 = u64x4_from_u32x4 (u32x4_load_unaligned (indices + 4));
	  b2 = u64x4_from_u32x4 (u32x4_load_unaligned (indices + 8));
	  b3 = u64x4_from_u32x4 (u32x4_load_unaligned (indices + 12));
	  u64x4_store_unaligned ((b0 << shift) + off, ptrs);
	  u64x4_store_unaligned ((b1 << shift) + off, ptrs + 4);
	  u64x4_store_unaligned ((b2 << shift) + off, ptrs + 8);
	  u64x4_store_unaligned ((b3 << shift) + off, ptrs + 12);
	  ptrs += 16;
	  indices += 16;
	  n_elts -= 16;
	}
      if (n_elts >= 8)
	{
	  b0 = u64x4_from_u32x4 (u32x4_load_unaligned (indices));
	  b1 = u64x4_from_u32x4 (u32x4_load_unaligned (indices + 4));
	  u64x4_store_unaligned ((b0 << shift) + off, ptrs);
	  u64x4_store_unaligned ((b1 << shift) + off, ptrs + 4);
	  ptrs += 8;
	  indices += 8;
	  n_elts -= 8;
	}
      if (n_elts > 4)
	{
	  b0 = u64x4_from_u32x4 (u32x4_load_unaligned (indices));
	  u64x4_store_unaligned ((b0 << shift) + off, ptrs);
	  ptrs += 4;
	  indices += 4;
	  n_elts -= 4;
	}

      b0 = u64x4_from_u32x4 (u32x4_load_unaligned (indices + n_elts - 4));
      u64x4_store_unaligned ((b0 << shift) + off, ptrs + n_elts - 4);
      return;
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
#elif defined(CLIB_HAVE_VEC128)
  if (n_elts >= 4)
    {
      u64x2 ov = u64x2_splat ((u64) base);
      u32 *i = (u32 *) indices;
      void **p = (void **) ptrs;
      u32 n = n_elts;

      while (n >= 32)
	{
	  clib_index_to_ptr_u32x4 (indices, ptrs, 0, ov, shift);
	  clib_index_to_ptr_u32x4 (indices, ptrs, 4, ov, shift);
	  clib_index_to_ptr_u32x4 (indices, ptrs, 8, ov, shift);
	  clib_index_to_ptr_u32x4 (indices, ptrs, 12, ov, shift);
	  clib_index_to_ptr_u32x4 (indices, ptrs, 16, ov, shift);
	  clib_index_to_ptr_u32x4 (indices, ptrs, 20, ov, shift);
	  clib_index_to_ptr_u32x4 (indices, ptrs, 24, ov, shift);
	  clib_index_to_ptr_u32x4 (indices, ptrs, 28, ov, shift);
	  indices += 32;
	  ptrs += 32;
	  n -= 32;
	}

      if (n == 0)
	return;

      if (n >= 16)
	{
	  clib_index_to_ptr_u32x4 (indices, ptrs, 0, ov, shift);
	  clib_index_to_ptr_u32x4 (indices, ptrs, 4, ov, shift);
	  clib_index_to_ptr_u32x4 (indices, ptrs, 8, ov, shift);
	  clib_index_to_ptr_u32x4 (indices, ptrs, 12, ov, shift);
	  indices += 16;
	  ptrs += 16;
	  n -= 16;
	}

      if (n >= 8)
	{
	  clib_index_to_ptr_u32x4 (indices, ptrs, 0, ov, shift);
	  clib_index_to_ptr_u32x4 (indices, ptrs, 4, ov, shift);
	  indices += 8;
	  ptrs += 8;
	  n -= 8;
	}

      if (n > 4)
	clib_index_to_ptr_u32x4 (indices, ptrs, 0, ov, shift);

      clib_index_to_ptr_u32x4 (i, p, n_elts - 4, ov, shift);
      return;
    }
#endif
  while (n_elts)
    {
      ptrs[0] = base + ((u64) indices[0] << shift);
      ptrs += 1;
      indices += 1;
      n_elts -= 1;
    }
}

#endif
