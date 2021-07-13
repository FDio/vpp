/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_compress_h
#define included_vector_compress_h
#include <vppinfra/clib.h>
#include <vppinfra/memcpy.h>

static_always_inline u32 *
clib_compress_u32_x64 (u32 *dst, u32 *src, u64 mask)
{
#if defined(CLIB_HAVE_VEC512_COMPRESS)
  u32x16u *sv = (u32x16u *) src;
  for (int i = 0; i < 4; i++)
    {
      int cnt = _popcnt32 ((u16) mask);
      u32x16_compress_store (sv[i], mask, dst);
      dst += cnt;
      mask >>= 16;
    }

#elif defined(CLIB_HAVE_VEC256_COMPRESS)
  u32x8u *sv = (u32x8u *) src;
  for (int i = 0; i < 8; i++)
    {
      int cnt = _popcnt32 ((u8) mask);
      u32x8_compress_store (sv[i], mask, dst);
      dst += cnt;
      mask >>= 8;
    }
#else
  while (mask)
    {
      u16 bit = count_trailing_zeros (mask);
      mask = clear_lowest_set_bit (mask);
      dst++[0] = src[bit];
    }
#endif
  return dst;
}

/** \brief Compress array of 32-bit elemments into destination array based on
 * mask

    @param dst destination array of u32 elements
    @param src source array of u32 elements
    @param mask array of u64 values representing compress mask
    @param n_elts number of elements in the source array
    @return number of elements stored in destionation array
*/

static_always_inline u32
clib_compress_u32 (u32 *dst, u32 *src, u64 *mask, u32 n_elts)
{
  u32 *dst0 = dst;
  while (n_elts >= 64)
    {
      if (mask[0] == ~0ULL)
	{
	  clib_memcpy_u32 (dst, src, 64);
	  dst += 64;
	}
      else
	dst = clib_compress_u32_x64 (dst, src, mask[0]);

      mask++;
      src += 64;
      n_elts -= 64;
    }

  if (PREDICT_TRUE (n_elts == 0))
    return dst - dst0;

  return clib_compress_u32_x64 (dst, src, mask[0] & pow2_mask (n_elts)) - dst0;
}

#endif
