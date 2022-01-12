/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_compress_h
#define included_vector_compress_h
#include <vppinfra/clib.h>
#include <vppinfra/memcpy.h>

static_always_inline u64 *
clib_compress_u64_x64 (u64 *dst, u64 *src, u64 mask)
{
#if defined(CLIB_HAVE_VEC512_COMPRESS)
  u64x8u *sv = (u64x8u *) src;
  for (int i = 0; i < 8; i++)
    {
      u64x8_compress_store (sv[i], mask, dst);
      dst += _popcnt32 ((u8) mask);
      mask >>= 8;
    }
#elif defined(CLIB_HAVE_VEC256_COMPRESS)
  u64x4u *sv = (u64x4u *) src;
  for (int i = 0; i < 16; i++)
    {
      u64x4_compress_store (sv[i], mask, dst);
      dst += _popcnt32 (((u8) mask) & 0x0f);
      mask >>= 4;
    }
#else
  u32 i;
  foreach_set_bit_index (i, mask)
    dst++[0] = src[i];
#endif
  return dst;
}

/** \brief Compress array of 64-bit elemments into destination array based on
 * mask

    @param dst destination array of u64 elements
    @param src source array of u64 elements
    @param mask array of u64 values representing compress mask
    @param n_elts number of elements in the source array
    @return number of elements stored in destionation array
*/

static_always_inline u32
clib_compress_u64 (u64 *dst, u64 *src, u64 *mask, u32 n_elts)
{
  u64 *dst0 = dst;
  while (n_elts >= 64)
    {
      if (mask[0] == ~0ULL)
	{
	  clib_memcpy_fast (dst, src, 64 * sizeof (u64));
	  dst += 64;
	}
      else
	dst = clib_compress_u64_x64 (dst, src, mask[0]);

      mask++;
      src += 64;
      n_elts -= 64;
    }

  if (PREDICT_TRUE (n_elts == 0))
    return dst - dst0;

  return clib_compress_u64_x64 (dst, src, mask[0] & pow2_mask (n_elts)) - dst0;
}

static_always_inline u32 *
clib_compress_u32_x64 (u32 *dst, u32 *src, u64 mask)
{
#if defined(CLIB_HAVE_VEC512_COMPRESS)
  u32x16u *sv = (u32x16u *) src;
  for (int i = 0; i < 4; i++)
    {
      u32x16_compress_store (sv[i], mask, dst);
      dst += _popcnt32 ((u16) mask);
      mask >>= 16;
    }

#elif defined(CLIB_HAVE_VEC256_COMPRESS)
  u32x8u *sv = (u32x8u *) src;
  for (int i = 0; i < 8; i++)
    {
      u32x8_compress_store (sv[i], mask, dst);
      dst += _popcnt32 ((u8) mask);
      mask >>= 8;
    }
#else
  u32 i;
  foreach_set_bit_index (i, mask)
    dst++[0] = src[i];
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

static_always_inline u16 *
clib_compress_u16_x64 (u16 *dst, u16 *src, u64 mask)
{
#if defined(CLIB_HAVE_VEC512_COMPRESS_U8_U16)
  u16x32u *sv = (u16x32u *) src;
  for (int i = 0; i < 2; i++)
    {
      u16x32_compress_store (sv[i], mask, dst);
      dst += _popcnt32 ((u32) mask);
      mask >>= 32;
    }
#else
  u32 i;
  foreach_set_bit_index (i, mask)
    dst++[0] = src[i];
#endif
  return dst;
}

/** \brief Compress array of 16-bit elemments into destination array based on
 * mask

    @param dst destination array of u16 elements
    @param src source array of u16 elements
    @param mask array of u64 values representing compress mask
    @param n_elts number of elements in the source array
    @return number of elements stored in destionation array
*/

static_always_inline u32
clib_compress_u16 (u16 *dst, u16 *src, u64 *mask, u32 n_elts)
{
  u16 *dst0 = dst;
  while (n_elts >= 64)
    {
      if (mask[0] == ~0ULL)
	{
	  clib_memcpy_fast (dst, src, 64 * sizeof (u16));
	  dst += 64;
	}
      else
	dst = clib_compress_u16_x64 (dst, src, mask[0]);

      mask++;
      src += 64;
      n_elts -= 64;
    }

  if (PREDICT_TRUE (n_elts == 0))
    return dst - dst0;

  return clib_compress_u16_x64 (dst, src, mask[0] & pow2_mask (n_elts)) - dst0;
}

static_always_inline u8 *
clib_compress_u8_x64 (u8 *dst, u8 *src, u64 mask)
{
#if defined(CLIB_HAVE_VEC512_COMPRESS_U8_U16)
  u8x64u *sv = (u8x64u *) src;
  u8x64_compress_store (sv[0], mask, dst);
  dst += _popcnt64 (mask);
#else
  u32 i;
  foreach_set_bit_index (i, mask)
    dst++[0] = src[i];
#endif
  return dst;
}

/** \brief Compress array of 8-bit elemments into destination array based on
 * mask

    @param dst destination array of u8 elements
    @param src source array of u8 elements
    @param mask array of u64 values representing compress mask
    @param n_elts number of elements in the source array
    @return number of elements stored in destionation array
*/

static_always_inline u32
clib_compress_u8 (u8 *dst, u8 *src, u64 *mask, u32 n_elts)
{
  u8 *dst0 = dst;
  while (n_elts >= 64)
    {
      if (mask[0] == ~0ULL)
	{
	  clib_memcpy_fast (dst, src, 64);
	  dst += 64;
	}
      else
	dst = clib_compress_u8_x64 (dst, src, mask[0]);

      mask++;
      src += 64;
      n_elts -= 64;
    }

  if (PREDICT_TRUE (n_elts == 0))
    return dst - dst0;

  return clib_compress_u8_x64 (dst, src, mask[0] & pow2_mask (n_elts)) - dst0;
}

#endif
