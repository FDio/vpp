/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_count_equal_h
#define included_vector_count_equal_h
#include <vppinfra/clib.h>

static_always_inline uword
clib_count_equal_u64 (u64 *data, uword max_count)
{
  uword count;
  u64 first;

  if (max_count <= 1)
    return max_count;
  if (data[0] != data[1])
    return 1;

  count = 0;
  first = data[0];

#ifdef CLIB_HAVE_VEC_SCALABLE
  i32 i, eno;
  i32 len = (i32) max_count;
  u64xn s, splat = u64xn_splat (first);
  boolxn m, neq;
  scalable_vector_foreach2 (i, eno, m, len, 64, ({
			      s = u64xn_load_unaligned (m, data + i);
			      neq = u64xn_unequal (m, s, splat);
			      if (boolxn_anytrue (m, neq))
				{
				  count += u64xn_clz (m, neq);
				  return count;
				}
			      count += u64xn_clz (m, neq);
			    }));
  return count;
#elif defined(CLIB_HAVE_VEC256)
  u64x4 splat = u64x4_splat (first);
  while (count + 3 < max_count)
    {
      u64 bmp;
      bmp = u8x32_msb_mask ((u8x32) (u64x4_load_unaligned (data) == splat));
      if (bmp != 0xffffffff)
	{
	  count += count_trailing_zeros (~bmp) / 8;
	  return count;
	}

      data += 4;
      count += 4;
    }
#else
  count += 2;
  data += 2;
  while (count + 3 < max_count && ((data[0] ^ first) | (data[1] ^ first) |
				   (data[2] ^ first) | (data[3] ^ first)) == 0)
    {
      data += 4;
      count += 4;
    }
#endif
  while (count < max_count && (data[0] == first))
    {
      data += 1;
      count += 1;
    }
  return count;
}

static_always_inline uword
clib_count_equal_u32 (u32 *data, uword max_count)
{
  uword count;
  u32 first;

  if (max_count <= 1)
    return max_count;
  if (data[0] != data[1])
    return 1;

  count = 0;
  first = data[0];

#ifdef CLIB_HAVE_VEC_SCALABLE
  i32 i, eno;
  i32 len = (i32) max_count;
  u32xn s, splat = u32xn_splat (first);
  boolxn m, neq;
  scalable_vector_foreach2 (i, eno, m, len, 32, ({
			      s = u32xn_load_unaligned (m, data + i);
			      neq = u32xn_unequal (m, s, splat);
			      if (boolxn_anytrue (m, neq))
				{
				  count += u32xn_clz (m, neq);
				  return count;
				}
			      count += u32xn_clz (m, neq);
			    }));
  return count;
#elif defined(CLIB_HAVE_VEC512)
  u32x16 splat = u32x16_splat (first);
  while (count + 15 < max_count)
    {
      u32 bmp;
      bmp = u32x16_is_equal_mask (u32x16_load_unaligned (data), splat);
      if (bmp != pow2_mask (16))
	return count + count_trailing_zeros (~bmp);

      data += 16;
      count += 16;
    }
  if (count == max_count)
    return count;
  else
    {
      u32 mask = pow2_mask (max_count - count);
      u32 bmp =
	u32x16_is_equal_mask (u32x16_mask_load_zero (data, mask), splat) &
	mask;
      return count + count_trailing_zeros (~bmp);
    }
#elif defined(CLIB_HAVE_VEC256)
  u32x8 splat = u32x8_splat (first);
  while (count + 7 < max_count)
    {
      u32 bmp;
#ifdef __AVX512F__
      bmp = u32x8_is_equal_mask (u32x8_load_unaligned (data), splat);
      if (bmp != pow2_mask (8))
	return count + count_trailing_zeros (~bmp);
#else
      bmp = u8x32_msb_mask ((u8x32) (u32x8_load_unaligned (data) == splat));
      if (bmp != 0xffffffff)
	return count + count_trailing_zeros (~bmp) / 4;
#endif

      data += 8;
      count += 8;
    }
  if (count == max_count)
    return count;
#if defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
  else
    {
      u32 mask = pow2_mask (max_count - count);
      u32 bmp =
	u32x8_is_equal_mask (u32x8_mask_load_zero (data, mask), splat) & mask;
      return count + count_trailing_zeros (~bmp);
    }
#endif
#elif defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_MSB_MASK)
  u32x4 splat = u32x4_splat (first);
  while (count + 3 < max_count)
    {
      u64 bmp;
      bmp = u8x16_msb_mask ((u8x16) (u32x4_load_unaligned (data) == splat));
      if (bmp != pow2_mask (4 * 4))
	{
	  count += count_trailing_zeros (~bmp) / 4;
	  return count;
	}

      data += 4;
      count += 4;
    }
#else
  count += 2;
  data += 2;
  while (count + 3 < max_count && ((data[0] ^ first) | (data[1] ^ first) |
				   (data[2] ^ first) | (data[3] ^ first)) == 0)
    {
      data += 4;
      count += 4;
    }
#endif
  while (count < max_count && (data[0] == first))
    {
      data += 1;
      count += 1;
    }
  return count;
}

static_always_inline uword
clib_count_equal_u16 (u16 *data, uword max_count)
{
  uword count;
  u16 first;

  if (max_count <= 1)
    return max_count;
  if (data[0] != data[1])
    return 1;

  count = 0;
  first = data[0];

#ifdef CLIB_HAVE_VEC_SCALABLE
  i32 i, eno;
  i32 len = (i32) max_count;
  u16xn s, splat = u16xn_splat (first);
  boolxn m, neq;
  scalable_vector_foreach2 (i, eno, m, len, 16, ({
			      s = u16xn_load_unaligned (m, data + i);
			      neq = u16xn_unequal (m, s, splat);
			      if (boolxn_anytrue (m, neq))
				{
				  count += u16xn_clz (m, neq);
				  return count;
				}
			      count += u16xn_clz (m, neq);
			    }));
  return count;
#elif defined(CLIB_HAVE_VEC256)
  u16x16 splat = u16x16_splat (first);
  while (count + 15 < max_count)
    {
      u64 bmp;
      bmp = u8x32_msb_mask ((u8x32) (u16x16_load_unaligned (data) == splat));
      if (bmp != 0xffffffff)
	{
	  count += count_trailing_zeros (~bmp) / 2;
	  return count;
	}

      data += 16;
      count += 16;
    }
#elif defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_MSB_MASK)
  u16x8 splat = u16x8_splat (first);
  while (count + 7 < max_count)
    {
      u64 bmp;
      bmp = u8x16_msb_mask ((u8x16) (u16x8_load_unaligned (data) == splat));
      if (bmp != 0xffff)
	{
	  count += count_trailing_zeros (~bmp) / 2;
	  return count;
	}

      data += 8;
      count += 8;
    }
#else
  count += 2;
  data += 2;
  while (count + 3 < max_count && ((data[0] ^ first) | (data[1] ^ first) |
				   (data[2] ^ first) | (data[3] ^ first)) == 0)
    {
      data += 4;
      count += 4;
    }
#endif
  while (count < max_count && (data[0] == first))
    {
      data += 1;
      count += 1;
    }
  return count;
}

static_always_inline uword
clib_count_equal_u8 (u8 *data, uword max_count)
{
  uword count;
  u8 first;

  if (max_count <= 1)
    return max_count;
  if (data[0] != data[1])
    return 1;

  count = 0;
  first = data[0];

#ifdef CLIB_HAVE_VEC_SCALABLE
  i32 i, eno;
  i32 len = (i32) max_count;
  u8xn s, splat = u8xn_splat (first);
  boolxn m, neq;
  scalable_vector_foreach2 (i, eno, m, len, 8, ({
			      s = u8xn_load_unaligned (m, data + i);
			      neq = u8xn_unequal (m, s, splat);
			      if (boolxn_anytrue (m, neq))
				{
				  count += u8xn_clz (m, neq);
				  return count;
				}
			      count += u8xn_clz (m, neq);
			    }));
  return count;
#elif defined(CLIB_HAVE_VEC512)
  u8x64 splat = u8x64_splat (first);
  while (count + 63 < max_count)
    {
      u64 bmp;
      bmp = u8x64_is_equal_mask (u8x64_load_unaligned (data), splat);
      if (bmp != -1)
	return count + count_trailing_zeros (~bmp);

      data += 64;
      count += 64;
    }
  if (count == max_count)
    return count;
#if defined(CLIB_HAVE_VEC512_MASK_LOAD_STORE)
  else
    {
      u64 mask = pow2_mask (max_count - count);
      u64 bmp =
	u8x64_is_equal_mask (u8x64_mask_load_zero (data, mask), splat) & mask;
      return count + count_trailing_zeros (~bmp);
    }
#endif
#elif defined(CLIB_HAVE_VEC256)
  u8x32 splat = u8x32_splat (first);
  while (count + 31 < max_count)
    {
      u64 bmp;
      bmp = u8x32_msb_mask ((u8x32) (u8x32_load_unaligned (data) == splat));
      if (bmp != 0xffffffff)
	return count + count_trailing_zeros (~bmp);

      data += 32;
      count += 32;
    }
  if (count == max_count)
    return count;
#if defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
  else
    {
      u32 mask = pow2_mask (max_count - count);
      u64 bmp =
	u8x32_msb_mask (u8x32_mask_load_zero (data, mask) == splat) & mask;
      return count + count_trailing_zeros (~bmp);
    }
#endif
#elif defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_MSB_MASK)
  u8x16 splat = u8x16_splat (first);
  while (count + 15 < max_count)
    {
      u64 bmp;
      bmp = u8x16_msb_mask ((u8x16) (u8x16_load_unaligned (data) == splat));
      if (bmp != 0xffff)
	return count + count_trailing_zeros (~bmp);

      data += 16;
      count += 16;
    }
#else
  count += 2;
  data += 2;
  while (count + 3 < max_count && ((data[0] ^ first) | (data[1] ^ first) |
				   (data[2] ^ first) | (data[3] ^ first)) == 0)
    {
      data += 4;
      count += 4;
    }
#endif
  while (count < max_count && (data[0] == first))
    {
      data += 1;
      count += 1;
    }
  return count;
}

#endif
