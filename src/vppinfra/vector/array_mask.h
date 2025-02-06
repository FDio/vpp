/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_vector_array_mask_h
#define included_vector_array_mask_h
#include <vppinfra/clib.h>

static_always_inline u64
clib_array_mask_flag_test_u32_x64_n (u64 bitmap, u32 *a, u32 v, u32 n_elts)
{
  u64 mask = 0;
  CLIB_UNUSED (u32 i) = 0;
#if defined(__AVX512F__)
  u32x16 v16 = u32x16_splat (v);
  u32x16u *av = (u32x16u *) a;
  mask = ((u64) _mm512_mask_test_epi32_mask (bitmap, av[0], v16) |
	  (u64) _mm512_mask_test_epi32_mask (bitmap >> 16, av[1], v16) << 16 |
	  (u64) _mm512_mask_test_epi32_mask (bitmap >> 32, av[2], v16) << 32 |
	  (u64) _mm512_mask_test_epi32_mask (bitmap >> 48, av[3], v16) << 48);
  return mask;
#elif defined(__AVX2__)
  u32x8 v8 = u32x8_splat (v);
  u32x8 dst0, av;
  for (; i + 8 <= n_elts; i += 8)
    {
      av = _mm256_loadu_si256 ((__m256i *) &a[i]);
      dst0 = _mm256_cmpeq_epi32 (_mm256_and_si256 (av, v8),
				 _mm256_setzero_si256 ());
      mask |=
	(u64) (0x000000FF & ~_mm256_movemask_ps (_mm256_castsi256_ps (dst0)))
	<< i;
    }
#endif
  for (; i < n_elts; i++)
    {
      if (a[i] & v)
	mask |= (1ULL << i);
    }
  mask &= bitmap;
  return mask;
}

static_always_inline void
clib_array_mask_flag_test_u32 (u64 *bitmap, u32 *vec, u32 value,
			       u64 *ret_bitmap, u32 n_elts)
{
  while (n_elts >= uword_bits)
    {
      ret_bitmap++[0] =
	clib_array_mask_flag_test_u32_x64_n (bitmap++[0], vec, value, n_elts);
      n_elts -= 64;
      vec += 64;
    }
  if (PREDICT_TRUE (n_elts == 0))
    return;
  ret_bitmap[0] =
    clib_array_mask_flag_test_u32_x64_n (bitmap[0], vec, value, n_elts);
}

static_always_inline u64
clib_array_test_flag_u32_x64 (u32 *a, u32 v)
{
  u64 mask = 0;
#if defined(__AVX512F__)
  u32x16 v16 = u32x16_splat (v);
  u32x16u *av = (u32x16u *) a;
  mask = ((u64) _mm512_test_epi32_mask (av[0], v16) |
	  (u64) _mm512_test_epi32_mask (av[1], v16) << 16 |
	  (u64) _mm512_test_epi32_mask (av[2], v16) << 32 |
	  (u64) _mm512_test_epi32_mask (av[3], v16) << 48);
#elif defined(__AVX2__)
  u32x8 v8 = u32x8_splat (v);
  u32x8 dst0, av;
  for (u32 i = 0; i + 8 <= 64; i += 8)
    {
      av = _mm256_loadu_si256 ((__m256i *) &a[i]);
      dst0 = _mm256_cmpeq_epi32 (_mm256_and_si256 (av, v8),
				 _mm256_setzero_si256 ());
      mask |=
	(u64) (0x000000FF & ~_mm256_movemask_ps (_mm256_castsi256_ps (dst0)))
	<< i;
    }
#else
  for (u32 i = 0; i < 64; i++)
    {
      if (a[i] & v)
	mask |= (1ULL << i);
    }
#endif
  return mask;
}

static_always_inline u64
clib_array_test_flag_u32_x64_n (u32 *a, u32 v, u32 n_elts)
{
  u64 mask = 0;
  CLIB_UNUSED (u32 i) = 0;
  CLIB_UNUSED (u64 data_mask) = pow2_mask (n_elts);
#if defined(__AVX512F__)
  u32x16 v16 = u32x16_splat (v);
  u32x16u *av = (u32x16u *) a;
  mask = ((u64) _mm512_test_epi32_mask (
	    u32x16_mask_load_zero (&av[0], data_mask), v16) |
	  (u64) _mm512_test_epi32_mask (
	    u32x16_mask_load_zero (&av[1], data_mask >> 16), v16)
	    << 16 |
	  (u64) _mm512_test_epi32_mask (
	    u32x16_mask_load_zero (&av[2], data_mask >> 32), v16)
	    << 32 |
	  (u64) _mm512_test_epi32_mask (
	    u32x16_mask_load_zero (&av[3], data_mask >> 48), v16)
	    << 48);
  n_elts = 0;
#elif defined(__AVX2__)
  u32x8 v8 = u32x8_splat (v);
  u32x8 dst0, av;
  for (; i + 8 <= n_elts; i += 8)
    {
      av = _mm256_loadu_si256 ((__m256i *) &a[i]);
      dst0 =
	_mm256_cmpeq_epi32 (_mm256_and_si256 (av, v8),
			    _mm256_setzero_si256 ()); // Test flag presence
      mask |=
	(u64) (0x000000FF & ~_mm256_movemask_ps (_mm256_castsi256_ps (dst0)))
	<< i;
    }

#endif
  for (; i < n_elts; i++)
    {
      if (a[i] & v)
	mask |= (1ULL << i);
    }
  return mask;
}

static_always_inline void
clib_array_test_flag_u32 (u32 *vec, u32 value, u64 *bitmap, u32 n_elts)
{
  while (n_elts >= uword_bits)
    {
      bitmap++[0] = clib_array_test_flag_u32_x64 (vec, value);
      n_elts -= 64;
      vec += 64;
    }
  if (PREDICT_TRUE (n_elts == 0))
    return;
  bitmap[0] =
    clib_array_test_flag_u32_x64_n (vec, value, n_elts) & pow2_mask (n_elts);
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
