/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_clib_memcpy_x86_64_h
#define included_clib_memcpy_x86_64_h
#ifdef __x86_64__

#include <vppinfra/clib.h>

static_always_inline void
clib_memcpy_const_le32 (u8 *dst, u8 *src, size_t n)
{
  switch (n)
    {
    case 1:
      *(u8 *) dst = *(u8 *) src;
      break;
    case 2:
      *(u16u *) dst = *(u16u *) src;
      break;
    case 3:
      *(u16u *) dst = *(u16u *) src;
      *((u8 *) dst + 2) = *((u8 *) src + 2);
      break;
    case 4:
      *(u32u *) dst = *(u32u *) src;
      break;
    case 5:
      *(u32u *) dst = *(u32u *) src;
      *((u8 *) dst + 4) = *((u8 *) src + 4);
      break;
    case 6:
      *(u32u *) dst = *(u32u *) src;
      *((u16u *) dst + 2) = *((u16u *) src + 2);
      break;
    case 7:
      *(u32u *) dst = *(u32u *) src;
      *((u32u *) (dst + 3)) = *((u32u *) (src + 3));
      break;
    case 8:
      *(u64u *) dst = *(u64u *) src;
      break;
    case 9:
      *(u64u *) dst = *(u64u *) src;
      *(dst + 8) = *(src + 8);
      break;
    case 10:
      *(u64u *) dst = *(u64u *) src;
      *((u16u *) (dst + 8)) = *((u16u *) (src + 8));
      break;
    case 11:
    case 12:
      *(u64u *) dst = *(u64u *) src;
      *((u32u *) (dst + n - 4)) = *((u32u *) (src + n - 4));
      break;
    case 13:
    case 14:
    case 15:
      *(u64u *) dst = *(u64u *) src;
      *((u64u *) (dst + n - 8)) = *((u64u *) (src + n - 8));
      break;
    case 16:
      *(u8x16u *) dst = *(u8x16u *) src;
      break;
    case 17:
      *(u8x16u *) dst = *(u8x16u *) src;
      *(dst + 16) = *(src + 16);
      break;
    case 18:
      *(u8x16u *) dst = *(u8x16u *) src;
      *((u16u *) (dst + 16)) = *((u16u *) (src + 16));
      break;
    case 20:
      *(u8x16u *) dst = *(u8x16u *) src;
      *((u32u *) (dst + 16)) = *((u32u *) (src + 16));
      break;
    case 24:
      *(u8x16u *) dst = *(u8x16u *) src;
      *((u64u *) (dst + 16)) = *((u64u *) (src + 16));
      break;
    default:
      *(u8x16u *) dst = *(u8x16u *) src;
      *((u8x16u *) (dst + n - 16)) = *((u8x16u *) (src + n - 16));
      break;
    }
}

static_always_inline void
clib_memcpy_const_le64 (u8 *dst, u8 *src, size_t n)
{
  if (n < 32)
    {
      clib_memcpy_const_le32 (dst, src, n);
      return;
    }

#if defined(CLIB_HAVE_VEC256)
  switch (n)
    {
    case 32:
      *(u8x32u *) dst = *(u8x32u *) src;
      break;
    case 33:
      *(u8x32u *) dst = *(u8x32u *) src;
      *(dst + 32) = *(src + 32);
      break;
    case 34:
      *(u8x32u *) dst = *(u8x32u *) src;
      *((u16u *) (dst + 32)) = *((u16u *) (src + 32));
      break;
    case 36:
      *(u8x32u *) dst = *(u8x32u *) src;
      *((u32u *) (dst + 32)) = *((u32u *) (src + 32));
      break;
    case 40:
      *(u8x32u *) dst = *(u8x32u *) src;
      *((u64u *) (dst + 32)) = *((u64u *) (src + 32));
      break;
    case 48:
      *(u8x32u *) dst = *(u8x32u *) src;
      *((u8x16u *) (dst + 32)) = *((u8x16u *) (src + 32));
      break;
    default:
      *(u8x32u *) dst = *(u8x32u *) src;
      *((u8x32u *) (dst + n - 32)) = *((u8x32u *) (src + n - 32));
      break;
    }
#else
  while (n > 31)
    {
      *(u8x16u *) dst = *(u8x16u *) src;
      dst += 16;
      src += 16;
      n -= 16;
    }
  clib_memcpy_const_le32 (dst, src, n);
#endif
}

static_always_inline void
clib_memcpy_const_le128 (u8 *dst, u8 *src, size_t n)
{
  if (n < 64)
    {
      clib_memcpy_const_le64 (dst, src, n);
      return;
    }

#if defined(CLIB_HAVE_VEC512)
  switch (n)
    {
    case 64:
      *(u8x64u *) dst = *(u8x64u *) src;
      break;
    case 65:
      *(u8x64u *) dst = *(u8x64u *) src;
      *(dst + 64) = *(src + 64);
      break;
    case 66:
      *(u8x64u *) dst = *(u8x64u *) src;
      *((u16u *) (dst + 64)) = *((u16u *) (src + 64));
      break;
    case 68:
      *(u8x64u *) dst = *(u8x64u *) src;
      *((u32u *) (dst + 64)) = *((u32u *) (src + 64));
      break;
    case 72:
      *(u8x64u *) dst = *(u8x64u *) src;
      *((u64u *) (dst + 64)) = *((u64u *) (src + 64));
      break;
    case 80:
      *(u8x64u *) dst = *(u8x64u *) src;
      *((u8x16u *) (dst + 64)) = *((u8x16u *) (src + 64));
      break;
    case 96:
      *(u8x64u *) dst = *(u8x64u *) src;
      *((u8x32u *) (dst + 64)) = *((u8x32u *) (src + 64));
      break;
    default:
      *(u8x64u *) dst = *(u8x64u *) src;
      *((u8x64u *) (dst + n - 64)) = *((u8x64u *) (src + n - 64));
      break;
    }
#elif defined(CLIB_HAVE_VEC256)
  while (n > 63)
    {
      *(u8x32u *) dst = *(u8x32u *) src;
      dst += 32;
      src += 32;
      n -= 32;
    }
  clib_memcpy_const_le64 (dst, src, n);
#else
  while (n > 31)
    {
      *(u8x16u *) dst = *(u8x16u *) src;
      dst += 16;
      src += 16;
      n -= 16;
    }
  clib_memcpy_const_le32 (dst, src, n);
#endif
}

static_always_inline void *
clib_memcpy_x86_64 (void *restrict dst, const void *restrict src, size_t n)
{

#if defined(CLIB_HAVE_VEC512)
  u8x64u *dv = (u8x64u *) dst, *sv = (u8x64u *) src;
  const u8 log2_vec_bytes = 6;
#elif defined(CLIB_HAVE_VEC256)
  u8x32u *dv = (u8x32u *) dst, *sv = (u8x32u *) src;
  const u8 log2_vec_bytes = 5;
#else
  u8x16u *dv = (u8x16u *) dst, *sv = (u8x16u *) src;
  const u8 log2_vec_bytes = 4;
#endif
  u8 vec_bytes = 1 << log2_vec_bytes;
  u8 mask = pow2_mask (vec_bytes);

  /* emit minimal number of instructions for cases where n is compile-time
   * constant */
  if (COMPILE_TIME_CONST (n) && n <= 128)
    {
      clib_memcpy_const_le128 ((u8 *) dst, (u8 *) src, n);
      return dst;
    }

  /* copy less than vector register size */
  if (n < vec_bytes)
    {
      u8 *d = (u8 *) dst;
      u8 *s = (u8 *) src;
#if defined(CLIB_HAVE_VEC512_MASK_LOAD_STORE)
      u64 mask = pow2_mask (n);
      u8x64_mask_store (u8x64_mask_load_zero ((void *) s, mask), d, mask);
#elif defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
      u32 mask = pow2_mask (n);
      u8x32_mask_store (u8x32_mask_load_zero ((void *) s, mask), d, mask);
#else
      if (n >= 8)
	{
#ifdef CLIB_HAVE_VEC256 /* AVX2 only - no mask load/store */
	  if (n >= 16)
	    {
	      *(u8x16u *) d = *(u8x16u *) s;
	      *(u8x16u *) (d + n - 16) = *(u8x16u *) (s + n - 16);
	      return dst;
	    }
#endif
	  *(u64u *) d = *(u64u *) s;
	  *(u64u *) (d + n - 8) = *(u64u *) (s + n - 8);
	  return dst;
	}

      if (n >= 2)
	{
	  if (n >= 4)
	    {
	      *(u32u *) d = *(u32u *) s;
	      *(u32u *) (d + n - 4) = *(u32u *) (s + n - 4);
	      return dst;
	    }

	  *(u16u *) d = *(u16u *) s;
	  *(u16u *) (d + n - 2) = *(u16u *) (s + n - 2);
	  return dst;
	}

      *d = *s;
#endif
      return dst;
    }

  if (n < vec_bytes * 8)
    goto last;

  u8 off = (uword) dst & mask;

  if (off)
    {
      /* dst pointer is not aligned */
      off = vec_bytes - off;
      dv[0] = sv[0];
      dv = (__typeof__ (dv)) ((u8 *) dv + off);
      sv = (__typeof__ (sv)) ((u8 *) sv + off);
      n += off;

      if (n < vec_bytes * 8)
	goto last;
    }

more:
  dv[0] = sv[0];
  dv[1] = sv[1];
  dv[2] = sv[2];
  dv[3] = sv[3];
  dv[4] = sv[4];
  dv[5] = sv[5];
  dv[6] = sv[6];
  dv[7] = sv[7];
  dv += 8;
  sv += 8;
  n -= vec_bytes * 8;
  if (n > vec_bytes * 8)
    goto more;

last:
  /* copy up to eight load/stores */
  switch (n >> log2_vec_bytes)
    {
    case 7:
      dv[6] = sv[6];
    case 6:
      dv[5] = sv[5];
    case 5:
      dv[4] = sv[4];
    case 4:
      dv[3] = sv[3];
    case 3:
      dv[2] = sv[2];
    case 2:
      dv[1] = sv[1];
    case 1:
      dv[0] = sv[0];
    }

  n &= mask;

  if (n)
    {
      dv = (__typeof__ (dv)) ((u8 *) dv - vec_bytes + n);
      sv = (__typeof__ (sv)) ((u8 *) sv - vec_bytes + n);
      dv[0] = sv[0];
    }
  return dst;
}

#endif
#endif
