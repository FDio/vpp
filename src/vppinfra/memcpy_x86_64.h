/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#ifndef included_clib_memcpy_x86_64_h
#define included_clib_memcpy_x86_64_h
#ifdef __x86_64__

#include <vppinfra/clib.h>

#if __AVX512BITALG__
#include <vppinfra/memcpy_avx512.h>
#define clib_memcpy_fast_arch(a, b, c) clib_memcpy_fast_avx512 (a, b, c)
#elif __AVX2__
#include <vppinfra/memcpy_avx2.h>
#define clib_memcpy_fast_arch(a, b, c) clib_memcpy_fast_avx2 (a, b, c)
#elif __SSSE3__
#include <vppinfra/memcpy_sse3.h>
#define clib_memcpy_fast_arch(a, b, c) clib_memcpy_fast_sse3 (a, b, c)
#endif /* __AVX512BITALG__ */

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
  u8 *d = (u8 *) dst;
  u8 *s = (u8 *) src;
  void *rv = dst;

  /* emit minimal number of instructions for cases where n is compile-time
   * constant */
  if (COMPILE_TIME_CONST (n) && n <= 128)
    {
      clib_memcpy_const_le128 (d, s, n);
      return rv;
    }

  /* copy less than 16 bytes */
  if (n < 16)
    {
#ifdef CLIB_HAVE_VEC128_MASK_LOAD_STORE
      u16 mask = pow2_mask (n);
      u8x16_mask_store (u8x16_mask_load_zero ((void *) s, mask), d, mask);
#else
      if (n & 0x01)
	{
	  *d = *s;
	  d++;
	  s++;
	}
      if (n & 0x02)
	{
	  *(u16u *) d = *(const u16u *) s;
	  d += 2;
	  s += 2;
	}
      if (n & 0x04)
	{
	  *(u32u *) d = *(const u32u *) s;
	  d += 4;
	  s += 4;
	}
      if (n & 0x08)
	*(u64u *) d = *(const u64u *) s;
#endif
      return rv;
    }

  return clib_memcpy_fast_arch (dst, src, n);
}

#endif
#endif
