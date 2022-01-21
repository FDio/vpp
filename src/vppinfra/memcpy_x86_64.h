/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Damjan Marion
 */

#ifndef included_clib_memcpy_x86_64_h
#define included_clib_memcpy_x86_64_h
#ifdef __x86_64__

#include <vppinfra/clib.h>
#include <vppinfra/warnings.h>
#include <stdio.h>

/* clang-format off */
WARN_OFF (stringop-overflow)
/* clang-format on */

static_always_inline void
clib_memcpy1 (void *d, void *s)
{
  *(u8 *) d = *(u8 *) s;
}

static_always_inline void
clib_memcpy2 (void *d, void *s)
{
  *(u16u *) d = *(u16u *) s;
}

static_always_inline void
clib_memcpy4 (void *d, void *s)
{
  *(u32u *) d = *(u32u *) s;
}

static_always_inline void
clib_memcpy8 (void *d, void *s)
{
  *(u64u *) d = *(u64u *) s;
}

static_always_inline void
clib_memcpy16 (void *d, void *s)
{
  *(u8x16u *) d = *(u8x16u *) s;
}

static_always_inline void
clib_memcpy32 (void *d, void *s)
{
  *(u8x32u *) d = *(u8x32u *) s;
}

static_always_inline void
clib_memcpy64 (void *d, void *s)
{
  *(u8x64u *) d = *(u8x64u *) s;
}

static_always_inline void
clib_memcpy_const_le32 (u8 *dst, u8 *src, size_t n)
{
  switch (n)
    {
    case 1:
      clib_memcpy1 (dst, src);
      break;
    case 2:
      clib_memcpy2 (dst, src);
      break;
    case 3:
      clib_memcpy2 (dst, src);
      clib_memcpy1 (dst + 2, src + 2);
      break;
    case 4:
      clib_memcpy4 (dst, src);
      break;
    case 5:
      clib_memcpy4 (dst, src);
      clib_memcpy1 (dst + 4, src + 4);
      break;
    case 6:
      clib_memcpy4 (dst, src);
      clib_memcpy2 (dst + 4, src + 4);
      break;
    case 7:
      clib_memcpy4 (dst, src);
      clib_memcpy4 (dst + 3, src + 3);
      break;
    case 8:
      clib_memcpy8 (dst, src);
      break;
    case 9:
      clib_memcpy8 (dst, src);
      clib_memcpy1 (dst + 8, src + 8);
      break;
    case 10:
      clib_memcpy8 (dst, src);
      clib_memcpy2 (dst + 8, src + 8);
      break;
    case 11:
    case 12:
      clib_memcpy8 (dst, src);
      clib_memcpy4 (dst + n - 4, src + n - 4);
      break;
    case 13:
    case 14:
    case 15:
      clib_memcpy8 (dst, src);
      clib_memcpy8 (dst + n - 8, src + n - 8);
      break;
    case 16:
      clib_memcpy16 (dst, src);
      break;
    case 17:
      clib_memcpy16 (dst, src);
      clib_memcpy1 (dst + 16, src + 16);
      break;
    case 18:
      clib_memcpy16 (dst, src);
      clib_memcpy2 (dst + 16, src + 16);
      break;
    case 20:
      clib_memcpy16 (dst, src);
      clib_memcpy4 (dst + 16, src + 16);
      break;
    case 24:
      clib_memcpy16 (dst, src);
      clib_memcpy8 (dst + 16, src + 16);
      break;
    default:
      clib_memcpy16 (dst, src);
      clib_memcpy16 (dst + n - 16, src + n - 16);
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
      clib_memcpy32 (dst, src);
      break;
    case 33:
      clib_memcpy32 (dst, src);
      clib_memcpy1 (dst + 32, src + 32);
      break;
    case 34:
      clib_memcpy32 (dst, src);
      clib_memcpy2 (dst + 32, src + 32);
      break;
    case 36:
      clib_memcpy32 (dst, src);
      clib_memcpy4 (dst + 32, src + 32);
      break;
    case 40:
      clib_memcpy32 (dst, src);
      clib_memcpy8 (dst + 32, src + 32);
      break;
    case 48:
      clib_memcpy32 (dst, src);
      clib_memcpy16 (dst + 32, src + 32);
      break;
    default:
      clib_memcpy32 (dst, src);
      clib_memcpy32 (dst + n - 32, src + n - 32);
      break;
    }
#else
  while (n > 31)
    {
      clib_memcpy16 (dst, src);
      clib_memcpy16 (dst + 16, src + 16);
      dst += 32;
      src += 32;
      n -= 32;
    }
  clib_memcpy_const_le32 (dst, src, n);
#endif
}

static_always_inline void
clib_memcpy_x86_64_const (u8 *dst, u8 *src, size_t n)
{
#if defined(CLIB_HAVE_VEC512)
  while (n > 128)
    {
      clib_memcpy64 (dst, src);
      dst += 64;
      src += 64;
      n -= 64;
    }

  if (n < 64)
    {
      clib_memcpy_const_le64 (dst, src, n);
      return;
    }

  switch (n)
    {
    case 64:
      clib_memcpy64 (dst, src);
      break;
    case 65:
      clib_memcpy64 (dst, src);
      clib_memcpy1 (dst + 64, src + 64);
      break;
    case 66:
      clib_memcpy64 (dst, src);
      clib_memcpy2 (dst + 64, src + 64);
      break;
    case 68:
      clib_memcpy64 (dst, src);
      clib_memcpy4 (dst + 64, src + 64);
      break;
    case 72:
      clib_memcpy64 (dst, src);
      clib_memcpy8 (dst + 64, src + 64);
      break;
    case 80:
      clib_memcpy64 (dst, src);
      clib_memcpy16 (dst + 64, src + 64);
      break;
    case 96:
      clib_memcpy64 (dst, src);
      clib_memcpy32 (dst + 64, src + 64);
      break;
    default:
      clib_memcpy64 (dst, src);
      clib_memcpy64 (dst + n - 64, src + n - 64);
      break;
    }
#elif defined(CLIB_HAVE_VEC256)
  while (n > 64)
    {
      clib_memcpy32 (dst, src);
      dst += 32;
      src += 32;
      n -= 32;
    }
  clib_memcpy_const_le64 (dst, src, n);
#else
  while (n > 32)
    {
      clib_memcpy16 (dst, src);
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
  u8 *d = (u8 *) dst, *s = (u8 *) src;

  if (n == 0)
    return dst;

  if (COMPILE_TIME_CONST (n))
    {
      if (n)
	clib_memcpy_x86_64_const (d, s, n);
      return dst;
    }

  if (n <= 32)
    {
#if defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
      u32 mask = pow2_mask (n);
      u8x32_mask_store (u8x32_mask_load_zero (s, mask), d, mask);
#else
      if (PREDICT_TRUE (n >= 16))
	{
	  clib_memcpy16 (d, s);
	  clib_memcpy16 (d + n - 16, s + n - 16);
	}
      else if (PREDICT_TRUE (n >= 8))
	{
	  clib_memcpy8 (d, s);
	  clib_memcpy8 (d + n - 8, s + n - 8);
	}
      else if (PREDICT_TRUE (n >= 4))
	{
	  clib_memcpy4 (d, s);
	  clib_memcpy4 (d + n - 4, s + n - 4);
	}
      else if (PREDICT_TRUE (n > 1))
	{
	  clib_memcpy2 (d, s);
	  clib_memcpy2 (d + n - 2, s + n - 2);
	}
      else
	clib_memcpy1 (d, s);
#endif
    }
#ifdef CLIB_HAVE_VEC512
  else
    {
      u8x64 v0, v1, v2, v3;
      u64 final_off, nr, off = 64;

      if (n <= 64)
	{
	  n -= 32;
	  u8x32_store_unaligned (u8x32_load_unaligned (s), d);
	  u8x32_store_unaligned (u8x32_load_unaligned (s + n), d + n);
	  return dst;
	}

      u8x64_store_unaligned (u8x64_load_unaligned (s), d);

      if (n <= 128)
	goto done2;

      if (n <= 192)
	goto one;

      if (n <= 512 + 64)
	{
	  nr = round_pow2 (n - 128, 64);
	  goto last;
	}

      off -= ((u64) d) & 0x3f;
      nr = round_pow2 (n - off - 64, 64);
      final_off = (nr & ~(u64) 0x1ff) + off;

    more:
      v0 = u8x64_load_unaligned (s + off + 0x000);
      v1 = u8x64_load_unaligned (s + off + 0x040);
      v2 = u8x64_load_unaligned (s + off + 0x080);
      v3 = u8x64_load_unaligned (s + off + 0x0c0);
      u8x64_store_unaligned (v0, d + off + 0x000);
      u8x64_store_unaligned (v1, d + off + 0x040);
      u8x64_store_unaligned (v2, d + off + 0x080);
      u8x64_store_unaligned (v3, d + off + 0x0c0);
      v0 = u8x64_load_unaligned (s + off + 0x100);
      v1 = u8x64_load_unaligned (s + off + 0x140);
      v2 = u8x64_load_unaligned (s + off + 0x180);
      v3 = u8x64_load_unaligned (s + off + 0x1c0);
      u8x64_store_unaligned (v0, d + off + 0x100);
      u8x64_store_unaligned (v1, d + off + 0x140);
      u8x64_store_unaligned (v2, d + off + 0x180);
      u8x64_store_unaligned (v3, d + off + 0x1c0);
      off += 512;
      if (off != final_off)
	goto more;

      if ((nr & 0x1ff) == 0)
	goto done2;

    last:
      if (PREDICT_TRUE (nr & 256))
	{
	  v0 = u8x64_load_unaligned (s + off + 0x000);
	  v1 = u8x64_load_unaligned (s + off + 0x040);
	  v2 = u8x64_load_unaligned (s + off + 0x080);
	  v3 = u8x64_load_unaligned (s + off + 0x0c0);
	  u8x64_store_unaligned (v0, d + off + 0x000);
	  u8x64_store_unaligned (v1, d + off + 0x040);
	  u8x64_store_unaligned (v2, d + off + 0x080);
	  u8x64_store_unaligned (v3, d + off + 0x0c0);
	  off += 256;
	}
      if (PREDICT_TRUE (nr & 128))
	{
	  v0 = u8x64_load_unaligned (s + off + 0x000);
	  v1 = u8x64_load_unaligned (s + off + 0x040);
	  u8x64_store_unaligned (v0, d + off + 0x000);
	  u8x64_store_unaligned (v1, d + off + 0x040);
	  off += 128;
	}
      if (PREDICT_TRUE (nr & 64))
	{
	one:
	  u8x64_store_unaligned (u8x64_load_unaligned (s + off), d + off);
	}
    done2:
      u8x64_store_unaligned (u8x64_load_unaligned (s + n - 64), d + n - 64);
    }
  return dst;
#elif defined(CLIB_HAVE_VEC256)
  else
    {
      u8x32 v0, v1, v2, v3;
      u64 final_off, nr, off = 32;

      u8x32_store_unaligned (u8x32_load_unaligned (s), d);

      if (n <= 64)
	goto done2;

      if (n <= 96)
	goto one;

      if (n <= 256 + 32)
	{
	  nr = round_pow2 (n - 64, 32);
	  goto last;
	}

      off -= ((u64) d) & 0x1f;
      nr = round_pow2 (n - off - 32, 32);
      final_off = (nr & ~(u64) 0xff) + off;

    more:
      v0 = u8x32_load_unaligned (s + off + 0x00);
      v1 = u8x32_load_unaligned (s + off + 0x20);
      v2 = u8x32_load_unaligned (s + off + 0x40);
      v3 = u8x32_load_unaligned (s + off + 0x60);
      u8x32_store_unaligned (v0, d + off + 0x00);
      u8x32_store_unaligned (v1, d + off + 0x20);
      u8x32_store_unaligned (v2, d + off + 0x40);
      u8x32_store_unaligned (v3, d + off + 0x60);
      v0 = u8x32_load_unaligned (s + off + 0x80);
      v1 = u8x32_load_unaligned (s + off + 0xa0);
      v2 = u8x32_load_unaligned (s + off + 0xc0);
      v3 = u8x32_load_unaligned (s + off + 0xe0);
      u8x32_store_unaligned (v0, d + off + 0x80);
      u8x32_store_unaligned (v1, d + off + 0xa0);
      u8x32_store_unaligned (v2, d + off + 0xc0);
      u8x32_store_unaligned (v3, d + off + 0xe0);
      off += 256;
      if (off != final_off)
	goto more;

      if ((nr & 0xff) == 0)
	goto done2;

    last:
      if (PREDICT_TRUE (nr & 128))
	{
	  v0 = u8x32_load_unaligned (s + off + 0x00);
	  v1 = u8x32_load_unaligned (s + off + 0x20);
	  v2 = u8x32_load_unaligned (s + off + 0x40);
	  v3 = u8x32_load_unaligned (s + off + 0x60);
	  u8x32_store_unaligned (v0, d + off + 0x00);
	  u8x32_store_unaligned (v1, d + off + 0x20);
	  u8x32_store_unaligned (v2, d + off + 0x40);
	  u8x32_store_unaligned (v3, d + off + 0x60);
	  off += 128;
	}
      if (PREDICT_TRUE (nr & 64))
	{
	  v0 = u8x32_load_unaligned (s + off + 0x00);
	  v1 = u8x32_load_unaligned (s + off + 0x20);
	  u8x32_store_unaligned (v0, d + off + 0x00);
	  u8x32_store_unaligned (v1, d + off + 0x20);
	  off += 64;
	}
      if (PREDICT_TRUE (nr & 32))
	{
	one:
	  u8x32_store_unaligned (u8x32_load_unaligned (s + off), d + off);
	}
    done2:
      u8x32_store_unaligned (u8x32_load_unaligned (s + n - 32), d + n - 32);
    }
  return dst;
#elif defined(CLIB_HAVE_VEC128)
  else
    {
      u8x16 v0, v1, v2, v3;
      u64 final_off, nr, off = 32;

      if (0 && n > 389)
	{
	  __builtin_memcpy (d, s, n);
	  return dst;
	}

      u8x16_store_unaligned (u8x16_load_unaligned (s), d);
      u8x16_store_unaligned (u8x16_load_unaligned (s + 16), d + 16);

      if (n <= 48)
	goto done2;

      if (n <= 64)
	goto one;

      if (n <= 256 + 32)
	{
	  nr = round_pow2 (n - 48, 16);
	  goto last;
	}

      off -= ((u64) d) & 0x0f;
      nr = round_pow2 (n - off - 16, 16);
      final_off = (nr & ~(u64) 0xff) + off;

    more:
      v0 = u8x16_load_unaligned (s + off + 0x00);
      v1 = u8x16_load_unaligned (s + off + 0x10);
      v2 = u8x16_load_unaligned (s + off + 0x20);
      v3 = u8x16_load_unaligned (s + off + 0x30);
      u8x16_store_unaligned (v0, d + off + 0x00);
      u8x16_store_unaligned (v1, d + off + 0x10);
      u8x16_store_unaligned (v2, d + off + 0x20);
      u8x16_store_unaligned (v3, d + off + 0x30);
      v0 = u8x16_load_unaligned (s + off + 0x40);
      v1 = u8x16_load_unaligned (s + off + 0x50);
      v2 = u8x16_load_unaligned (s + off + 0x60);
      v3 = u8x16_load_unaligned (s + off + 0x70);
      u8x16_store_unaligned (v0, d + off + 0x40);
      u8x16_store_unaligned (v1, d + off + 0x50);
      u8x16_store_unaligned (v2, d + off + 0x60);
      u8x16_store_unaligned (v3, d + off + 0x70);
      v0 = u8x16_load_unaligned (s + off + 0x80);
      v1 = u8x16_load_unaligned (s + off + 0x90);
      v2 = u8x16_load_unaligned (s + off + 0xa0);
      v3 = u8x16_load_unaligned (s + off + 0xb0);
      u8x16_store_unaligned (v0, d + off + 0x80);
      u8x16_store_unaligned (v1, d + off + 0x90);
      u8x16_store_unaligned (v2, d + off + 0xa0);
      u8x16_store_unaligned (v3, d + off + 0xb0);
      v0 = u8x16_load_unaligned (s + off + 0xc0);
      v1 = u8x16_load_unaligned (s + off + 0xd0);
      v2 = u8x16_load_unaligned (s + off + 0xe0);
      v3 = u8x16_load_unaligned (s + off + 0xf0);
      u8x16_store_unaligned (v0, d + off + 0xc0);
      u8x16_store_unaligned (v1, d + off + 0xd0);
      u8x16_store_unaligned (v2, d + off + 0xe0);
      u8x16_store_unaligned (v3, d + off + 0xf0);
      off += 256;
      if (off != final_off)
	goto more;

      if ((nr & 0xff) == 0)
	goto done2;

    last:
      if (PREDICT_TRUE (nr & 128))
	{
	  v0 = u8x16_load_unaligned (s + off + 0x00);
	  v1 = u8x16_load_unaligned (s + off + 0x10);
	  v2 = u8x16_load_unaligned (s + off + 0x20);
	  v3 = u8x16_load_unaligned (s + off + 0x30);
	  u8x16_store_unaligned (v0, d + off + 0x00);
	  u8x16_store_unaligned (v1, d + off + 0x10);
	  u8x16_store_unaligned (v2, d + off + 0x20);
	  u8x16_store_unaligned (v3, d + off + 0x30);
	  v0 = u8x16_load_unaligned (s + off + 0x40);
	  v1 = u8x16_load_unaligned (s + off + 0x50);
	  v2 = u8x16_load_unaligned (s + off + 0x60);
	  v3 = u8x16_load_unaligned (s + off + 0x70);
	  u8x16_store_unaligned (v0, d + off + 0x40);
	  u8x16_store_unaligned (v1, d + off + 0x50);
	  u8x16_store_unaligned (v2, d + off + 0x60);
	  u8x16_store_unaligned (v3, d + off + 0x70);
	  off += 128;
	}
      if (PREDICT_TRUE (nr & 64))
	{
	  v0 = u8x16_load_unaligned (s + off + 0x00);
	  v1 = u8x16_load_unaligned (s + off + 0x10);
	  v2 = u8x16_load_unaligned (s + off + 0x20);
	  v3 = u8x16_load_unaligned (s + off + 0x30);
	  u8x16_store_unaligned (v0, d + off + 0x00);
	  u8x16_store_unaligned (v1, d + off + 0x10);
	  u8x16_store_unaligned (v2, d + off + 0x20);
	  u8x16_store_unaligned (v3, d + off + 0x30);
	  off += 64;
	}
      if (PREDICT_TRUE (nr & 32))
	{
	  v0 = u8x16_load_unaligned (s + off + 0x00);
	  v1 = u8x16_load_unaligned (s + off + 0x10);
	  u8x16_store_unaligned (v0, d + off + 0x00);
	  u8x16_store_unaligned (v1, d + off + 0x10);
	  off += 32;
	}
      if (PREDICT_TRUE (nr & 16))
	{
	one:
	  u8x16_store_unaligned (u8x16_load_unaligned (s + off), d + off);
	}
    done2:
      u8x16_store_unaligned (u8x16_load_unaligned (s + n - 16), d + n - 16);
    }
  return dst;
#else
  __builtin_memcpy (dst, src, n);
  return dst;
#endif
}

/* clang-format off */
WARN_ON (stringop-overflow)
/* clang-format on */

#endif
#endif
