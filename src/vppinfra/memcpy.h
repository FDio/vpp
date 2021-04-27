/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>
#ifndef included_memcpy_h
#define included_memcpy_h

#ifndef __COVERITY__

static_always_inline void
clib_memcpy_u32_x4 (u32 *dst, u32 *src)
{
#if defined(CLIB_HAVE_VEC128)
  u32x4_store_unaligned (u32x4_load_unaligned (src), dst);
#else
  clib_memcpy_fast (dst, src, 4 * sizeof (u32));
#endif
}
static_always_inline void
clib_memcpy_u32_x8 (u32 *dst, u32 *src)
{
#if defined(CLIB_HAVE_VEC256)
  u32x8_store_unaligned (u32x8_load_unaligned (src), dst);
#else
  clib_memcpy_u32_x4 (dst, src);
  clib_memcpy_u32_x4 (dst + 4, src + 4);
#endif
}

static_always_inline void
clib_memcpy_u32_x16 (u32 *dst, u32 *src)
{
#if defined(CLIB_HAVE_VEC512)
  u32x16_store_unaligned (u32x16_load_unaligned (src), dst);
#else
  clib_memcpy_u32_x8 (dst, src);
  clib_memcpy_u32_x8 (dst + 8, src + 8);
#endif
}

static_always_inline void
clib_memcpy_u32 (u32 *dst, u32 *src, u32 n_left)
{
#if defined(CLIB_HAVE_VEC128)
  if (COMPILE_TIME_CONST (n_left))
    {
      /* for n_left defined as compile-time constant we should prevent compiler
       * to use more expensive mask load/store for common cases where smaller
       * register load/store exists */
      switch (n_left)
	{
	case 4:
	  clib_memcpy_u32_x4 (dst, src);
	  return;
	case 8:
	  clib_memcpy_u32_x8 (dst, src);
	  return;
	case 12:
	  clib_memcpy_u32_x8 (dst, src);
	  clib_memcpy_u32_x4 (dst + 8, src + 8);
	  return;
	case 16:
	  clib_memcpy_u32_x16 (dst, src);
	  return;
	case 32:
	  clib_memcpy_u32_x16 (dst, src);
	  clib_memcpy_u32_x16 (dst + 16, src + 16);
	  return;
	case 64:
	  clib_memcpy_u32_x16 (dst, src);
	  clib_memcpy_u32_x16 (dst + 16, src + 16);
	  clib_memcpy_u32_x16 (dst + 32, src + 32);
	  clib_memcpy_u32_x16 (dst + 48, src + 48);
	  return;
	default:
	  break;
	}
    }

#if defined(CLIB_HAVE_VEC512)
  while (n_left >= 64)
    {
      clib_memcpy_u32_x16 (dst, src);
      clib_memcpy_u32_x16 (dst + 16, src + 16);
      clib_memcpy_u32_x16 (dst + 32, src + 32);
      clib_memcpy_u32_x16 (dst + 48, src + 48);
      dst += 64;
      src += 64;
      n_left -= 64;
    }
#endif

#if defined(CLIB_HAVE_VEC256)
  while (n_left >= 32)
    {
      clib_memcpy_u32_x16 (dst, src);
      clib_memcpy_u32_x16 (dst + 16, src + 16);
      dst += 32;
      src += 32;
      n_left -= 32;
    }
#endif

  while (n_left >= 16)
    {
      clib_memcpy_u32_x16 (dst, src);
      dst += 16;
      src += 16;
      n_left -= 16;
    }

#if defined(CLIB_HAVE_VEC512_MASK_LOAD_STORE)
  if (n_left)
    {
      u16 mask = pow2_mask (n_left);
      u32x16_mask_store (u32x16_mask_load_zero (src, mask), dst, mask);
    }
  return;
#endif

  if (n_left >= 8)
    {
      clib_memcpy_u32_x8 (dst, src);
      dst += 8;
      src += 8;
      n_left -= 8;
    }

#if defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
  if (n_left)
    {
      u8 mask = pow2_mask (n_left);
      u32x8_mask_store (u32x8_mask_load_zero (src, mask), dst, mask);
    }
  return;
#endif

  if (n_left >= 4)
    {
      clib_memcpy_u32_x4 (dst, src);
      dst += 4;
      src += 4;
      n_left -= 4;
    }
#endif

  while (n_left)
    {
      dst[0] = src[0];
      dst += 1;
      src += 1;
      n_left -= 1;
    }
}

#else /* __COVERITY__ */
static_always_inline void
clib_memcpy_u32 (u32 *dst, u32 *src, u32 n_left)
{
  memcpy (dst, src, n_left * sizeof (u32));
}
#endif

#endif
