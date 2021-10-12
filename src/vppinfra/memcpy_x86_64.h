/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Damjan Marion
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
  const u8 vec_bytes = 64;
#elif defined(CLIB_HAVE_VEC256)
  u8x32u *dv = (u8x32u *) dst, *sv = (u8x32u *) src;
  const u8 vec_bytes = 32;
#else
  u8x16u *dv = (u8x16u *) dst, *sv = (u8x16u *) src;
  const u8 vec_bytes = 16;
#endif
  u8 *d = (u8 *) dst, *s = (u8 *) src;
  u64 off, n_ops;

  /* emit minimal number of instructions for cases where n is compile-time
   * constant */
  if (COMPILE_TIME_CONST (n) && n <= 128)
    {
      clib_memcpy_const_le128 (d, s, n);
      return dst;
    }

  /* copy less than vector register size */
  if (PREDICT_TRUE (n < vec_bytes))
    {
#if defined(CLIB_HAVE_VEC512_MASK_LOAD_STORE)
      u64 mask = pow2_mask (n);
      u8x64_mask_store (u8x64_mask_load_zero (s, mask), d, mask);
#elif defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
      u32 mask = pow2_mask (n);
      u8x32_mask_store (u8x32_mask_load_zero (s, mask), d, mask);
#else
      if (PREDICT_TRUE (n >= 8))
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

      if (PREDICT_TRUE (n >= 2))
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

  if (n < 256)
    goto last;

  if (PREDICT_FALSE (off = (uword) dv & (vec_bytes - 1)))
    {
      /* dst pointer is not aligned */
      off = vec_bytes - off;
      dv[0] = sv[0];
      d += off;
      s += off;
      n -= off;
    }

more:
  if (n < 256)
    goto last;
#ifdef CLIB_HAVE_VEC512
  asm volatile("vmovdqu8 (%[src]), %%zmm15\n"
	       "vmovdqu8 0x40(%[src]), %%zmm14\n"
	       "vmovdqu8 0x80(%[src]), %%zmm13\n"
	       "vmovdqu8 0xc0(%[src]), %%zmm12\n"
	       "vmovdqa64 %%zmm15, (%[dst])\n"
	       "vmovdqa64 %%zmm14, 0x40(%[dst])\n"
	       "vmovdqa64 %%zmm13, 0x80(%[dst])\n"
	       "vmovdqa64 %%zmm12, 0xc0(%[dst])\n"
	       :
	       : [dst] "D"(d), [src] "S"(s)
	       : "memory", "zmm15", "zmm14", "zmm13", "zmm12");

#elif defined(CLIB_HAVE_VEC256)
  asm volatile(/* load 0, 2 */
	       "vmovdqu (%[src]), %%ymm15\n"
	       "vmovdqu 0x40(%[src]), %%ymm14\n"

	       /* load 1, store 0, 1 */
	       "vmovdqa %%ymm15, (%[dst])\n"
	       "vmovdqu 0x20(%[src]), %%ymm15\n"
	       "vmovdqa %%ymm15, 0x20(%[dst])\n"

	       /* load 4, 6 */
	       "vmovdqu 0x80(%[src]), %%ymm13\n"
	       "vmovdqu 0xc0(%[src]), %%ymm12\n"

	       /* load 3, store 2, 3 */
	       "vmovdqu 0x60(%[src]), %%ymm15\n"
	       "vmovdqa %%ymm14, 0x40(%[dst])\n"
	       "vmovdqa %%ymm15, 0x60(%[dst])\n"

	       /* load 5, store 4, 5 */
	       "vmovdqu 0xa0(%[src]), %%ymm15\n"
	       "vmovdqa %%ymm13, 0x80(%[dst])\n"
	       "vmovdqa %%ymm15, 0xa0(%[dst])\n"

	       /* load 7, store 6, 7 */
	       "vmovdqu 0xe0(%[src]), %%ymm15\n"
	       "vmovdqa %%ymm12, 0xc0(%[dst])\n"
	       "vmovdqa %%ymm15, 0xe0(%[dst])\n"
	       :
	       : [dst] "D"(d), [src]"S"(s)
	       : "memory", "ymm15", "ymm14", "ymm13", "ymm12");
#else
  asm volatile(/* load 0, 4, 8, 12 */
	       "vmovdqu (%[src]), %%xmm15\n"
	       "vmovdqu 0x40(%[src]), %%xmm14\n"
	       "vmovdqu 0x80(%[src]), %%xmm13\n"

	       /* load 1, 2, 3, store 0, 1, 2, 3 */
	       "vmovdqa %%xmm15, (%[dst])\n"
	       "vmovdqu 0x10(%[src]), %%xmm15\n"
	       "vmovdqa %%xmm15, 0x10(%[dst])\n"
	       "vmovdqu 0x20(%[src]), %%xmm15\n"
	       "vmovdqa %%xmm15, 0x20(%[dst])\n"

	       "vmovdqu 0xc0(%[src]), %%xmm12\n"

	       "vmovdqu 0x30(%[src]), %%xmm15\n"
	       "vmovdqa %%xmm15, 0x30(%[dst])\n"

	       /* load 5, 6, 7 store 4, 5, 6, 7  */
	       "vmovdqa %%xmm14, 0x40(%[dst])\n"
	       "vmovdqu 0x50(%[src]), %%xmm15\n"
	       "vmovdqa %%xmm15, 0x50(%[dst])\n"
	       "vmovdqu 0x60(%[src]), %%xmm15\n"
	       "vmovdqa %%xmm15, 0x60(%[dst])\n"
	       "vmovdqu 0x70(%[src]), %%xmm15\n"
	       "vmovdqa %%xmm15, 0x70(%[dst])\n"

	       /* load 5, store 4, 5 */
	       "vmovdqa %%xmm13, 0x80(%[dst])\n"
	       "vmovdqu 0x90(%[src]), %%xmm15\n"
	       "vmovdqa %%xmm15, 0x90(%[dst])\n"
	       "vmovdqu 0xa0(%[src]), %%xmm15\n"
	       "vmovdqa %%xmm15, 0xa0(%[dst])\n"
	       "vmovdqu 0xb0(%[src]), %%xmm15\n"
	       "vmovdqa %%xmm15, 0xb0(%[dst])\n"

	       /* load 7, store 6, 7 */
	       "vmovdqa %%xmm12, 0xc0(%[dst])\n"
	       "vmovdqu 0xd0(%[src]), %%xmm15\n"
	       "vmovdqa %%xmm15, 0xd0(%[dst])\n"
	       "vmovdqu 0xe0(%[src]), %%xmm15\n"
	       "vmovdqa %%xmm15, 0xe0(%[dst])\n"
	       "vmovdqu 0xf0(%[src]), %%xmm15\n"
	       "vmovdqa %%xmm15, 0xf0(%[dst])\n"
	       :
	       : [dst] "D"(d), [src] "S"(s)
	       : "memory", "xmm15", "xmm14", "xmm13", "xmm12");
#endif
  n -= 256;
  d += 256;
  s += 256;

  goto more;

last:

  if (PREDICT_TRUE (n))
    {
#ifdef CLIB_HAVE_VEC512
      n_ops = (3 - (n >> 6)) * 20;
      off = (n & 0x3f) - 64;

      asm volatile(
	"lea 1f(%%rip), %%r11\n"
	"addq %[n_ops], %%r11\n"
	"jmp *%%r11\n"

	"1:\n"
	"vmovdqu8 (%[src]), %%zmm15; addq $64, %[src]\n"
	"vmovdqa64 %%zmm15, (%[dst]); addq $64, %[dst]\n"
	"vmovdqu8 (%[src]), %%zmm15; addq $64, %[src]\n"
	"vmovdqa64 %%zmm15, (%[dst]); addq $64, %[dst]\n"
	"vmovdqu8 (%[src]), %%zmm15; addq $64, %[src]\n"
	"vmovdqa64 %%zmm15, (%[dst]); addq $64, %[dst]\n"

	"addq %[off], %[src]\n"
	"vmovdqu8 (%[src]), %%zmm15\n"
	"addq %[off], %[dst]\n"
	"vmovdqu8 %%zmm15, (%[dst])\n"

	:
	: [dst] "D"(d), [src] "S"(s), [n_ops] "r"(n_ops), [off] "r"(off)
	: "memory", "r11", "zmm15");
#elif defined(CLIB_HAVE_VEC256)
      n_ops = (7 - (n >> 5)) * 16;
      off = n - 32;
      asm volatile(
	"lea 1f(%%rip), %%r11\n"
	"addq %[n_ops], %%r11\n"
	"jmp *%%r11\n"

	"1:\n"
	"vmovdqu 0xc0(%[src]), %%ymm15;\n"
	"vmovdqu %%ymm15, 0xc0(%[dst]);\n"

	"vmovdqu 0xa0(%[src]), %%ymm15;\n"
	"vmovdqu %%ymm15, 0xa0(%[dst]);\n"

	"vmovdqu 0x80(%[src]), %%ymm15;\n"
	"vmovdqu %%ymm15, 0x80(%[dst]);\n"

	"%{disp32%} vmovdqu 0x60(%[src]), %%ymm15;\n"
	"%{disp32%} vmovdqu %%ymm15, 0x60(%[dst]);\n"

	"%{disp32%} vmovdqu 0x40(%[src]), %%ymm15;\n"
	"%{disp32%} vmovdqu %%ymm15, 0x40(%[dst]);\n"

	"%{disp32%} vmovdqu 0x20(%[src]), %%ymm15;\n"
	"%{disp32%} vmovdqu %%ymm15, 0x20(%[dst]);\n"

	"%{disp32%} vmovdqu (%[src]), %%ymm15;\n"
	"%{disp32%} vmovdqu %%ymm15, (%[dst]);\n"

	"addq %[off], %[src]\n"
	"vmovdqu (%[src]), %%ymm15\n"
	"addq %[off], %[dst]\n"
	"vmovdqu %%ymm15, (%[dst])\n"

	:
	: [dst] "D"(d), [src] "S"(s), [n_ops] "r"(n_ops), [off] "r"(off)
	: "memory", "r11", "ymm15");
#else
      n_ops = (15 - (n >> 4)) * 16;
      off = n - 16;
      asm volatile(
	"lea 1f(%%rip), %%r11\n"
	"addq %[n_ops], %%r11\n"
	"jmp *%%r11\n"

	"1:\n"
	"vmovdqu 0xe0(%[src]), %%xmm15;\n"
	"vmovdqu %%xmm15, 0xe0(%[dst]);\n"
	"vmovdqu 0xd0(%[src]), %%xmm15;\n"
	"vmovdqu %%xmm15, 0xd0(%[dst]);\n"
	"vmovdqu 0xc0(%[src]), %%xmm15;\n"
	"vmovdqu %%xmm15, 0xc0(%[dst]);\n"

	"vmovdqu 0xb0(%[src]), %%xmm15;\n"
	"vmovdqu %%xmm15, 0xb0(%[dst]);\n"
	"vmovdqu 0xa0(%[src]), %%xmm15;\n"
	"vmovdqu %%xmm15, 0xa0(%[dst]);\n"

	"vmovdqu 0x90(%[src]), %%xmm15;\n"
	"vmovdqu %%xmm15, 0x90(%[dst]);\n"
	"vmovdqu 0x80(%[src]), %%xmm15;\n"
	"vmovdqu %%xmm15, 0x80(%[dst]);\n"

	"%{disp32%} vmovdqu 0x70(%[src]), %%xmm15;\n"
	"%{disp32%} vmovdqu %%xmm15, 0x70(%[dst]);\n"
	"%{disp32%} vmovdqu 0x60(%[src]), %%xmm15;\n"
	"%{disp32%} vmovdqu %%xmm15, 0x60(%[dst]);\n"

	"%{disp32%} vmovdqu 0x50(%[src]), %%xmm15;\n"
	"%{disp32%} vmovdqu %%xmm15, 0x50(%[dst]);\n"
	"%{disp32%} vmovdqu 0x40(%[src]), %%xmm15;\n"
	"%{disp32%} vmovdqu %%xmm15, 0x40(%[dst]);\n"

	"%{disp32%} vmovdqu 0x30(%[src]), %%xmm15;\n"
	"%{disp32%} vmovdqu %%xmm15, 0x30(%[dst]);\n"
	"%{disp32%} vmovdqu 0x20(%[src]), %%xmm15;\n"
	"%{disp32%} vmovdqu %%xmm15, 0x20(%[dst]);\n"

	"%{disp32%} vmovdqu 0x10(%[src]), %%xmm15;\n"
	"%{disp32%} vmovdqu %%xmm15, 0x10(%[dst]);\n"
	"%{disp32%} vmovdqu (%[src]), %%xmm15;\n"
	"%{disp32%} vmovdqu %%xmm15, (%[dst]);\n"

	"addq %[off], %[src]\n"
	"vmovdqu (%[src]), %%xmm15\n"
	"addq %[off], %[dst]\n"
	"vmovdqu %%xmm15, (%[dst])\n"

	:
	: [dst] "D"(d), [src] "S"(s), [n_ops] "r"(n_ops), [off] "r"(off)
	: "memory", "r11", "xmm15");
#endif
    }
  return dst;
}

#endif
#endif
