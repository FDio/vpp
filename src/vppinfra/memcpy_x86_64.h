/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Damjan Marion
 */

#ifndef included_clib_memcpy_x86_64_h
#define included_clib_memcpy_x86_64_h
#ifdef __x86_64__

#include <vppinfra/clib.h>
#include <vppinfra/warnings.h>

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
  *(u16 *) d = *(u16 *) s;
}

static_always_inline void
clib_memcpy4 (void *d, void *s)
{
  *(u32 *) d = *(u32 *) s;
}

static_always_inline void
clib_memcpy8 (void *d, void *s)
{
  *(u64 *) d = *(u64 *) s;
}

#ifdef CLIB_HAVE_VEC128
static_always_inline void
clib_memcpy16 (void *d, void *s)
{
  *(u8x16u *) d = *(u8x16u *) s;
}
#endif

#ifdef CLIB_HAVE_VEC256
static_always_inline void
clib_memcpy32 (void *d, void *s)
{
  *(u8x32u *) d = *(u8x32u *) s;
}
#endif

#ifdef CLIB_HAVE_VEC512
static_always_inline void
clib_memcpy64 (void *d, void *s)
{
  *(u8x64u *) d = *(u8x64u *) s;
}
#endif

/* clang-format off */
WARN_ON (stringop-overflow)
/* clang-format on */

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

  /* emit minimal number of instructions for cases where n is compile-time
   * constant */
  if (COMPILE_TIME_CONST (n))
    {
      if (n)
	clib_memcpy_x86_64_const (d, s, n);
      goto done;
    }

  /* copy less than largest vector register size */
  if (PREDICT_TRUE (n < 32))
    {
#if defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
      u32 mask = pow2_mask (n);
      u8x32_mask_store (u8x32_mask_load_zero (s, mask), d, mask);
#else
      if (PREDICT_TRUE (n >= 8))
	{
	  if (n >= 16)
	    {
	      clib_memcpy16 (d, s);
	      clib_memcpy16 (d + n - 16, s + n - 16);
	      goto done;
	    }
	  clib_memcpy8 (d, s);
	  clib_memcpy8 (d + n - 8, s + n - 8);
	  goto done;
	}

      if (PREDICT_TRUE (n >= 2))
	{
	  if (n >= 4)
	    {
	      clib_memcpy4 (d, s);
	      clib_memcpy4 (d + n - 4, s + n - 4);
	      goto done;
	    }

	  clib_memcpy2 (d, s);
	  clib_memcpy2 (d + n - 2, s + n - 2);
	  goto done;
	}

      clib_memcpy1 (d, s);
#endif
      goto done;
    }

#ifdef CLIB_HAVE_VEC512
  if (PREDICT_TRUE (n <= 64))
    {
      clib_memcpy32 (d, s);
      clib_memcpy32 (d + n - 32, s + n - 32);
      goto done;
    }

#if defined(__clang__) && __clang_major__ < 10
  /* clang versions prior to 10 have issues with inline assembly when
   * ZMM registers are used so we fallback to C implementation whch leverages
   * clang loop unrolling */
  uword nr = round_pow2 (n - 64, 64);
  for (uword i = 0; i < nr; i += 64)
    clib_memcpy64 (d + i, s + i);
  clib_memcpy64 (d + n - 64, d + n - 64);
#else
  u8x64 zmm0, zmm1, zmm2, zmm3;
  u64 off, nr, tmp;
  asm volatile(
    "vmovdqu8	(%[src]), %[zmm0]		\n\t" /* copy first 64 bytes */
    "vmovdqu8	%[zmm0], (%[dst])		\n\t"

    "cmp	$0x80,%[n]			\n\t" /* done if n <= 128 */
    "jbe	.L_done_%=			\n\t"

    "mov	$0x240, %k[off]			\n\t" /* offset 512 + 64 */
    /*  512 is used to force 32-bit displacement of vmovdq* instructions
     *  bellow so all load/stores at the end are 8-byte long */

    "cmp	$0xc0,%[n]			\n\t" /* done if n <= 192 */
    "jbe	.L_only_one_%=			\n\t"

    "cmp	$0x240, %[n]			\n\t" /* if n =< (512 + 64) */
    "jbe	.L_skip_main_%=			\n\t" /* skip main */

    "mov	%[dst], %[tmp]			\n\t" /* align dst pointer */
    "and	$0x3f, %[tmp]			\n\t"
    "sub	%[tmp], %[off]			\n\t"

    "lea	-65(%[tmp], %[n]), %[nr]	\n\t" /* round n to x*64 */
    "mov	%[nr], %[tmp]			\n\t"
    "and	$-512, %[tmp]			\n\t" /* round tmp to x*256 */
    "add	%[off], %[tmp]			\n\t" /* tmp - loop exit val */

    ".L_more_%=:				\n\t" /* main copy loop */
    "vmovdqu8	-0x200(%[src],%[off]), %[zmm0]	\n\t"
    "vmovdqu8	-0x1c0(%[src],%[off]), %[zmm1]	\n\t"
    "vmovdqu8	-0x180(%[src],%[off]), %[zmm2]	\n\t"
    "vmovdqu8	-0x140(%[src],%[off]), %[zmm3]	\n\t"
    "vmovdqu64	%[zmm0], -0x200(%[dst],%[off])	\n\t"
    "vmovdqu64	%[zmm1], -0x1c0(%[dst],%[off])	\n\t"
    "vmovdqu8	-0x100(%[src],%[off]), %[zmm0]	\n\t"
    "vmovdqu8	-0x0c0(%[src],%[off]), %[zmm1]	\n\t"
    "vmovdqu64	%[zmm2], -0x180(%[dst],%[off])	\n\t"
    "vmovdqu64	%[zmm3], -0x140(%[dst],%[off])	\n\t"
    "vmovdqu8	-0x080(%[src],%[off]), %[zmm2]	\n\t"
    "vmovdqu8	-0x040(%[src],%[off]), %[zmm3]	\n\t"
    "vmovdqu64	%[zmm0], -0x100(%[dst],%[off])	\n\t"
    "vmovdqu64	%[zmm1], -0x0c0(%[dst],%[off])	\n\t"
    "vmovdqu64	%[zmm2], -0x080(%[dst],%[off])	\n\t"
    "vmovdqu64	%[zmm3], -0x040(%[dst],%[off])	\n\t"
    "add	$0x200, %[off]			\n\t"
    "cmp	%[tmp], %[off]			\n\t"
    "jne	.L_more_%=			\n\t"

    "and	$0x1c0, %[nr]			\n\t" /* n in last round */
    "je		.L_done_%=			\n\t"

    "shr	$2, %[nr]			\n\t" /* for eeach 64 bytes */
    "lea	.L_done_%=(%%rip), %[tmp]	\n\t" /* jump pointer */
    "sub	%[nr], %[tmp]			\n\t" /* ld/st is 16 byte */
    "jmp	*%[tmp]				\n\t"

    ".L_skip_main_%=:				\n\t"
    "lea	-65(%[n]), %[nr]		\n\t" /* round n to x * 64 */
    "and	$0x1c0, %[nr]			\n\t"
    "shr	$2, %[nr]			\n\t" /* for eeach 64 bytes */
    "lea	.L_done_%=(%%rip), %[tmp]	\n\t" /* jump pointer */
    "sub	%[nr], %[tmp]			\n\t" /* ld/st is 16 byte */
    "jmp	*%[tmp]				\n\t"

    "vmovdqu8	-0x080(%[src],%[off]), %[zmm0]	\n\t"
    "vmovdqu8	%[zmm0], -0x080(%[dst],%[off])	\n\t"
    "vmovdqu8	-0x0c0(%[src],%[off]), %[zmm0]	\n\t"
    "vmovdqu8	%[zmm0], -0x0c0(%[dst],%[off])	\n\t"
    "vmovdqu8	-0x100(%[src],%[off]), %[zmm0]	\n\t"
    "vmovdqu8	%[zmm0], -0x100(%[dst],%[off])	\n\t"
    "vmovdqu8	-0x140(%[src],%[off]), %[zmm0]	\n\t"
    "vmovdqu8	%[zmm0], -0x140(%[dst],%[off])	\n\t"
    "vmovdqu8	-0x180(%[src],%[off]), %[zmm0]	\n\t"
    "vmovdqu8	%[zmm0], -0x180(%[dst],%[off])	\n\t"
    "vmovdqu8	-0x1c0(%[src],%[off]), %[zmm0]	\n\t"
    "vmovdqu8	%[zmm0], -0x1c0(%[dst],%[off])	\n\t"
    ".L_only_one_%=:				\n\t"
    "vmovdqu8	-0x200(%[src],%[off]), %[zmm0]	\n\t"
    "vmovdqu8	%[zmm0], -0x200(%[dst],%[off])	\n\t"
    ".L_done_%=:				\n\t"
    "vmovdqu8	-0x40(%[src],%[n]), %[zmm0]	\n\t" /* copy last 64 bytes */
    "vmovdqu8	%[zmm0], -0x40(%[dst],%[n])	\n\t"

    : [ zmm0 ] "=&v"(zmm0), [ zmm1 ] "=&v"(zmm1), [ zmm2 ] "=&v"(zmm2),
      [ zmm3 ] "=&v"(zmm3), [ dst ] "+D"(d), [ src ] "+S"(s), [ n ] "+r"(n),
      [ nr ] "=&r"(nr), [ off ] "=&r"(off), [ tmp ] "=&r"(tmp)
    :
    : "memory");
#endif

#elif defined(CLIB_HAVE_VEC256)
  u8x32 ymm0, ymm1, ymm2, ymm3;
  u64 off, tmp, nr;
  asm volatile(
    /* copy first 32 bytes */
    "vmovdqu	(%[src]), %[ymm0]		\n\t"
    "vmovdqu	%[ymm0], (%[dst])		\n\t"

    /* do a bit of work in parallel with loads/stores
     *  initial offset is 256 + 32
     *  32 bytes are already copied
     *  256 is used to force 32-bit displacement of vmovdqu
     *  bellow so all load/stores at the end are 9-byte long
     */
    "mov	$0x220, %k[off]			\n\t"

    /* done if n <= 64 */
    "cmp	$0x40,%[n]			\n\t"
    "jbe	.L_done_%=			\n\t"

    /* done if n <= 96 */
    "cmp	$0x60,%[n]			\n\t"
    "jbe	.L_only_one_%=			\n\t"

    /* if n =< (256 + 32) skip main loop */
    "cmp	$0x120, %[n]			\n\t"
    "jbe	.L_skip_main_%=			\n\t"

    /* align dst pointer */
    "mov	%[dst], %[tmp]			\n\t"
    "and	$0x1f, %[tmp]			\n\t"
    "sub	%[tmp], %[off]			\n\t"

    /* loop preparation
     * tmp - loop exit value
     * n  - nomber of bytes to copy in the last round
     */
    "lea	-33(%[tmp], %[n]), %[nr]	\n\t"
    "mov	%[nr], %[tmp]			\n\t"
    "xor	%b[tmp], %b[tmp]		\n\t"
    "add	%[off], %[tmp]			\n\t"

    /* main 256-byte copy loop */
    ".L_more_%=:				\n\t"
    "vmovdqu	-0x200(%[src],%[off]), %[ymm0]	\n\t"
    "vmovdqu	-0x1e0(%[src],%[off]), %[ymm1]	\n\t"
    "vmovdqu	-0x1c0(%[src],%[off]), %[ymm2]	\n\t"
    "vmovdqu	-0x1a0(%[src],%[off]), %[ymm3]	\n\t"
    "vmovdqa	%[ymm0], -0x200(%[dst],%[off])	\n\t"
    "vmovdqa	%[ymm1], -0x1e0(%[dst],%[off])	\n\t"
    "vmovdqa	%[ymm2], -0x1c0(%[dst],%[off])	\n\t"
    "vmovdqa	%[ymm3], -0x1a0(%[dst],%[off])	\n\t"
    "vmovdqu	-0x180(%[src],%[off]), %[ymm0]	\n\t"
    "vmovdqu	-0x160(%[src],%[off]), %[ymm1]	\n\t"
    "vmovdqu	-0x140(%[src],%[off]), %[ymm2]	\n\t"
    "vmovdqu	-0x120(%[src],%[off]), %[ymm3]	\n\t"
    "vmovdqa	%[ymm0], -0x180(%[dst],%[off])	\n\t"
    "vmovdqa	%[ymm1], -0x160(%[dst],%[off])	\n\t"
    "vmovdqa	%[ymm2], -0x140(%[dst],%[off])	\n\t"
    "vmovdqa	%[ymm3], -0x120(%[dst],%[off])	\n\t"
    "add	$0x100, %[off]			\n\t"
    "cmp	%[tmp], %[off]			\n\t"
    "jne	.L_more_%=			\n\t"

    /* check if there is more bytes to copy (256 > n > 0) */
    "and	$0xe0, %[nr]			\n\t"
    "jz		.L_done_%=			\n\t"

    /* VEX encoded unaligned move with base, offset and 32 bit
     * displacement takes 9 bytes so we need to jump back 18 bytes
     * for each 32-byte load/store needed
     */
    "shr	$4, %[nr]			\n\t"
    "lea	(%[nr],%[nr],8), %[nr]		\n\t"
    "lea	.L_done_%=(%%rip), %[tmp]	\n\t"
    "sub	%[nr], %[tmp]			\n\t"
    "jmp	*%[tmp]				\n\t"

    /* n = ((c - 32) / 32) * 18 */
    ".L_skip_main_%=:				\n\t"
    "lea	-33(%[n]), %[nr]		\n\t"
    "and	$0xe0, %[nr]			\n\t"
    "shr	$4, %[nr]			\n\t"
    "lea	(%[nr],%[nr],8), %[nr]		\n\t"
    "lea	.L_done_%=(%%rip), %[tmp]	\n\t"
    "sub	%[nr], %[tmp]			\n\t"
    "jmp	*%[tmp]				\n\t"

    "vmovdqu	-0x140(%[src],%[off]), %[ymm0]	\n\t"
    "vmovdqu	%[ymm0], -0x140(%[dst],%[off])	\n\t"
    "vmovdqu	-0x160(%[src],%[off]), %[ymm0]	\n\t"
    "vmovdqu	%[ymm0], -0x160(%[dst],%[off])	\n\t"
    "vmovdqu	-0x180(%[src],%[off]), %[ymm0]	\n\t"
    "vmovdqu	%[ymm0], -0x180(%[dst],%[off])	\n\t"
    "vmovdqu	-0x1a0(%[src],%[off]), %[ymm0]	\n\t"
    "vmovdqu	%[ymm0], -0x1a0(%[dst],%[off])	\n\t"
    "vmovdqu	-0x1c0(%[src],%[off]), %[ymm0]	\n\t"
    "vmovdqu	%[ymm0], -0x1c0(%[dst],%[off])	\n\t"
    "vmovdqu	-0x1e0(%[src],%[off]), %[ymm0]	\n\t"
    "vmovdqu	%[ymm0], -0x1e0(%[dst],%[off])	\n\t"
    ".L_only_one_%=:				\n\t"
    "vmovdqu	-0x200(%[src],%[off]), %[ymm0]	\n\t"
    "vmovdqu	%[ymm0], -0x200(%[dst],%[off])	\n\t"
    ".L_done_%=:				\n\t"
    /* copy last 32 bytes */
    "vmovdqu	-0x20(%[src],%[n]), %[ymm0]	\n\t"
    "vmovdqu	%[ymm0], -0x20(%[dst],%[n])	\n\t"

    : [ ymm0 ] "=&x"(ymm0), [ ymm1 ] "=&x"(ymm1), [ ymm2 ] "=&x"(ymm2),
      [ ymm3 ] "=&x"(ymm3), [ dst ] "+D"(d), [ src ] "+S"(s), [ n ] "+r"(n),
      [ off ] "=&Q"(off), /* Q = r{a,b,c,d}x, use of r8-15 changes inst len */
      [ tmp ] "=&r"(tmp), [ nr ] "=&r"(nr)
    :
    : "memory");
#else
  u8x16 xmm0, xmm1, xmm2, xmm3;
  u64 off, tmp, nr;
  asm volatile(
    /* copy first 32 bytes */
    "movdqu	(%[src]), %[xmm0]		\n\t"
    "movdqu	%[xmm0], (%[dst])		\n\t"
    "movdqu	0x10(%[src]), %[xmm0]		\n\t"
    "movdqu	%[xmm0], 0x10(%[dst])		\n\t"

    /* do a bit of work in parallel with loads/stores
     *  initial offset is 256 + 32
     *  32 bytes are already copied
     *  256 is used to force 32-bit displacement of vmovdqu
     *  bellow so all load/stores at the end are 9-byte long
     */
    "mov	$0x220, %k[off]			\n\t"

    /* done if n <= 64 */
    "cmp	$0x40,%[n]			\n\t"
    "jbe	.L_done_%=			\n\t"

    /* done if n <= 96 */
    "cmp	$0x60,%[n]			\n\t"
    "jbe	.L_only_two_%=			\n\t"

    /* if n < (256 + 48) skip main loop */
    "cmp	$0x130, %[n]			\n\t"
    "jbe	.L_skip_main_%=			\n\t"

    /* align dst pointer */
    "mov	%[dst], %[tmp]			\n\t"
    "and	$0x0f, %[tmp]			\n\t"
    "sub	%[tmp], %[off]			\n\t"

    /* round n to number of lods/stores left
     * n = (n - 64 + (16 - 1)) & ~0x0f */
    "lea	-49(%[tmp],%[n]), %[nr]		\n\t"

    /* number of bytes to be copied in the main loop
     * tmp = n & ~0xff */
    "mov	%[nr], %[tmp]			\n\t"
    "xor	%b[tmp], %b[tmp]		\n\t"

    /* main loop exit value tmp = tmp + off */
    "add	%[off], %[tmp]			\n\t"

    /* main 256-byte copy loop */
    ".L_more_%=:				\n\t"
    "movdqu	-0x200(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	-0x1f0(%[src],%[off]), %[xmm1]	\n\t"
    "movdqu	-0x1e0(%[src],%[off]), %[xmm2]	\n\t"
    "movdqu	-0x1d0(%[src],%[off]), %[xmm3]	\n\t"
    "movdqa	%[xmm0], -0x200(%[dst],%[off])	\n\t"
    "movdqa	%[xmm1], -0x1f0(%[dst],%[off])	\n\t"
    "movdqa	%[xmm2], -0x1e0(%[dst],%[off])	\n\t"
    "movdqa	%[xmm3], -0x1d0(%[dst],%[off])	\n\t"
    "movdqu	-0x1c0(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	-0x1b0(%[src],%[off]), %[xmm1]	\n\t"
    "movdqu	-0x1a0(%[src],%[off]), %[xmm2]	\n\t"
    "movdqu	-0x190(%[src],%[off]), %[xmm3]	\n\t"
    "movdqa	%[xmm0], -0x1c0(%[dst],%[off])	\n\t"
    "movdqa	%[xmm1], -0x1b0(%[dst],%[off])	\n\t"
    "movdqa	%[xmm2], -0x1a0(%[dst],%[off])	\n\t"
    "movdqa	%[xmm3], -0x190(%[dst],%[off])	\n\t"
    "movdqu	-0x180(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	-0x170(%[src],%[off]), %[xmm1]	\n\t"
    "movdqu	-0x160(%[src],%[off]), %[xmm2]	\n\t"
    "movdqu	-0x150(%[src],%[off]), %[xmm3]	\n\t"
    "movdqa	%[xmm0], -0x180(%[dst],%[off])	\n\t"
    "movdqa	%[xmm1], -0x170(%[dst],%[off])	\n\t"
    "movdqa	%[xmm2], -0x160(%[dst],%[off])	\n\t"
    "movdqa	%[xmm3], -0x150(%[dst],%[off])	\n\t"
    "movdqu	-0x140(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	-0x130(%[src],%[off]), %[xmm1]	\n\t"
    "movdqu	-0x120(%[src],%[off]), %[xmm2]	\n\t"
    "movdqu	-0x110(%[src],%[off]), %[xmm3]	\n\t"
    "movdqa	%[xmm0], -0x140(%[dst],%[off])	\n\t"
    "movdqa	%[xmm1], -0x130(%[dst],%[off])	\n\t"
    "movdqa	%[xmm2], -0x120(%[dst],%[off])	\n\t"
    "movdqa	%[xmm3], -0x110(%[dst],%[off])	\n\t"
    "add	$0x100, %[off]			\n\t"
    "cmp	%[tmp], %[off]			\n\t"
    "jne	.L_more_%=			\n\t"

    /* check if there is more bytes to copy (256 > n > 0) */
    "and	$0xf0, %[nr]			\n\t"
    "jz		.L_done_%=			\n\t"

    /* unaligned move with base, offset and 32 bit
     * displacement takes 9 bytes so we need to jump back 18 bytes
     * for each 16-byte load/store
     */
    "shr	$3, %[nr]			\n\t"
    "lea	(%[nr],%[nr],8), %[nr]		\n\t"
    "lea	.L_done_%=(%%rip), %[tmp]	\n\t"
    "sub	%[nr], %[tmp]			\n\t"
    "jmp	*%[tmp]				\n\t"

    /* n = ((c - 32) / 16) * 18 */
    ".L_skip_main_%=:				\n\t"
    "lea	-49(%[n]), %[nr]		\n\t"
    "and	$0xf0, %[nr]			\n\t"
    "shr	$3, %[nr]			\n\t"
    "lea	(%[nr],%[nr],8), %[nr]		\n\t"
    "lea	.L_done_%=(%%rip), %[tmp]	\n\t"
    "sub	%[nr], %[tmp]			\n\t"
    "jmp	*%[tmp]				\n\t"

    "movdqu	-0x120(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x120(%[dst],%[off])	\n\t"
    "movdqu	-0x130(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x130(%[dst],%[off])	\n\t"
    "movdqu	-0x140(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x140(%[dst],%[off])	\n\t"
    "movdqu	-0x150(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x150(%[dst],%[off])	\n\t"
    "movdqu	-0x160(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x160(%[dst],%[off])	\n\t"
    "movdqu	-0x170(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x170(%[dst],%[off])	\n\t"
    "movdqu	-0x180(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x180(%[dst],%[off])	\n\t"
    "movdqu	-0x190(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x190(%[dst],%[off])	\n\t"
    "movdqu	-0x1a0(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x1a0(%[dst],%[off])	\n\t"
    "movdqu	-0x1b0(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x1b0(%[dst],%[off])	\n\t"
    "movdqu	-0x1c0(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x1c0(%[dst],%[off])	\n\t"
    "movdqu	-0x1d0(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x1d0(%[dst],%[off])	\n\t"
    "movdqu	-0x1e0(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x1e0(%[dst],%[off])	\n\t"
    ".L_only_two_%=:				\n\t"
    "movdqu	-0x1f0(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x1f0(%[dst],%[off])	\n\t"
    ".L_only_one_%=:				\n\t"
    "movdqu	-0x200(%[src],%[off]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x200(%[dst],%[off])	\n\t"
    ".L_done_%=:				\n\t"
    /* copy last 32 bytes */
    "movdqu	-0x20(%[src],%[n]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x20(%[dst],%[n])	\n\t"
    "movdqu	-0x10(%[src],%[n]), %[xmm0]	\n\t"
    "movdqu	%[xmm0], -0x10(%[dst],%[n])	\n\t"

    : [ xmm0 ] "=&x"(xmm0), [ xmm1 ] "=&x"(xmm1), [ xmm2 ] "=&x"(xmm2),
      [ xmm3 ] "=&x"(xmm3), [ dst ] "+D"(d), [ src ] "+S"(s), [ n ] "+r"(n),
      [ off ] "=&Q"(off), /* Q = r{a,b,c,d}x, use of r8-15 changes inst len */
      [ tmp ] "=&r"(tmp), [ nr ] "=&r"(nr)
    :
    : "memory");

#endif
done:
  return dst;
}

#endif
#endif
