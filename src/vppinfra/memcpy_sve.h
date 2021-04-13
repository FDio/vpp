/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
 * Copyright (c) 2021 Arm Limited. and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_clib_memcpy_sve_h
#define included_clib_memcpy_sve_h

#include <stdint.h>
#include <arm_sve.h>
#include "vppinfra/warnings.h"

#ifndef MEMCPY_OPTIONS
#define MEMCPY_OPTIONS 3 // 0/1/2/3
#endif

// There are several options: 0 means using memcpy from glibc
#if 0 == MEMCPY_OPTIONS
#define clib_memcpy_fast(a, b, c) memcpy (a, b, c)

#else

// There are several options: 1 means using NEON instructions,
// and each NEON instruction operates only one vector register.
#if 1 == MEMCPY_OPTIONS
#define USING_STPLDP	  0
#define USING_NEON_multi  0
#define USING_NEON_single 1
// There are several options: 2 means using NEON instrunctions also,
// but the NEON instruction may operate one or four vector registers.
#elif 2 == MEMCPY_OPTIONS
#define USING_STPLDP	  0
#define USING_NEON_multi  1
#define USING_NEON_single 0
#elif 3 == MEMCPY_OPTIONS
// There are several options: 3 means using STP/LDP instrunctions.
#define USING_STPLDP	  1
#define USING_NEON_multi  0
#define USING_NEON_single 0
#endif

static inline void
clib_mov16 (u8 *dst, const u8 *src)
{
#if USING_STPLDP
  __uint128_t *dst128 = (__uint128_t *) dst;
  const __uint128_t *src128 = (const __uint128_t *) src;
  *dst128 = *src128;
#else
  vst1q_u8 (dst, vld1q_u8 (src));
#endif
}

static inline void
clib_mov32 (u8 *dst, const u8 *src)
{
#if USING_STPLDP
  __uint128_t *dst128 = (__uint128_t *) dst;
  const __uint128_t *src128 = (const __uint128_t *) src;
  const __uint128_t x0 = src128[0], x1 = src128[1];
  dst128[0] = x0;
  dst128[1] = x1;
#else
#if USING_NEON_single
  clib_mov16 ((u8 *) dst + 0 * 16, (const u8 *) src + 0 * 16);
  WARN_OFF (array - bounds)
  clib_mov16 ((u8 *) dst + 1 * 16, (const u8 *) src + 1 * 16);
  WARN_ON (array - bounds)
#endif
#if USING_NEON_multi
  vst2q_u8 (dst, vld2q_u8 (src));
#endif
#endif
}

static inline void
clib_mov64 (u8 *dst, const u8 *src)
{
#if USING_STPLDP
  __uint128_t *dst128 = (__uint128_t *) dst;
  const __uint128_t *src128 = (const __uint128_t *) src;
  const __uint128_t x0 = src128[0];
  const __uint128_t x1 = src128[1];
  const __uint128_t x2 = src128[2];
  const __uint128_t x3 = src128[3];
  dst128[0] = x0;
  dst128[1] = x1;
  dst128[2] = x2;
  dst128[3] = x3;
#else
#if USING_NEON_single
  clib_mov32 ((u8 *) dst + 0 * 32, (const u8 *) src + 0 * 32);
  clib_mov32 ((u8 *) dst + 1 * 32, (const u8 *) src + 1 * 32);
#endif
#if USING_NEON_multi
  vst4q_u8 (dst, vld4q_u8 (src));
#endif
#endif
}

static inline void
clib_mov128 (u8 *dst, const u8 *src)
{
#if USING_STPLDP
  __uint128_t *dst128 = (__uint128_t *) dst;
  const __uint128_t *src128 = (const __uint128_t *) src;
  /* Keep below declaration & copy sequence for optimized instructions */
  const __uint128_t x0 = src128[0];
  const __uint128_t x1 = src128[1];
  const __uint128_t x2 = src128[2];
  const __uint128_t x3 = src128[3];
  dst128[0] = x0;
  __uint128_t x4 = src128[4];
  dst128[1] = x1;
  __uint128_t x5 = src128[5];
  dst128[2] = x2;
  __uint128_t x6 = src128[6];
  dst128[3] = x3;
  __uint128_t x7 = src128[7];
  dst128[4] = x4;
  dst128[5] = x5;
  dst128[6] = x6;
  dst128[7] = x7;
#else
  clib_mov64 ((u8 *) dst + 0 * 64, (const u8 *) src + 0 * 64);
  clib_mov64 ((u8 *) dst + 1 * 64, (const u8 *) src + 1 * 64);
#endif
}

static inline void
clib_mov64blocks (u8 *dst, const u8 *src, size_t n)
{
  while (n >= 64)
    {
      clib_mov64 ((u8 *) dst + 0 * 64, (const u8 *) src + 0 * 64);
      n -= 64;
      src = (const u8 *) src + 64;
      dst = (u8 *) dst + 64;
    }
}

static inline void
clib_mov128blocks (u8 *dst, const u8 *src, size_t n)
{
  while (n >= 128)
    {
      clib_mov64 ((u8 *) dst + 0 * 64, (const u8 *) src + 0 * 64);
      clib_mov64 ((u8 *) dst + 1 * 64, (const u8 *) src + 1 * 64);
      n -= 128;
      src = (const u8 *) src + 128;
      dst = (u8 *) dst + 128;
    }
}

static inline void *
clib_memcpy_fast_sve (void *dst, const void *src, size_t n)
{
  uword dstu = (uword) dst;
  uword srcu = (uword) src;
  void *ret = dst;
  size_t dstofss;
  size_t bits;

  /**
   * copy less than 16 bytes
   */
  if (n < 16)
    {
      if (n & 0x01)
	{
	  *(u8 *) dstu = *(const u8 *) srcu;
	  srcu = (uword) ((const u8 *) srcu + 1);
	  dstu = (uword) ((u8 *) dstu + 1);
	}
      if (n & 0x02)
	{
	  *(u16 *) dstu = *(const u16 *) srcu;
	  srcu = (uword) ((const u16 *) srcu + 1);
	  dstu = (uword) ((u16 *) dstu + 1);
	}
      if (n & 0x04)
	{
	  *(u32 *) dstu = *(const u32 *) srcu;
	  srcu = (uword) ((const u32 *) srcu + 1);
	  dstu = (uword) ((u32 *) dstu + 1);
	}
      if (n & 0x08)
	{
	  *(u64 *) dstu = *(const u64 *) srcu;
	}
      return ret;
    }

  /* fast way */
  if (n <= 32)
    {
      clib_mov16 ((u8 *) dst, (const u8 *) src);
      clib_mov16 ((u8 *) dst - 16 + n, (const u8 *) src - 16 + n);
      return ret;
    }
  else if (n <= 64)
    {
      clib_mov32 ((u8 *) dst, (const u8 *) src);
      clib_mov32 ((u8 *) dst - 32 + n, (const u8 *) src - 32 + n);
      return ret;
    }
  else
    {
      /**
       * make store aligned when copy size exceeds 64 bytes
       */
      dstofss = (uword) dst & 0x0F;
      if (dstofss > 0)
	{
	  dstofss = 16 - dstofss;
	  n -= dstofss;
	  clib_mov16 ((u8 *) dst, (const u8 *) src);
	  src = (const u8 *) src + dstofss;
	  dst = (u8 *) dst + dstofss;
	}

      /**
       * copy SVE-vector-length-byte blocks.
       */
      i32 i = 0;
      i32 eno = (i32) svcntb ();
      boolxn m;
      while (i < n)
	{
	  m = u8xn_elt_mask (i, n);
	  svst1_u8 (m, dst + i, svld1_u8 (m, src + i));
	  i += eno;
	}

      return ret;
    }
}

#endif // 0 == MEMCPY_OPTIONS

#endif /* included_clib_memcpy_sve_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
