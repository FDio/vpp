/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef included_clib_memcpy_avx2_h
#define included_clib_memcpy_avx2_h

#include <stdint.h>
#include <x86intrin.h>

static inline void
clib_mov16 (u8 * dst, const u8 * src)
{
  __m128i xmm0;

  xmm0 = _mm_loadu_si128 ((const __m128i *) src);
  _mm_storeu_si128 ((__m128i *) dst, xmm0);
}

static inline void
clib_mov32 (u8 * dst, const u8 * src)
{
  __m256i ymm0;

  ymm0 = _mm256_loadu_si256 ((const __m256i *) src);
  _mm256_storeu_si256 ((__m256i *) dst, ymm0);
}

static inline void
clib_mov64 (u8 * dst, const u8 * src)
{
  clib_mov32 ((u8 *) dst + 0 * 32, (const u8 *) src + 0 * 32);
  clib_mov32 ((u8 *) dst + 1 * 32, (const u8 *) src + 1 * 32);
}

static inline void
clib_mov128 (u8 * dst, const u8 * src)
{
  clib_mov64 ((u8 *) dst + 0 * 64, (const u8 *) src + 0 * 64);
  clib_mov64 ((u8 *) dst + 1 * 64, (const u8 *) src + 1 * 64);
}

static inline void
clib_mov128blocks (u8 * dst, const u8 * src, size_t n)
{
  __m256i ymm0, ymm1, ymm2, ymm3;

  while (n >= 128)
    {
      ymm0 =
	_mm256_loadu_si256 ((const __m256i *) ((const u8 *) src + 0 * 32));
      n -= 128;
      ymm1 =
	_mm256_loadu_si256 ((const __m256i *) ((const u8 *) src + 1 * 32));
      ymm2 =
	_mm256_loadu_si256 ((const __m256i *) ((const u8 *) src + 2 * 32));
      ymm3 =
	_mm256_loadu_si256 ((const __m256i *) ((const u8 *) src + 3 * 32));
      src = (const u8 *) src + 128;
      _mm256_storeu_si256 ((__m256i *) ((u8 *) dst + 0 * 32), ymm0);
      _mm256_storeu_si256 ((__m256i *) ((u8 *) dst + 1 * 32), ymm1);
      _mm256_storeu_si256 ((__m256i *) ((u8 *) dst + 2 * 32), ymm2);
      _mm256_storeu_si256 ((__m256i *) ((u8 *) dst + 3 * 32), ymm3);
      dst = (u8 *) dst + 128;
    }
}

static inline void *
clib_memcpy (void *dst, const void *src, size_t n)
{
  uword dstu = (uword) dst;
  uword srcu = (uword) src;
  void *ret = dst;
  size_t dstofss;
  size_t bits;

  /**
   * Copy less than 16 bytes
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

  /**
    * Fast way when copy size doesn't exceed 512 bytes
    */
  if (n <= 32)
    {
      clib_mov16 ((u8 *) dst, (const u8 *) src);
      clib_mov16 ((u8 *) dst - 16 + n, (const u8 *) src - 16 + n);
      return ret;
    }
  if (n <= 48)
    {
      clib_mov16 ((u8 *) dst, (const u8 *) src);
      clib_mov16 ((u8 *) dst + 16, (const u8 *) src + 16);
      clib_mov16 ((u8 *) dst - 16 + n, (const u8 *) src - 16 + n);
      return ret;
    }
  if (n <= 64)
    {
      clib_mov32 ((u8 *) dst, (const u8 *) src);
      clib_mov32 ((u8 *) dst - 32 + n, (const u8 *) src - 32 + n);
      return ret;
    }
  if (n <= 256)
    {
      if (n >= 128)
	{
	  n -= 128;
	  clib_mov128 ((u8 *) dst, (const u8 *) src);
	  src = (const u8 *) src + 128;
	  dst = (u8 *) dst + 128;
	}
    COPY_BLOCK_128_BACK31:
      if (n >= 64)
	{
	  n -= 64;
	  clib_mov64 ((u8 *) dst, (const u8 *) src);
	  src = (const u8 *) src + 64;
	  dst = (u8 *) dst + 64;
	}
      if (n > 32)
	{
	  clib_mov32 ((u8 *) dst, (const u8 *) src);
	  clib_mov32 ((u8 *) dst - 32 + n, (const u8 *) src - 32 + n);
	  return ret;
	}
      if (n > 0)
	{
	  clib_mov32 ((u8 *) dst - 32 + n, (const u8 *) src - 32 + n);
	}
      return ret;
    }

    /**
      * Make store aligned when copy size exceeds 256 bytes
      */
  dstofss = (uword) dst & 0x1F;
  if (dstofss > 0)
    {
      dstofss = 32 - dstofss;
      n -= dstofss;
      clib_mov32 ((u8 *) dst, (const u8 *) src);
      src = (const u8 *) src + dstofss;
      dst = (u8 *) dst + dstofss;
    }

  /**
    * Copy 128-byte blocks.
    */
  clib_mov128blocks ((u8 *) dst, (const u8 *) src, n);
  bits = n;
  n = n & 127;
  bits -= n;
  src = (const u8 *) src + bits;
  dst = (u8 *) dst + bits;

  /**
   * Copy whatever left
   */
  goto COPY_BLOCK_128_BACK31;
}


#endif /* included_clib_memcpy_avx2_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
