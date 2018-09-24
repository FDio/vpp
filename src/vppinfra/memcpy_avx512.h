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

#ifndef included_clib_memcpy_avx512_h
#define included_clib_memcpy_avx512_h

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
  __m512i zmm0;

  zmm0 = _mm512_loadu_si512 ((const void *) src);
  _mm512_storeu_si512 ((void *) dst, zmm0);
}

static inline void
clib_mov128 (u8 * dst, const u8 * src)
{
  clib_mov64 (dst + 0 * 64, src + 0 * 64);
  clib_mov64 (dst + 1 * 64, src + 1 * 64);
}

static inline void
clib_mov256 (u8 * dst, const u8 * src)
{
  clib_mov128 (dst + 0 * 128, src + 0 * 128);
  clib_mov128 (dst + 1 * 128, src + 1 * 128);
}

static inline void
clib_mov128blocks (u8 * dst, const u8 * src, size_t n)
{
  __m512i zmm0, zmm1;

  while (n >= 128)
    {
      zmm0 = _mm512_loadu_si512 ((const void *) (src + 0 * 64));
      n -= 128;
      zmm1 = _mm512_loadu_si512 ((const void *) (src + 1 * 64));
      src = src + 128;
      _mm512_storeu_si512 ((void *) (dst + 0 * 64), zmm0);
      _mm512_storeu_si512 ((void *) (dst + 1 * 64), zmm1);
      dst = dst + 128;
    }
}

static inline void
clib_mov512blocks (u8 * dst, const u8 * src, size_t n)
{
  __m512i zmm0, zmm1, zmm2, zmm3, zmm4, zmm5, zmm6, zmm7;

  while (n >= 512)
    {
      zmm0 = _mm512_loadu_si512 ((const void *) (src + 0 * 64));
      n -= 512;
      zmm1 = _mm512_loadu_si512 ((const void *) (src + 1 * 64));
      zmm2 = _mm512_loadu_si512 ((const void *) (src + 2 * 64));
      zmm3 = _mm512_loadu_si512 ((const void *) (src + 3 * 64));
      zmm4 = _mm512_loadu_si512 ((const void *) (src + 4 * 64));
      zmm5 = _mm512_loadu_si512 ((const void *) (src + 5 * 64));
      zmm6 = _mm512_loadu_si512 ((const void *) (src + 6 * 64));
      zmm7 = _mm512_loadu_si512 ((const void *) (src + 7 * 64));
      src = src + 512;
      _mm512_storeu_si512 ((void *) (dst + 0 * 64), zmm0);
      _mm512_storeu_si512 ((void *) (dst + 1 * 64), zmm1);
      _mm512_storeu_si512 ((void *) (dst + 2 * 64), zmm2);
      _mm512_storeu_si512 ((void *) (dst + 3 * 64), zmm3);
      _mm512_storeu_si512 ((void *) (dst + 4 * 64), zmm4);
      _mm512_storeu_si512 ((void *) (dst + 5 * 64), zmm5);
      _mm512_storeu_si512 ((void *) (dst + 6 * 64), zmm6);
      _mm512_storeu_si512 ((void *) (dst + 7 * 64), zmm7);
      dst = dst + 512;
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
	*(u64 *) dstu = *(const u64 *) srcu;
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
  if (n <= 64)
    {
      clib_mov32 ((u8 *) dst, (const u8 *) src);
      clib_mov32 ((u8 *) dst - 32 + n, (const u8 *) src - 32 + n);
      return ret;
    }
  if (n <= 512)
    {
      if (n >= 256)
	{
	  n -= 256;
	  clib_mov256 ((u8 *) dst, (const u8 *) src);
	  src = (const u8 *) src + 256;
	  dst = (u8 *) dst + 256;
	}
      if (n >= 128)
	{
	  n -= 128;
	  clib_mov128 ((u8 *) dst, (const u8 *) src);
	  src = (const u8 *) src + 128;
	  dst = (u8 *) dst + 128;
	}
    COPY_BLOCK_128_BACK63:
      if (n > 64)
	{
	  clib_mov64 ((u8 *) dst, (const u8 *) src);
	  clib_mov64 ((u8 *) dst - 64 + n, (const u8 *) src - 64 + n);
	  return ret;
	}
      if (n > 0)
	clib_mov64 ((u8 *) dst - 64 + n, (const u8 *) src - 64 + n);
      return ret;
    }

	/**
         * Make store aligned when copy size exceeds 512 bytes
         */
  dstofss = (uword) dst & 0x3F;
  if (dstofss > 0)
    {
      dstofss = 64 - dstofss;
      n -= dstofss;
      clib_mov64 ((u8 *) dst, (const u8 *) src);
      src = (const u8 *) src + dstofss;
      dst = (u8 *) dst + dstofss;
    }

	/**
         * Copy 512-byte blocks.
         * Use copy block function for better instruction order control,
         * which is important when load is unaligned.
         */
  clib_mov512blocks ((u8 *) dst, (const u8 *) src, n);
  bits = n;
  n = n & 511;
  bits -= n;
  src = (const u8 *) src + bits;
  dst = (u8 *) dst + bits;

	/**
         * Copy 128-byte blocks.
         * Use copy block function for better instruction order control,
         * which is important when load is unaligned.
         */
  if (n >= 128)
    {
      clib_mov128blocks ((u8 *) dst, (const u8 *) src, n);
      bits = n;
      n = n & 127;
      bits -= n;
      src = (const u8 *) src + bits;
      dst = (u8 *) dst + bits;
    }

	/**
         * Copy whatever left
         */
  goto COPY_BLOCK_128_BACK63;
}


#endif /* included_clib_memcpy_avx512_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
