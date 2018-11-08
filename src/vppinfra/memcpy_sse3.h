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

#ifndef included_clib_memcpy_sse3_h
#define included_clib_memcpy_sse3_h

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
  clib_mov16 ((u8 *) dst + 0 * 16, (const u8 *) src + 0 * 16);
  clib_mov16 ((u8 *) dst + 1 * 16, (const u8 *) src + 1 * 16);
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
clib_mov256 (u8 * dst, const u8 * src)
{
  clib_mov128 ((u8 *) dst + 0 * 128, (const u8 *) src + 0 * 128);
  clib_mov128 ((u8 *) dst + 1 * 128, (const u8 *) src + 1 * 128);
}

/**
 * Macro for copying unaligned block from one location to another with constant load offset,
 * 47 bytes leftover maximum,
 * locations should not overlap.
 * Requirements:
 * - Store is aligned
 * - Load offset is <offset>, which must be immediate value within [1, 15]
 * - For <src>, make sure <offset> bit backwards & <16 - offset> bit forwards are available for loading
 * - <dst>, <src>, <len> must be variables
 * - __m128i <xmm0> ~ <xmm8> must be pre-defined
 */
#define CLIB_MVUNALIGN_LEFT47_IMM(dst, src, len, offset)                                                    \
({                                                                                                          \
    int tmp;                                                                                                \
    while (len >= 128 + 16 - offset) {                                                                      \
        xmm0 = _mm_loadu_si128((const __m128i *)((const u8 *)src - offset + 0 * 16));                       \
        len -= 128;                                                                                         \
        xmm1 = _mm_loadu_si128((const __m128i *)((const u8 *)src - offset + 1 * 16));                       \
        xmm2 = _mm_loadu_si128((const __m128i *)((const u8 *)src - offset + 2 * 16));                       \
        xmm3 = _mm_loadu_si128((const __m128i *)((const u8 *)src - offset + 3 * 16));                       \
        xmm4 = _mm_loadu_si128((const __m128i *)((const u8 *)src - offset + 4 * 16));                       \
        xmm5 = _mm_loadu_si128((const __m128i *)((const u8 *)src - offset + 5 * 16));                       \
        xmm6 = _mm_loadu_si128((const __m128i *)((const u8 *)src - offset + 6 * 16));                       \
        xmm7 = _mm_loadu_si128((const __m128i *)((const u8 *)src - offset + 7 * 16));                       \
        xmm8 = _mm_loadu_si128((const __m128i *)((const u8 *)src - offset + 8 * 16));                       \
        src = (const u8 *)src + 128;                                                                        \
        _mm_storeu_si128((__m128i *)((u8 *)dst + 0 * 16), _mm_alignr_epi8(xmm1, xmm0, offset));             \
        _mm_storeu_si128((__m128i *)((u8 *)dst + 1 * 16), _mm_alignr_epi8(xmm2, xmm1, offset));             \
        _mm_storeu_si128((__m128i *)((u8 *)dst + 2 * 16), _mm_alignr_epi8(xmm3, xmm2, offset));             \
        _mm_storeu_si128((__m128i *)((u8 *)dst + 3 * 16), _mm_alignr_epi8(xmm4, xmm3, offset));             \
        _mm_storeu_si128((__m128i *)((u8 *)dst + 4 * 16), _mm_alignr_epi8(xmm5, xmm4, offset));             \
        _mm_storeu_si128((__m128i *)((u8 *)dst + 5 * 16), _mm_alignr_epi8(xmm6, xmm5, offset));             \
        _mm_storeu_si128((__m128i *)((u8 *)dst + 6 * 16), _mm_alignr_epi8(xmm7, xmm6, offset));             \
        _mm_storeu_si128((__m128i *)((u8 *)dst + 7 * 16), _mm_alignr_epi8(xmm8, xmm7, offset));             \
        dst = (u8 *)dst + 128;                                                                              \
    }                                                                                                       \
    tmp = len;                                                                                              \
    len = ((len - 16 + offset) & 127) + 16 - offset;                                                        \
    tmp -= len;                                                                                             \
    src = (const u8 *)src + tmp;                                                                            \
    dst = (u8 *)dst + tmp;                                                                                  \
    if (len >= 32 + 16 - offset) {                                                                          \
        while (len >= 32 + 16 - offset) {                                                                   \
            xmm0 = _mm_loadu_si128((const __m128i *)((const u8 *)src - offset + 0 * 16));                   \
            len -= 32;                                                                                      \
            xmm1 = _mm_loadu_si128((const __m128i *)((const u8 *)src - offset + 1 * 16));                   \
            xmm2 = _mm_loadu_si128((const __m128i *)((const u8 *)src - offset + 2 * 16));                   \
            src = (const u8 *)src + 32;                                                                     \
            _mm_storeu_si128((__m128i *)((u8 *)dst + 0 * 16), _mm_alignr_epi8(xmm1, xmm0, offset));         \
            _mm_storeu_si128((__m128i *)((u8 *)dst + 1 * 16), _mm_alignr_epi8(xmm2, xmm1, offset));         \
            dst = (u8 *)dst + 32;                                                                           \
        }                                                                                                   \
        tmp = len;                                                                                          \
        len = ((len - 16 + offset) & 31) + 16 - offset;                                                     \
        tmp -= len;                                                                                         \
        src = (const u8 *)src + tmp;                                                                        \
        dst = (u8 *)dst + tmp;                                                                              \
    }                                                                                                       \
})

/**
 * Macro for copying unaligned block from one location to another,
 * 47 bytes leftover maximum,
 * locations should not overlap.
 * Use switch here because the aligning instruction requires immediate value for shift count.
 * Requirements:
 * - Store is aligned
 * - Load offset is <offset>, which must be within [1, 15]
 * - For <src>, make sure <offset> bit backwards & <16 - offset> bit forwards are available for loading
 * - <dst>, <src>, <len> must be variables
 * - __m128i <xmm0> ~ <xmm8> used in CLIB_MVUNALIGN_LEFT47_IMM must be pre-defined
 */
#define CLIB_MVUNALIGN_LEFT47(dst, src, len, offset)                  \
({                                                                    \
    switch (offset) {                                                 \
    case 0x01: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x01); break;   \
    case 0x02: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x02); break;   \
    case 0x03: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x03); break;   \
    case 0x04: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x04); break;   \
    case 0x05: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x05); break;   \
    case 0x06: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x06); break;   \
    case 0x07: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x07); break;   \
    case 0x08: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x08); break;   \
    case 0x09: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x09); break;   \
    case 0x0A: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x0A); break;   \
    case 0x0B: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x0B); break;   \
    case 0x0C: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x0C); break;   \
    case 0x0D: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x0D); break;   \
    case 0x0E: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x0E); break;   \
    case 0x0F: CLIB_MVUNALIGN_LEFT47_IMM(dst, src, n, 0x0F); break;   \
    default:;                                                         \
    }                                                                 \
})

static inline void *
_clib_memcpy (void *dst, const void *src, size_t n)
{
  __m128i xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8;
  uword dstu = (uword) dst;
  uword srcu = (uword) src;
  void *ret = dst;
  size_t dstofss;
  size_t srcofs;

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
      clib_mov32 ((u8 *) dst, (const u8 *) src);
      clib_mov16 ((u8 *) dst - 16 + n, (const u8 *) src - 16 + n);
      return ret;
    }
  if (n <= 64)
    {
      clib_mov32 ((u8 *) dst, (const u8 *) src);
      clib_mov16 ((u8 *) dst + 32, (const u8 *) src + 32);
      clib_mov16 ((u8 *) dst - 16 + n, (const u8 *) src - 16 + n);
      return ret;
    }
  if (n <= 128)
    {
      goto COPY_BLOCK_128_BACK15;
    }
  if (n <= 512)
    {
      if (n >= 256)
	{
	  n -= 256;
	  clib_mov128 ((u8 *) dst, (const u8 *) src);
	  clib_mov128 ((u8 *) dst + 128, (const u8 *) src + 128);
	  src = (const u8 *) src + 256;
	  dst = (u8 *) dst + 256;
	}
    COPY_BLOCK_255_BACK15:
      if (n >= 128)
	{
	  n -= 128;
	  clib_mov128 ((u8 *) dst, (const u8 *) src);
	  src = (const u8 *) src + 128;
	  dst = (u8 *) dst + 128;
	}
    COPY_BLOCK_128_BACK15:
      if (n >= 64)
	{
	  n -= 64;
	  clib_mov64 ((u8 *) dst, (const u8 *) src);
	  src = (const u8 *) src + 64;
	  dst = (u8 *) dst + 64;
	}
    COPY_BLOCK_64_BACK15:
      if (n >= 32)
	{
	  n -= 32;
	  clib_mov32 ((u8 *) dst, (const u8 *) src);
	  src = (const u8 *) src + 32;
	  dst = (u8 *) dst + 32;
	}
      if (n > 16)
	{
	  clib_mov16 ((u8 *) dst, (const u8 *) src);
	  clib_mov16 ((u8 *) dst - 16 + n, (const u8 *) src - 16 + n);
	  return ret;
	}
      if (n > 0)
	{
	  clib_mov16 ((u8 *) dst - 16 + n, (const u8 *) src - 16 + n);
	}
      return ret;
    }

  /**
   * Make store aligned when copy size exceeds 512 bytes,
   * and make sure the first 15 bytes are copied, because
   * unaligned copy functions require up to 15 bytes
   * backwards access.
   */
  dstofss = (uword) dst & 0x0F;
  if (dstofss > 0)
    {
      dstofss = 16 - dstofss + 16;
      n -= dstofss;
      clib_mov32 ((u8 *) dst, (const u8 *) src);
      src = (const u8 *) src + dstofss;
      dst = (u8 *) dst + dstofss;
    }
  srcofs = ((uword) src & 0x0F);

  /**
   * For aligned copy
   */
  if (srcofs == 0)
    {
      /**
       * Copy 256-byte blocks
       */
      for (; n >= 256; n -= 256)
	{
	  clib_mov256 ((u8 *) dst, (const u8 *) src);
	  dst = (u8 *) dst + 256;
	  src = (const u8 *) src + 256;
	}

      /**
       * Copy whatever left
       */
      goto COPY_BLOCK_255_BACK15;
    }

  /**
   * For copy with unaligned load
   */
  CLIB_MVUNALIGN_LEFT47 (dst, src, n, srcofs);

  /**
   * Copy whatever left
   */
  goto COPY_BLOCK_64_BACK15;
}


#undef CLIB_MVUNALIGN_LEFT47_IMM
#undef CLIB_MVUNALIGN_LEFT47

#endif /* included_clib_memcpy_sse3_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
