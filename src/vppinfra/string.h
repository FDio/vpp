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
/*
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef included_clib_string_h
#define included_clib_string_h

#include <vppinfra/clib.h>	/* for CLIB_LINUX_KERNEL */
#include <vppinfra/vector.h>

#ifdef CLIB_LINUX_KERNEL
#include <linux/string.h>
#endif

#ifdef CLIB_UNIX
#include <string.h>
#endif

#ifdef CLIB_STANDALONE
#include <vppinfra/standalone_string.h>
#endif

#if _x86_64_
#include <x86intrin.h>
#endif

/* Exchanges source and destination. */
void clib_memswap (void *_a, void *_b, uword bytes);

/*
 * the vector unit memcpy variants confuse coverity
 * so don't let it anywhere near them.
 */
#ifndef __COVERITY__
#if __AVX512F__
#include <vppinfra/memcpy_avx512.h>
#elif __AVX2__
#include <vppinfra/memcpy_avx2.h>
#elif __SSSE3__
#include <vppinfra/memcpy_sse3.h>
#else
#define clib_memcpy(a,b,c) memcpy(a,b,c)
#endif
#else /* __COVERITY__ */
#define clib_memcpy(a,b,c) memcpy(a,b,c)
#endif

/*
 * Copy 64 bytes of data to 4 destinations
 * this function is typically used in quad-loop case when whole cacheline
 * needs to be copied to 4 different places. First it reads whole cacheline
 * to 1/2/4 SIMD registers and then it writes data to 4 destinations.
 */

static_always_inline void
clib_memcpy64_x4 (void *d0, void *d1, void *d2, void *d3, void *s)
{
#if defined (__AVX512F__)
  __m512i r0 = _mm512_loadu_si512 (s);

  _mm512_storeu_si512 (d0, r0);
  _mm512_storeu_si512 (d1, r0);
  _mm512_storeu_si512 (d2, r0);
  _mm512_storeu_si512 (d3, r0);

#elif defined (__AVX2__)
  __m256i r0 = _mm256_loadu_si256 ((__m256i *) (s + 0 * 32));
  __m256i r1 = _mm256_loadu_si256 ((__m256i *) (s + 1 * 32));

  _mm256_storeu_si256 ((__m256i *) (d0 + 0 * 32), r0);
  _mm256_storeu_si256 ((__m256i *) (d0 + 1 * 32), r1);

  _mm256_storeu_si256 ((__m256i *) (d1 + 0 * 32), r0);
  _mm256_storeu_si256 ((__m256i *) (d1 + 1 * 32), r1);

  _mm256_storeu_si256 ((__m256i *) (d2 + 0 * 32), r0);
  _mm256_storeu_si256 ((__m256i *) (d2 + 1 * 32), r1);

  _mm256_storeu_si256 ((__m256i *) (d3 + 0 * 32), r0);
  _mm256_storeu_si256 ((__m256i *) (d3 + 1 * 32), r1);

#elif defined (__SSSE3__)
  __m128i r0 = _mm_loadu_si128 ((__m128i *) (s + 0 * 16));
  __m128i r1 = _mm_loadu_si128 ((__m128i *) (s + 1 * 16));
  __m128i r2 = _mm_loadu_si128 ((__m128i *) (s + 2 * 16));
  __m128i r3 = _mm_loadu_si128 ((__m128i *) (s + 3 * 16));

  _mm_storeu_si128 ((__m128i *) (d0 + 0 * 16), r0);
  _mm_storeu_si128 ((__m128i *) (d0 + 1 * 16), r1);
  _mm_storeu_si128 ((__m128i *) (d0 + 2 * 16), r2);
  _mm_storeu_si128 ((__m128i *) (d0 + 3 * 16), r3);

  _mm_storeu_si128 ((__m128i *) (d1 + 0 * 16), r0);
  _mm_storeu_si128 ((__m128i *) (d1 + 1 * 16), r1);
  _mm_storeu_si128 ((__m128i *) (d1 + 2 * 16), r2);
  _mm_storeu_si128 ((__m128i *) (d1 + 3 * 16), r3);

  _mm_storeu_si128 ((__m128i *) (d2 + 0 * 16), r0);
  _mm_storeu_si128 ((__m128i *) (d2 + 1 * 16), r1);
  _mm_storeu_si128 ((__m128i *) (d2 + 2 * 16), r2);
  _mm_storeu_si128 ((__m128i *) (d2 + 3 * 16), r3);

  _mm_storeu_si128 ((__m128i *) (d3 + 0 * 16), r0);
  _mm_storeu_si128 ((__m128i *) (d3 + 1 * 16), r1);
  _mm_storeu_si128 ((__m128i *) (d3 + 2 * 16), r2);
  _mm_storeu_si128 ((__m128i *) (d3 + 3 * 16), r3);

#else
  clib_memcpy (d0, s, 64);
  clib_memcpy (d1, s, 64);
  clib_memcpy (d2, s, 64);
  clib_memcpy (d3, s, 64);
#endif
}

static_always_inline void
clib_memset_u64 (void *p, u64 val, uword count)
{
  u64 *ptr = p;
#if defined(CLIB_HAVE_VEC512)
  u64x8 v512 = u64x8_splat (val);
  while (count >= 8)
    {
      u64x8_store_unaligned (v512, ptr);
      ptr += 8;
      count -= 8;
    }
  if (count == 0)
    return;
#endif
#if defined(CLIB_HAVE_VEC256)
  u64x4 v256 = u64x4_splat (val);
  while (count >= 4)
    {
      u64x4_store_unaligned (v256, ptr);
      ptr += 4;
      count -= 4;
    }
  if (count == 0)
    return;
#else
  while (count >= 4)
    {
      ptr[0] = ptr[1] = ptr[2] = ptr[3] = val;
      ptr += 4;
      count -= 4;
    }
#endif
  while (count--)
    ptr++[0] = val;
}

static_always_inline void
clib_memset_u32 (void *p, u32 val, uword count)
{
  u32 *ptr = p;
#if defined(CLIB_HAVE_VEC512)
  u32x16 v512 = u32x16_splat (val);
  while (count >= 16)
    {
      u32x16_store_unaligned (v512, ptr);
      ptr += 16;
      count -= 16;
    }
  if (count == 0)
    return;
#endif
#if defined(CLIB_HAVE_VEC256)
  u32x8 v256 = u32x8_splat (val);
  while (count >= 8)
    {
      u32x8_store_unaligned (v256, ptr);
      ptr += 8;
      count -= 8;
    }
  if (count == 0)
    return;
#endif
#if defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  u32x4 v128 = u32x4_splat (val);
  while (count >= 4)
    {
      u32x4_store_unaligned (v128, ptr);
      ptr += 4;
      count -= 4;
    }
#else
  while (count >= 4)
    {
      ptr[0] = ptr[1] = ptr[2] = ptr[3] = val;
      ptr += 4;
      count -= 4;
    }
#endif
  while (count--)
    ptr++[0] = val;
}

static_always_inline void
clib_memset_u16 (void *p, u16 val, uword count)
{
  u16 *ptr = p;
#if defined(CLIB_HAVE_VEC512)
  u16x32 v512 = u16x32_splat (val);
  while (count >= 32)
    {
      u16x32_store_unaligned (v512, ptr);
      ptr += 32;
      count -= 32;
    }
  if (count == 0)
    return;
#endif
#if defined(CLIB_HAVE_VEC256)
  u16x16 v256 = u16x16_splat (val);
  while (count >= 16)
    {
      u16x16_store_unaligned (v256, ptr);
      ptr += 16;
      count -= 16;
    }
  if (count == 0)
    return;
#endif
#if defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  u16x8 v128 = u16x8_splat (val);
  while (count >= 8)
    {
      u16x8_store_unaligned (v128, ptr);
      ptr += 8;
      count -= 8;
    }
#else
  while (count >= 4)
    {
      ptr[0] = ptr[1] = ptr[2] = ptr[3] = val;
      ptr += 4;
      count -= 4;
    }
#endif
  while (count--)
    ptr++[0] = val;
}

static_always_inline void
clib_memset_u8 (void *p, u8 val, uword count)
{
  u8 *ptr = p;
#if defined(CLIB_HAVE_VEC512)
  u8x64 v512 = u8x64_splat (val);
  while (count >= 64)
    {
      u8x64_store_unaligned (v512, ptr);
      ptr += 64;
      count -= 64;
    }
  if (count == 0)
    return;
#endif
#if defined(CLIB_HAVE_VEC256)
  u8x32 v256 = u8x32_splat (val);
  while (count >= 32)
    {
      u8x32_store_unaligned (v256, ptr);
      ptr += 32;
      count -= 32;
    }
  if (count == 0)
    return;
#endif
#if defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  u8x16 v128 = u8x16_splat (val);
  while (count >= 16)
    {
      u8x16_store_unaligned (v128, ptr);
      ptr += 16;
      count -= 16;
    }
#else
  while (count >= 4)
    {
      ptr[0] = ptr[1] = ptr[2] = ptr[3] = val;
      ptr += 4;
      count -= 4;
    }
#endif
  while (count--)
    ptr++[0] = val;
}

static_always_inline uword
clib_count_equal_u64 (u64 * data, uword max_count)
{
  uword count = 0;
  u64 first = data[0];

#if defined(CLIB_HAVE_VEC512)
  while (u64x8_is_all_equal (u64x8_load_unaligned (data), first))
    {
      data += 8;
      count += 8;
      if (count >= max_count)
	return max_count;
    }
#endif
#if defined(CLIB_HAVE_VEC256)
  while (u64x4_is_all_equal (u64x4_load_unaligned (data), first))
    {
      data += 4;
      count += 4;
      if (count >= max_count)
	return max_count;
    }
#endif
#if defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  while (u64x2_is_all_equal (u64x2_load_unaligned (data), first))
    {
      data += 2;
      count += 2;
      if (count >= max_count)
	return max_count;
    }
#endif
  while (count < max_count && (data[0] == first))
    {
      data += 1;
      count += 1;
    }
  return count;
}

static_always_inline uword
clib_count_equal_u32 (u32 * data, uword max_count)
{
  uword count = 0;
  u32 first = data[0];

#if defined(CLIB_HAVE_VEC512)
  while (u32x16_is_all_equal (u32x16_load_unaligned (data), first))
    {
      data += 16;
      count += 16;
      if (count >= max_count)
	return max_count;
    }
#endif
#if defined(CLIB_HAVE_VEC256)
  while (u32x8_is_all_equal (u32x8_load_unaligned (data), first))
    {
      data += 8;
      count += 8;
      if (count >= max_count)
	return max_count;
    }
#endif
#if defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  while (u32x4_is_all_equal (u32x4_load_unaligned (data), first))
    {
      data += 4;
      count += 4;
      if (count >= max_count)
	return max_count;
    }
#endif
  while (count < max_count && (data[0] == first))
    {
      data += 1;
      count += 1;
    }
  return count;
}

static_always_inline uword
clib_count_equal_u16 (u16 * data, uword max_count)
{
  uword count = 0;
  u16 first = data[0];

#if defined(CLIB_HAVE_VEC512)
  while (count + 32 <= max_count &&
	 u16x32_is_all_equal (u16x32_load_unaligned (data), first))
    {
      data += 32;
      count += 32;
    }
#endif
#if defined(CLIB_HAVE_VEC256)
  while (count + 16 <= max_count &&
	 u16x16_is_all_equal (u16x16_load_unaligned (data), first))
    {
      data += 16;
      count += 16;
    }
#endif
#if defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  while (count + 8 <= max_count &&
	 u16x8_is_all_equal (u16x8_load_unaligned (data), first))
    {
      data += 8;
      count += 8;
    }
#endif
  while (count < max_count && (data[0] == first))
    {
      data += 1;
      count += 1;
    }
  return count;
}

static_always_inline u32
clib_count_equal_u8 (u32 * data, uword max_count)
{
  uword count = 0;
  u8 first = data[0];

#if defined(CLIB_HAVE_VEC512)
  while (count + 64 <= max_count &&
	 u8x64_is_all_equal (u8x64_load_unaligned (data), first))
    {
      data += 64;
      count += 64;
    }
#endif
#if defined(CLIB_HAVE_VEC256)
  while (count + 32 <= max_count &&
	 u8x32_is_all_equal (u8x32_load_unaligned (data), first))
    {
      data += 32;
      count += 32;
    }
#endif
#if defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  while (count + 16 <= max_count &&
	 u8x16_is_all_equal (u8x16_load_unaligned (data), first))
    {
      data += 4;
      count += 4;
    }
#endif
  while (count < max_count && (data[0] == first))
    {
      data += 1;
      count += 1;
    }
  return count;
}


#endif /* included_clib_string_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
