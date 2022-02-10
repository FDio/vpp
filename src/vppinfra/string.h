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

/** \file

    Optimized string handling code, including c11-compliant
    "safe C library" variants.
*/

#ifndef included_clib_string_h
#define included_clib_string_h

#include <vppinfra/clib.h>	/* for CLIB_LINUX_KERNEL */
#include <vppinfra/vector.h>
#include <vppinfra/error_bootstrap.h>
#include <vppinfra/memcpy_x86_64.h>

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


static_always_inline void *
clib_memcpy_fast (void *restrict dst, const void *restrict src, size_t n)
{
  ASSERT (dst && src &&
	  "memcpy(src, dst, n) with src == NULL or dst == NULL is undefined "
	  "behaviour");
#if defined(__COVERITY__)
  return memcpy (dst, src, n);
#elif defined(__x86_64__)
  clib_memcpy_x86_64 (dst, src, n);
  return dst;
#else
  return memcpy (dst, src, n);
#endif
}

#include <vppinfra/memcpy.h>

/* c-11 string manipulation variants */

#ifndef EOK
#define EOK 0
#endif
#ifndef EINVAL
#define EINVAL 22
#endif
#ifndef ESRCH
#define ESRCH 3
#endif
#ifndef EOVERFLOW
#define EOVERFLOW 75
#endif

/*
 * In order to provide smooth mapping from unsafe string API to the clib string
 * macro, we often have to improvise s1max and s2max due to the additional
 * arguments are required for implementing the safe API. This macro is used
 * to provide the s1max/s2max. It is not perfect because the actual
 * s1max/s2max may be greater than 4k and the mapping from the unsafe API to
 * the macro would cause a regression. However, it is not terribly likely.
 * So I bet against the odds.
 */
#define CLIB_STRING_MACRO_MAX 4096

typedef int errno_t;
typedef uword rsize_t;

void clib_c11_violation (const char *s);
errno_t memcpy_s (void *__restrict__ dest, rsize_t dmax,
		  const void *__restrict__ src, rsize_t n);

always_inline errno_t
memcpy_s_inline (void *__restrict__ dest, rsize_t dmax,
		 const void *__restrict__ src, rsize_t n)
{
  uword low, hi;
  u8 bad;

  /*
   * Optimize constant-number-of-bytes calls without asking
   * "too many questions for someone from New Jersey"
   */
  if (COMPILE_TIME_CONST (n))
    {
      clib_memcpy_fast (dest, src, n);
      return EOK;
    }

  /*
   * call bogus if: src or dst NULL, trying to copy
   * more data than we have space in dst, or src == dst.
   * n == 0 isn't really "bad", so check first in the
   * "wall-of-shame" department...
   */
  bad = (dest == 0) + (src == 0) + (n > dmax) + (dest == src) + (n == 0);
  if (PREDICT_FALSE (bad != 0))
    {
      /* Not actually trying to copy anything is OK */
      if (n == 0)
	return EOK;
      if (dest == NULL)
	clib_c11_violation ("dest NULL");
      if (src == NULL)
	clib_c11_violation ("src NULL");
      if (n > dmax)
	clib_c11_violation ("n > dmax");
      if (dest == src)
	clib_c11_violation ("dest == src");
      return EINVAL;
    }

  /* Check for src/dst overlap, which is not allowed */
  low = (uword) (src < dest ? src : dest);
  hi = (uword) (src < dest ? dest : src);

  if (PREDICT_FALSE (low + (n - 1) >= hi))
    {
      clib_c11_violation ("src/dest overlap");
      return EINVAL;
    }

  clib_memcpy_fast (dest, src, n);
  return EOK;
}

/*
 * Note: $$$ This macro is a crutch. Folks need to manually
 * inspect every extant clib_memcpy(...) call and
 * attempt to provide a real destination buffer size
 * argument...
 */
#define clib_memcpy(d,s,n) memcpy_s_inline(d,n,s,n)

errno_t memset_s (void *s, rsize_t smax, int c, rsize_t n);

always_inline errno_t
memset_s_inline (void *s, rsize_t smax, int c, rsize_t n)
{
  u8 bad;

  bad = (s == 0) + (n > smax);

  if (PREDICT_FALSE (bad != 0))
    {
      if (s == 0)
	clib_c11_violation ("s NULL");
      if (n > smax)
	clib_c11_violation ("n > smax");
      return (EINVAL);
    }
  memset (s, c, n);
  return (EOK);
}

/*
 * This macro is not [so much of] a crutch.
 * It's super-typical to write:
 *
 *   ep = pool_get (<pool>);
 *   clib_memset(ep, 0, sizeof (*ep));
 *
 * The compiler should delete the not-so useful
 * (n > smax) test. TBH the NULL pointer check isn't
 * so useful in this case, but so be it.
 */
#define clib_memset(s,c,n) memset_s_inline(s,n,c,n)

static_always_inline void
clib_memcpy_le (u8 * dst, u8 * src, u8 len, u8 max_len)
{
#if defined (CLIB_HAVE_VEC256)
  u8x32 s0, s1, d0, d1;
  u8x32 mask = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17,
    18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
  };
  u8x32 lv = u8x32_splat (len);
  u8x32 add = u8x32_splat (32);

  s0 = u8x32_load_unaligned (src);
  s1 = u8x32_load_unaligned (src + 32);
  d0 = u8x32_load_unaligned (dst);
  d1 = u8x32_load_unaligned (dst + 32);

  d0 = u8x32_blend (d0, s0, lv > mask);
  u8x32_store_unaligned (d0, dst);

  if (max_len <= 32)
    return;

  mask += add;
  d1 = u8x32_blend (d1, s1, lv > mask);
  u8x32_store_unaligned (d1, dst + 32);

#elif defined (CLIB_HAVE_VEC128)
  u8x16 s0, s1, s2, s3, d0, d1, d2, d3;
  u8x16 mask = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
  u8x16 lv = u8x16_splat (len);
  u8x16 add = u8x16_splat (16);

  s0 = u8x16_load_unaligned (src);
  s1 = u8x16_load_unaligned (src + 16);
  s2 = u8x16_load_unaligned (src + 32);
  s3 = u8x16_load_unaligned (src + 48);
  d0 = u8x16_load_unaligned (dst);
  d1 = u8x16_load_unaligned (dst + 16);
  d2 = u8x16_load_unaligned (dst + 32);
  d3 = u8x16_load_unaligned (dst + 48);

  d0 = u8x16_blend (d0, s0, lv > mask);
  u8x16_store_unaligned (d0, dst);

  if (max_len <= 16)
    return;

  mask += add;
  d1 = u8x16_blend (d1, s1, lv > mask);
  u8x16_store_unaligned (d1, dst + 16);

  if (max_len <= 32)
    return;

  mask += add;
  d2 = u8x16_blend (d2, s2, lv > mask);
  u8x16_store_unaligned (d2, dst + 32);

  mask += add;
  d3 = u8x16_blend (d3, s3, lv > mask);
  u8x16_store_unaligned (d3, dst + 48);
#else
  memmove (dst, src, len);
#endif
}

static_always_inline void
clib_memcpy_le64 (u8 * dst, u8 * src, u8 len)
{
  clib_memcpy_le (dst, src, len, 64);
}

static_always_inline void
clib_memcpy_le32 (u8 * dst, u8 * src, u8 len)
{
  clib_memcpy_le (dst, src, len, 32);
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


/*
 * This macro is to provide smooth mapping from memcmp to memcmp_s.
 * memcmp has fewer parameters and fewer returns than memcmp_s.
 * This macro is somewhat a crutch. When err != EOK is returned from memcmp_s,
 * we return 0 and spit out a message in the console because there is
 * no way to return the error code to the memcmp callers.
 * This condition happens when s1 or s2 is null. Please note
 * in the extant memcmp calls, if s1, s2, or both are null, memcmp returns 0
 * anyway. So we are consistent in this case for the comparison return
 * although we also spit out a C11 violation message in the console to
 * warn that they pass null pointers for both s1 and s2.
 * Applications are encouraged to use the cool C11 memcmp_s API to get the
 * maximum benefit out of it.
 */
#define clib_memcmp(s1,s2,m1) \
  ({ int __diff = 0;				       \
    memcmp_s_inline (s1, m1, s2, m1, &__diff);	\
    __diff; \
  })

errno_t memcmp_s (const void *s1, rsize_t s1max, const void *s2,
		  rsize_t s2max, int *diff);

always_inline errno_t
memcmp_s_inline (const void *s1, rsize_t s1max, const void *s2, rsize_t s2max,
		 int *diff)
{
  u8 bad;

  bad = (s1 == 0) + (s2 == 0) + (diff == 0) + (s2max > s1max) + (s2max == 0) +
    (s1max == 0);

  if (PREDICT_FALSE (bad != 0))
    {
      if (s1 == NULL)
	clib_c11_violation ("s1 NULL");
      if (s2 == NULL)
	clib_c11_violation ("s2 NULL");
      if (diff == NULL)
	clib_c11_violation ("diff NULL");
      if (s2max > s1max)
	clib_c11_violation ("s2max > s1max");
      if (s2max == 0)
	clib_c11_violation ("s2max 0");
      if (s1max == 0)
	clib_c11_violation ("s1max 0");
      return EINVAL;
    }

  if (PREDICT_FALSE (s1 == s2))
    {
      *diff = 0;
      return EOK;
    }

  *diff = memcmp (s1, s2, s2max);
  return EOK;
}

/*
 * This macro is to provide smooth mapping from strnlen to strnlen_s
 */
#define clib_strnlen(s,m) strnlen_s_inline(s,m)

size_t strnlen_s (const char *s, size_t maxsize);

always_inline size_t
strnlen_s_inline (const char *s, size_t maxsize)
{
  u8 bad;

  bad = (s == 0) + (maxsize == 0);
  if (PREDICT_FALSE (bad != 0))
    {
      if (s == 0)
	clib_c11_violation ("s NULL");
      if (maxsize == 0)
	clib_c11_violation ("maxsize 0");
      return 0;
    }
  return strnlen (s, maxsize);
}

/*
 * This macro is to provide smooth mapping from strcmp to strcmp_s.
 * strcmp has fewer parameters and fewer returns than strcmp_s.
 * This macro is somewhat a crutch. When err != EOK is returned from strcmp_s,
 * we return 0 and spit out a message in the console because
 * there is no way to return the error to the strcmp callers.
 * This condition happens when s1 or s2 is null. Please note in the extant
 * strcmp call, they would end up crashing if one of them is null.
 * So the new behavior is no crash, but an error is displayed in the
 * console which I think is more user friendly. If both s1 and s2 are null,
 * strcmp returns 0. Obviously, strcmp did the pointers comparison prior
 * to actually accessing the pointer contents. We are still consistent
 * in this case for the comparison return although we also spit out a
 * C11 violation message in the console to warn that they pass null pointers
 * for both s1 and s2. The other problem is strcmp does not provide s1max,
 * we use CLIB_STRING_MACRO_MAX and hopefully, s1 is null terminated.
 * If not, we may be accessing memory beyonf what is intended.
 * Applications are encouraged to use the cool C11 strcmp_s API to get the
 * maximum benefit out of it.
 */
#define clib_strcmp(s1,s2) \
  ({ int __indicator = 0; \
    strcmp_s_inline (s1, CLIB_STRING_MACRO_MAX, s2, &__indicator);	\
    __indicator;			\
  })

errno_t strcmp_s (const char *s1, rsize_t s1max, const char *s2,
		  int *indicator);

always_inline errno_t
strcmp_s_inline (const char *s1, rsize_t s1max, const char *s2,
		 int *indicator)
{
  u8 bad;

  bad = (indicator == 0) + (s1 == 0) + (s2 == 0) + (s1max == 0) +
    (s1 && s1max && s1[clib_strnlen (s1, s1max)] != '\0');

  if (PREDICT_FALSE (bad != 0))
    {
      if (indicator == NULL)
	clib_c11_violation ("indicator NULL");
      if (s1 == NULL)
	clib_c11_violation ("s1 NULL");
      if (s2 == NULL)
	clib_c11_violation ("s2 NULL");
      if (s1max == 0)
	clib_c11_violation ("s1max 0");
      if (s1 && s1max && s1[clib_strnlen (s1, s1max)] != '\0')
	clib_c11_violation ("s1 unterminated");
      return EINVAL;
    }

  *indicator = strcmp (s1, s2);
  return EOK;
}

/*
 * This macro is to provide smooth mapping from strncmp to strncmp_s.
 * strncmp has fewer parameters and fewer returns than strncmp_s. That said,
 * this macro is somewhat a crutch. When we get err != EOK from strncmp_s,
 * we return 0 and spit out a message in the console because there is no
 * means to return the error to the strncmp caller.
 * This condition happens when s1 or s2 is null. In the extant strncmp call,
 * they would end up crashing if one of them is null. So the new behavior is
 * no crash, but error is displayed in the console which is more
 * user friendly. If s1 and s2 are null, strncmp returns 0. Obviously,
 * strncmp did the pointers comparison prior to actually accessing the
 * pointer contents. We are still consistent in this case for the comparison
 * return although we also spit out a C11 violation message in the console to
 * warn that they pass null pointers for both s1 and s2.
 * Applications are encouraged to use the cool C11 strncmp_s API to get the
 * maximum benefit out of it.
 */
#define clib_strncmp(s1,s2,n) \
  ({ int __indicator = 0; \
    strncmp_s_inline (s1, CLIB_STRING_MACRO_MAX, s2, n, &__indicator);	\
    __indicator;			\
  })

errno_t strncmp_s (const char *s1, rsize_t s1max, const char *s2, rsize_t n,
		   int *indicator);

always_inline errno_t
strncmp_s_inline (const char *s1, rsize_t s1max, const char *s2, rsize_t n,
		  int *indicator)
{
  u8 bad;
  u8 s1_greater_s1max = (s1 && s1max && n > clib_strnlen (s1, s1max));

  if (PREDICT_FALSE (s1_greater_s1max && indicator))
    {
      /*
       * strcmp allows n > s1max. If indicator is non null, we can still
       * do the compare without any harm and return EINVAL as well as the
       * result in indicator.
       */
      clib_c11_violation ("n exceeds s1 length");
      *indicator = strncmp (s1, s2, n);
      return EINVAL;
    }

  bad = (s1 == 0) + (s2 == 0) + (indicator == 0) + (s1max == 0) +
    (s1 && s1max && s1[clib_strnlen (s1, s1max)] != '\0') + s1_greater_s1max;

  if (PREDICT_FALSE (bad != 0))
    {
      if (indicator == NULL)
	clib_c11_violation ("indicator NULL");
      if (s1 == NULL)
	clib_c11_violation ("s1 NULL");
      if (s2 == NULL)
	clib_c11_violation ("s2 NULL");
      if (s1max == 0)
	clib_c11_violation ("s1max 0");
      if (s1 && s1max && s1[clib_strnlen (s1, s1max)] != '\0')
	clib_c11_violation ("s1 unterminated");
      if (s1_greater_s1max)
	clib_c11_violation ("n exceeds s1 length");
      return EINVAL;
    }

  *indicator = strncmp (s1, s2, n);
  return EOK;
}

errno_t strcpy_s (char *__restrict__ dest, rsize_t dmax,
		  const char *__restrict__ src);

always_inline errno_t
strcpy_s_inline (char *__restrict__ dest, rsize_t dmax,
		 const char *__restrict__ src)
{
  u8 bad;
  uword low, hi;
  size_t n;

  bad = (dest == 0) + (dmax == 0) + (src == 0);
  if (PREDICT_FALSE (bad != 0))
    {
      if (dest == 0)
	clib_c11_violation ("dest NULL");
      if (src == 0)
	clib_c11_violation ("src NULL");
      if (dmax == 0)
	clib_c11_violation ("dmax 0");
      return EINVAL;
    }

  n = clib_strnlen (src, dmax);
  if (PREDICT_FALSE (n >= dmax))
    {
      clib_c11_violation ("not enough space for dest");
      return (EINVAL);
    }
  /* Not actually trying to copy anything is OK */
  if (PREDICT_FALSE (n == 0))
    return EOK;

  /* Check for src/dst overlap, which is not allowed */
  low = (uword) (src < dest ? src : dest);
  hi = (uword) (src < dest ? dest : src);

  if (PREDICT_FALSE (low + (n - 1) >= hi))
    {
      clib_c11_violation ("src/dest overlap");
      return EINVAL;
    }

  clib_memcpy_fast (dest, src, n);
  dest[n] = '\0';
  return EOK;
}

/*
 * This macro is provided for smooth migration from strncpy. It is not perfect
 * because we don't know the size of the destination buffer to pass to
 * strncpy_s. We improvise dmax with CLIB_STRING_MACRO_MAX.
 * Applications are encouraged to move to the C11 strncpy_s API and provide
 * the correct dmax for better error checking.
 */
#define clib_strncpy(d,s,n) strncpy_s_inline(d,CLIB_STRING_MACRO_MAX,s,n)

errno_t
strncpy_s (char *__restrict__ dest, rsize_t dmax,
	   const char *__restrict__ src, rsize_t n);

always_inline errno_t
strncpy_s_inline (char *__restrict__ dest, rsize_t dmax,
		  const char *__restrict__ src, rsize_t n)
{
  u8 bad;
  uword low, hi;
  rsize_t m;
  errno_t status = EOK;

  bad = (dest == 0) + (dmax == 0) + (src == 0) + (n == 0);
  if (PREDICT_FALSE (bad != 0))
    {
      /* Not actually trying to copy anything is OK */
      if (n == 0)
	return EOK;
      if (dest == 0)
	clib_c11_violation ("dest NULL");
      if (src == 0)
	clib_c11_violation ("src NULL");
      if (dmax == 0)
	clib_c11_violation ("dmax 0");
      return EINVAL;
    }

  if (PREDICT_FALSE (n >= dmax))
    {
      /* Relax and use strnlen of src */
      clib_c11_violation ("n >= dmax");
      m = clib_strnlen (src, dmax);
      if (m >= dmax)
	{
	  /* Truncate, adjust copy length to fit dest */
	  m = dmax - 1;
	  status = EOVERFLOW;
	}
    }
  else
    /* cap the copy to strlen(src) in case n > strlen(src) */
    m = clib_strnlen (src, n);

  /* Check for src/dst overlap, which is not allowed */
  low = (uword) (src < dest ? src : dest);
  hi = (uword) (src < dest ? dest : src);

  /*
   * This check may fail innocently if src + dmax >= dst, but
   * src + strlen(src) < dst. If it fails, check more carefully before
   * blowing the whistle.
   */
  if (PREDICT_FALSE (low + (m - 1) >= hi))
    {
      m = clib_strnlen (src, m);

      if (low + (m - 1) >= hi)
	{
	  clib_c11_violation ("src/dest overlap");
	  return EINVAL;
	}
    }

  clib_memcpy_fast (dest, src, m);
  dest[m] = '\0';
  return status;
}

errno_t strcat_s (char *__restrict__ dest, rsize_t dmax,
		  const char *__restrict__ src);

always_inline errno_t
strcat_s_inline (char *__restrict__ dest, rsize_t dmax,
		 const char *__restrict__ src)
{
  u8 bad;
  uword low, hi;
  size_t m, n, dest_size;

  bad = (dest == 0) + (dmax == 0) + (src == 0);
  if (PREDICT_FALSE (bad != 0))
    {
      if (dest == 0)
	clib_c11_violation ("dest NULL");
      if (src == 0)
	clib_c11_violation ("src NULL");
      if (dmax == 0)
	clib_c11_violation ("dmax 0");
      return EINVAL;
    }

  dest_size = clib_strnlen (dest, dmax);
  m = dmax - dest_size;
  n = clib_strnlen (src, m);
  if (PREDICT_FALSE (n >= m))
    {
      clib_c11_violation ("not enough space for dest");
      return EINVAL;
    }

  /* Not actually trying to concatenate anything is OK */
  if (PREDICT_FALSE (n == 0))
    return EOK;

  /* Check for src/dst overlap, which is not allowed */
  low = (uword) (src < dest ? src : dest);
  hi = (uword) (src < dest ? dest : src);

  if (PREDICT_FALSE (low + (n - 1) >= hi))
    {
      clib_c11_violation ("src/dest overlap");
      return EINVAL;
    }

  clib_memcpy_fast (dest + dest_size, src, n);
  dest[dest_size + n] = '\0';
  return EOK;
}

errno_t strncat_s (char *__restrict__ dest, rsize_t dmax,
		   const char *__restrict__ src, rsize_t n);

always_inline errno_t
strncat_s_inline (char *__restrict__ dest, rsize_t dmax,
		  const char *__restrict__ src, rsize_t n)
{
  u8 bad;
  uword low, hi;
  size_t m, dest_size, allowed_size;
  errno_t status = EOK;

  bad = (dest == 0) + (src == 0) + (dmax == 0) + (n == 0);
  if (PREDICT_FALSE (bad != 0))
    {
      /* Not actually trying to concatenate anything is OK */
      if (n == 0)
	return EOK;
      if (dest == 0)
	clib_c11_violation ("dest NULL");
      if (src == 0)
	clib_c11_violation ("src NULL");
      if (dmax == 0)
	clib_c11_violation ("dmax 0");
      return EINVAL;
    }

  /* Check for src/dst overlap, which is not allowed */
  low = (uword) (src < dest ? src : dest);
  hi = (uword) (src < dest ? dest : src);

  if (PREDICT_FALSE (low + (n - 1) >= hi))
    {
      clib_c11_violation ("src/dest overlap");
      return EINVAL;
    }

  dest_size = clib_strnlen (dest, dmax);
  allowed_size = dmax - dest_size;

  if (PREDICT_FALSE (allowed_size == 0))
    {
      clib_c11_violation ("no space left in dest");
      return (EINVAL);
    }

  if (PREDICT_FALSE (n >= allowed_size))
    {
      /*
       * unlike strcat_s, strncat_s will do the concatenation anyway when
       * there is not enough space in dest. But it will do the truncation and
       * null terminate dest
       */
      m = clib_strnlen (src, allowed_size);
      if (m >= allowed_size)
	{
	  m = allowed_size - 1;
	  status = EOVERFLOW;
	}
    }
  else
    m = clib_strnlen (src, n);

  clib_memcpy_fast (dest + dest_size, src, m);
  dest[dest_size + m] = '\0';
  return status;
}

/*
 * This macro is to provide smooth mapping from strtok_r to strtok_s.
 * To map strtok to this macro, the caller would have to supply an additional
 * argument. strtokr_s requires s1max which the unsafe API does not have. So
 * we have to improvise it with CLIB_STRING_MACRO_MAX. Unlike strtok_s,
 * this macro cannot catch unterminated s1 and s2.
 * Applications are encouraged to use the cool C11 strtok_s API to avoid
 * these problems.
 */
#define clib_strtok(s1,s2,p)		   \
  ({ rsize_t __s1max = CLIB_STRING_MACRO_MAX;	\
    strtok_s_inline (s1, &__s1max, s2, p);		\
  })

char *strtok_s (char *__restrict__ s1, rsize_t * __restrict__ s1max,
		const char *__restrict__ s2, char **__restrict__ ptr);

always_inline char *
strtok_s_inline (char *__restrict__ s1, rsize_t * __restrict__ s1max,
		 const char *__restrict__ s2, char **__restrict__ ptr)
{
#define STRTOK_DELIM_MAX_LEN 16
  u8 bad;
  const char *pt;
  char *ptoken;
  uword dlen, slen;

  bad = (s1max == 0) + (s2 == 0) + (ptr == 0) +
    ((s1 == 0) && ptr && (*ptr == 0));
  if (PREDICT_FALSE (bad != 0))
    {
      if (s2 == NULL)
	clib_c11_violation ("s2 NULL");
      if (s1max == NULL)
	clib_c11_violation ("s1max is NULL");
      if (ptr == NULL)
	clib_c11_violation ("ptr is NULL");
      /* s1 == 0 and *ptr == null is no good */
      if ((s1 == 0) && ptr && (*ptr == 0))
	clib_c11_violation ("s1 and ptr contents are NULL");
      return 0;
    }

  if (s1 == 0)
    s1 = *ptr;

  /*
   * scan s1 for a delimiter
   */
  dlen = *s1max;
  ptoken = 0;
  while (*s1 != '\0' && !ptoken)
    {
      if (PREDICT_FALSE (dlen == 0))
	{
	  *ptr = 0;
	  clib_c11_violation ("s1 unterminated");
	  return 0;
	}

      /*
       * must scan the entire delimiter list
       * ISO should have included a delimiter string limit!!
       */
      slen = STRTOK_DELIM_MAX_LEN;
      pt = s2;
      while (*pt != '\0')
	{
	  if (PREDICT_FALSE (slen == 0))
	    {
	      *ptr = 0;
	      clib_c11_violation ("s2 unterminated");
	      return 0;
	    }
	  slen--;
	  if (*s1 == *pt)
	    {
	      ptoken = 0;
	      break;
	    }
	  else
	    {
	      pt++;
	      ptoken = s1;
	    }
	}
      s1++;
      dlen--;
    }

  /*
   * if the beginning of a token was not found, then no
   * need to continue the scan.
   */
  if (ptoken == 0)
    {
      *s1max = dlen;
      return (ptoken);
    }

  /*
   * Now we need to locate the end of the token
   */
  while (*s1 != '\0')
    {
      if (dlen == 0)
	{
	  *ptr = 0;
	  clib_c11_violation ("s1 unterminated");
	  return 0;
	}

      slen = STRTOK_DELIM_MAX_LEN;
      pt = s2;
      while (*pt != '\0')
	{
	  if (slen == 0)
	    {
	      *ptr = 0;
	      clib_c11_violation ("s2 unterminated");
	      return 0;
	    }
	  slen--;
	  if (*s1 == *pt)
	    {
	      /*
	       * found a delimiter, set to null
	       * and return context ptr to next char
	       */
	      *s1 = '\0';
	      *ptr = (s1 + 1);	/* return pointer for next scan */
	      *s1max = dlen - 1;	/* account for the nulled delimiter */
	      return (ptoken);
	    }
	  else
	    {
	      /*
	       * simply scanning through the delimiter string
	       */
	      pt++;
	    }
	}
      s1++;
      dlen--;
    }

  *ptr = s1;
  *s1max = dlen;
  return (ptoken);
}

errno_t strstr_s (char *s1, rsize_t s1max, const char *s2, rsize_t s2max,
		  char **substring);

always_inline errno_t
strstr_s_inline (char *s1, rsize_t s1max, const char *s2, rsize_t s2max,
		 char **substring)
{
  u8 bad;
  size_t s1_size, s2_size;

  bad =
    (s1 == 0) + (s2 == 0) + (substring == 0) + (s1max == 0) + (s2max == 0) +
    (s1 && s1max && (s1[clib_strnlen (s1, s1max)] != '\0')) +
    (s2 && s2max && (s2[clib_strnlen (s2, s2max)] != '\0'));
  if (PREDICT_FALSE (bad != 0))
    {
      if (s1 == 0)
	clib_c11_violation ("s1 NULL");
      if (s2 == 0)
	clib_c11_violation ("s2 NULL");
      if (s1max == 0)
	clib_c11_violation ("s1max 0");
      if (s2max == 0)
	clib_c11_violation ("s2max 0");
      if (substring == 0)
	clib_c11_violation ("substring NULL");
      if (s1 && s1max && (s1[clib_strnlen (s1, s1max)] != '\0'))
	clib_c11_violation ("s1 unterminated");
      if (s2 && s2max && (s2[clib_strnlen (s2, s2max)] != '\0'))
	clib_c11_violation ("s2 unterminated");
      return EINVAL;
    }

  /*
   * s2 points to a string with zero length, or s2 equals s1, return s1
   */
  if (PREDICT_FALSE (*s2 == '\0' || s1 == s2))
    {
      *substring = s1;
      return EOK;
    }

  /*
   * s2_size > s1_size, it won't find match.
   */
  s1_size = clib_strnlen (s1, s1max);
  s2_size = clib_strnlen (s2, s2max);
  if (PREDICT_FALSE (s2_size > s1_size))
    return ESRCH;

  *substring = strstr (s1, s2);
  if (*substring == 0)
    return ESRCH;

  return EOK;
}

#endif /* included_clib_string_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
