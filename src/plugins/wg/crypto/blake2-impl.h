/*
 * Copyright (c) 2020 Doc.ai and/or its affiliates.
 * Copyright (c) 2012 Samuel Neves <sneves@dei.uc.pt>.
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
   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/
#ifndef __included_crypto_blake2_impl_h__
#define __included_crypto_blake2_impl_h__

#include <stdint.h>
#include <string.h>
#include <vppinfra/byte_order.h>

#if defined(CLIB_ARCH_IS_LITTLE_ENDIAN)
#define NATIVE_LITTLE_ENDIAN
#endif

#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
#if   defined(_MSC_VER)
#define BLAKE2_INLINE __inline
#elif defined(__GNUC__)
#define BLAKE2_INLINE __inline__
#else
#define BLAKE2_INLINE
#endif
#else
#define BLAKE2_INLINE inline
#endif

static BLAKE2_INLINE uint32_t
load32 (const void *src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  uint32_t w;
  memcpy (&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *) src;
  return ((uint32_t) (p[0]) << 0) |
    ((uint32_t) (p[1]) << 8) |
    ((uint32_t) (p[2]) << 16) | ((uint32_t) (p[3]) << 24);
#endif
}

static BLAKE2_INLINE uint64_t
load64 (const void *src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  uint64_t w;
  memcpy (&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *) src;
  return ((uint64_t) (p[0]) << 0) |
    ((uint64_t) (p[1]) << 8) |
    ((uint64_t) (p[2]) << 16) |
    ((uint64_t) (p[3]) << 24) |
    ((uint64_t) (p[4]) << 32) |
    ((uint64_t) (p[5]) << 40) |
    ((uint64_t) (p[6]) << 48) | ((uint64_t) (p[7]) << 56);
#endif
}

static BLAKE2_INLINE uint16_t
load16 (const void *src)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  uint16_t w;
  memcpy (&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *) src;
  return (uint16_t) (((uint32_t) (p[0]) << 0) | ((uint32_t) (p[1]) << 8));
#endif
}

static BLAKE2_INLINE void
store16 (void *dst, uint16_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy (dst, &w, sizeof w);
#else
  uint8_t *p = (uint8_t *) dst;
  *p++ = (uint8_t) w;
  w >>= 8;
  *p++ = (uint8_t) w;
#endif
}

static BLAKE2_INLINE void
store32 (void *dst, uint32_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy (dst, &w, sizeof w);
#else
  uint8_t *p = (uint8_t *) dst;
  p[0] = (uint8_t) (w >> 0);
  p[1] = (uint8_t) (w >> 8);
  p[2] = (uint8_t) (w >> 16);
  p[3] = (uint8_t) (w >> 24);
#endif
}

static BLAKE2_INLINE void
store64 (void *dst, uint64_t w)
{
#if defined(NATIVE_LITTLE_ENDIAN)
  memcpy (dst, &w, sizeof w);
#else
  uint8_t *p = (uint8_t *) dst;
  p[0] = (uint8_t) (w >> 0);
  p[1] = (uint8_t) (w >> 8);
  p[2] = (uint8_t) (w >> 16);
  p[3] = (uint8_t) (w >> 24);
  p[4] = (uint8_t) (w >> 32);
  p[5] = (uint8_t) (w >> 40);
  p[6] = (uint8_t) (w >> 48);
  p[7] = (uint8_t) (w >> 56);
#endif
}

static BLAKE2_INLINE uint64_t
load48 (const void *src)
{
  const uint8_t *p = (const uint8_t *) src;
  return ((uint64_t) (p[0]) << 0) |
    ((uint64_t) (p[1]) << 8) |
    ((uint64_t) (p[2]) << 16) |
    ((uint64_t) (p[3]) << 24) |
    ((uint64_t) (p[4]) << 32) | ((uint64_t) (p[5]) << 40);
}

static BLAKE2_INLINE void
store48 (void *dst, uint64_t w)
{
  uint8_t *p = (uint8_t *) dst;
  p[0] = (uint8_t) (w >> 0);
  p[1] = (uint8_t) (w >> 8);
  p[2] = (uint8_t) (w >> 16);
  p[3] = (uint8_t) (w >> 24);
  p[4] = (uint8_t) (w >> 32);
  p[5] = (uint8_t) (w >> 40);
}

static BLAKE2_INLINE uint32_t
rotr32 (const uint32_t w, const unsigned c)
{
  return (w >> c) | (w << (32 - c));
}

static BLAKE2_INLINE uint64_t
rotr64 (const uint64_t w, const unsigned c)
{
  return (w >> c) | (w << (64 - c));
}

/* prevents compiler optimizing out memset() */
static BLAKE2_INLINE void
secure_zero_memory (void *v, size_t n)
{
  static void *(*const volatile memset_v) (void *, int, size_t) = &memset;
  memset_v (v, 0, n);
}

#endif //__included_crypto_blake2_impl_h__

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
