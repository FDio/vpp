/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef __included_crc32_h__
#define __included_crc32_h__

#if __SSE4_2__
#define clib_crc32c_uses_intrinsics
#include <x86intrin.h>

static_always_inline u32
clib_crc32c (u8 * s, int len)
{
  u32 v = 0;

#if __x86_64__
  for (; len >= 8; len -= 8, s += 8)
    v = _mm_crc32_u64 (v, *((u64 *) s));
#else
  /* workaround weird GCC bug when using _mm_crc32_u32
     which happens with -O2 optimization */
  volatile ("":::"memory");
#endif

  for (; len >= 4; len -= 4, s += 4)
    v = _mm_crc32_u32 (v, *((u32 *) s));

  for (; len >= 2; len -= 2, s += 2)
    v = _mm_crc32_u16 (v, *((u16 *) s));

  for (; len >= 1; len -= 1, s += 1)
    v = _mm_crc32_u8 (v, *((u16 *) s));

  return v;
}

static_always_inline u32
crc_u32 (u32 data, u32 value)
{
  return _mm_crc32_u32 (data, value);
}

#elif __ARM_FEATURE_CRC32
#define clib_crc32c_with_intrinsics
#include <arm_acle.h>

static_always_inline u32
clib_crc32c (u8 * s, int len)
{
  u32 v = 0;

  for (; len >= 8; len -= 8, s += 8)
    v = __crc32cd (v, *((u64 *) s));

  for (; len >= 4; len -= 4, s += 4)
    v = __crc32cw (v, *((u32 *) s));

  for (; len >= 2; len -= 2, s += 2)
    v = __crc32ch (v, *((u16 *) s));

  for (; len >= 1; len -= 1, s += 1)
    v = __crc32cb (v, *((u8 *) s));

  return v;
}

static_always_inline u32
crc_u32 (u32 data, u32 value)
{
  return __crc32cw (data, value);
}

#else
#include <vppinfra/xxhash.h>

static inline u32
crc_u32 (u32 data, u32 value)
{
  u64 tmp = ((u64) data << 32) | (u64) value;
  return (u32) clib_xxhash (tmp);
}
#endif

#endif /* __included_crc32_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
