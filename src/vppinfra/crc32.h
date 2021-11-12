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

#include <vppinfra/clib.h>

#if __SSE4_2__
#define clib_crc32c_uses_intrinsics
#include <x86intrin.h>
static_always_inline u32
clib_crc32c_u8 (u32 last, u8 data)
{
  return _mm_crc32_u8 (last, data);
}

static_always_inline u32
clib_crc32c_u16 (u32 last, u16 data)
{
  return _mm_crc32_u16 (last, data);
}

static_always_inline u32
clib_crc32c_u32 (u32 last, u32 data)
{
  return _mm_crc32_u32 (last, data);
}

static_always_inline u32
clib_crc32c_u64 (u32 last, u64 data)
{
  return _mm_crc32_u64 (last, data);
}
#endif

#if __ARM_FEATURE_CRC32
#define clib_crc32c_uses_intrinsics
#include <arm_acle.h>
static_always_inline u32
clib_crc32c_u8 (u32 last, u8 data)
{
  return __crc32cd (last, data);
}

static_always_inline u32
clib_crc32c_u16 (u32 last, u16 data)
{
  return __crc32ch (last, data);
}

static_always_inline u32
clib_crc32c_u32 (u32 last, u32 data)
{
  return __crc32cw (last, data);
}

static_always_inline u32
clib_crc32c_u64 (u32 last, u64 data)
{
  return __crc32cd (last, data);
}
#endif

#ifdef clib_crc32c_uses_intrinsics
static_always_inline u32
clib_crc32c (u8 * s, int len)
{
  u32 v = 0;

  for (; len >= 8; len -= 8, s += 8)
    v = clib_crc32c_u64 (v, *((u64u *) s));

  for (; len >= 4; len -= 4, s += 4)
    v = clib_crc32c_u32 (v, *((u32u *) s));

  for (; len >= 2; len -= 2, s += 2)
    v = clib_crc32c_u16 (v, *((u16u *) s));

  for (; len >= 1; len -= 1, s += 1)
    v = clib_crc32c_u8 (v, *((u8 *) s));

  return v;
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
