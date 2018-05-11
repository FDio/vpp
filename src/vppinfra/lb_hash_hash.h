/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __included_lb_hash_hash_h__
#define __included_lb_hash_hash_h__

#include <vppinfra/crc32.h>
#include <vppinfra/xxhash.h>

#if defined(clib_crc32c_uses_intrinsics) && !defined (__i386__)
static_always_inline u32
lb_hash_hash (u64 k0, u64 k1, u64 k2, u64 k3, u64 k4)
{
  u64 val = 0;
  val = crc32_u64 (val, k0);
  val = crc32_u64 (val, k1);
  val = crc32_u64 (val, k2);
  val = crc32_u64 (val, k3);
  val = crc32_u64 (val, k4);
  return (u32) val;
}

/* Note: k0 is u64 and k1 is u32 */
static_always_inline u32
lb_hash_hash_2_tuples (u64 k0, u32 k1)
{
  u64 val = 0;
  val = crc32_u64 (val, k0);
  val = crc32_u32 (val, k1);
  return (u32) val;
}
#else
static_always_inline u32
lb_hash_hash (u64 k0, u64 k1, u64 k2, u64 k3, u64 k4)
{
  u64 tmp = k0 ^ k1 ^ k2 ^ k3 ^ k4;
  return (u32) clib_xxhash (tmp);
}

/* Note: k0 is u64 and k1 is u32 */
static_always_inline u32
lb_hash_hash_2_tuples (u64 k0, u32 k1)
{
  u64 tmp = k0 ^ k1;
  return (u32) clib_xxhash (tmp);
}
#endif

#endif /* __included_lb_hash_hash_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
