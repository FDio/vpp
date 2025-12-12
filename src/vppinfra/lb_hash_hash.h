/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
  val = clib_crc32c_u64 (val, k0);
  val = clib_crc32c_u64 (val, k1);
  val = clib_crc32c_u64 (val, k2);
  val = clib_crc32c_u64 (val, k3);
  val = clib_crc32c_u64 (val, k4);
  return (u32) val;
}

/* Note: k0 is u64 and k1 is u32 */
static_always_inline u32
lb_hash_hash_2_tuples (u64 k0, u32 k1)
{
  u64 val = 0;
  val = clib_crc32c_u64 (val, k0);
  val = clib_crc32c_u32 (val, k1);
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
