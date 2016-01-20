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
#undef BIHASH_TYPE

#define BIHASH_TYPE _24_8
#define BIHASH_KVP_PER_PAGE 4

#ifndef __included_bihash_24_8_h__
#define __included_bihash_24_8_h__

#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>

typedef struct {
  u64 key[3];
  u64 value;
} clib_bihash_kv_24_8_t;

static inline int clib_bihash_is_free_24_8 (clib_bihash_kv_24_8_t *v)
{
  /* Free values are memset to 0xff, check a bit... */
  if (v->key[0] == ~0ULL && v->value == ~0ULL)
    return 1;
  return 0;
}

#if !defined(__powerpc64__) && !defined(__aarch64__)
static inline u32
crc_u32(u32 data, u32 value)
{
  __asm__ volatile( "crc32l %[data], %[value];"
                    : [value] "+r" (value)
                    : [data] "rm" (data));
  return value;
}

static inline u64 clib_bihash_hash_24_8  (clib_bihash_kv_24_8_t *v)
{
#if 0
  u64 * dp = (u64 *) &v->key[0];
  u64 value = 0;

  value __builtin_ia32_crc32di (dp[0], value);
  value __builtin_ia32_crc32di (dp[1], value);
  value __builtin_ia32_crc32di (dp[2], value);
#endif
  u32 * dp = (u32 *) &v->key[0];
  u32 value = 0;

  value = crc_u32 (dp[0], value);
  value = crc_u32 (dp[1], value);
  value = crc_u32 (dp[2], value);
  value = crc_u32 (dp[3], value);
  value = crc_u32 (dp[4], value);
  value = crc_u32 (dp[5], value);

  return value;
}

#else
static inline u64 clib_bihash_hash_24_8  (clib_bihash_kv_24_8_t *v)
{
  u64 tmp = v->key[0] ^ v->key[1] ^ v->key[2];
  return clib_xxhash (tmp);
}
#endif

static inline u8 * format_bihash_kvp_24_8 (u8 * s, va_list * args)
{
  clib_bihash_kv_24_8_t * v = va_arg (*args, clib_bihash_kv_24_8_t *);

  s = format (s, "key %llu %llu %llu value %llu", 
              v->key[0], v->key[1], v->key[2], v->value);
  return s;
}

static inline int clib_bihash_key_compare_24_8 (u64 * a, u64 * b)
{
  return ((a[0]^b[0]) | (a[1]^b[1]) | (a[2]^b[2])) == 0;
}
#undef __included_bihash_template_h__
#include <vppinfra/bihash_template.h>

#endif /* __included_bihash_24_8_h__ */
