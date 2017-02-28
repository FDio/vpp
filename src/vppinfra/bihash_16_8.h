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
#undef BIHASH_TYPE

#define BIHASH_TYPE _16_8
#define BIHASH_KVP_PER_PAGE 4

#ifndef __included_bihash_16_8_h__
#define __included_bihash_16_8_h__

#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>

typedef struct
{
  u64 key[2];
  u64 value;
} clib_bihash_kv_16_8_t;

static inline int
clib_bihash_is_free_16_8 (clib_bihash_kv_16_8_t * v)
{
  /* Free values are memset to 0xff, check a bit... */
  if (v->key[0] == ~0ULL && v->value == ~0ULL)
    return 1;
  return 0;
}

#if __SSE4_2__
#ifndef __defined_crc_u32__
#define __defined_crc_u32__
static inline u32
crc_u32 (u32 data, u32 value)
{
  __asm__ volatile ("crc32l %[data], %[value];":[value] "+r" (value):[data]
		    "rm" (data));
  return value;
}
#endif /* __defined_crc_u32__ */

static inline u64
clib_bihash_hash_16_8 (clib_bihash_kv_16_8_t * v)
{
  u32 *dp = (u32 *) & v->key[0];
  u32 value = 0;

  value = crc_u32 (dp[0], value);
  value = crc_u32 (dp[1], value);
  value = crc_u32 (dp[2], value);
  value = crc_u32 (dp[3], value);

  return value;
}
#else
static inline u64
clib_bihash_hash_16_8 (clib_bihash_kv_16_8_t * v)
{
  u64 tmp = v->key[0] ^ v->key[1];
  return clib_xxhash (tmp);
}
#endif

static inline u8 *
format_bihash_kvp_16_8 (u8 * s, va_list * args)
{
  clib_bihash_kv_16_8_t *v = va_arg (*args, clib_bihash_kv_16_8_t *);

  s = format (s, "key %llu %llu value %llu", v->key[0], v->key[1], v->value);
  return s;
}

static inline int
clib_bihash_key_compare_16_8 (u64 * a, u64 * b)
{
  return ((a[0] ^ b[0]) | (a[1] ^ b[1])) == 0;
}

#undef __included_bihash_template_h__
#include <vppinfra/bihash_template.h>

#endif /* __included_bihash_16_8_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
