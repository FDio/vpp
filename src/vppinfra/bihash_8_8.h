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
#undef BIHASH_KVP_CACHE_SIZE
#undef BIHASH_KVP_PER_PAGE

#define BIHASH_TYPE _8_8
#define BIHASH_KVP_PER_PAGE 4
#define BIHASH_KVP_CACHE_SIZE 0

#ifndef __included_bihash_8_8_h__
#define __included_bihash_8_8_h__

#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/crc32.h>

/** 8 octet key, 8 octet key value pair */
typedef struct
{
  u64 key;			/**< the key */
  u64 value;			/**< the value */
} clib_bihash_kv_8_8_t;

/** Decide if a clib_bihash_kv_8_8_t instance is free
    @param v- pointer to the (key,value) pair
*/
static inline int
clib_bihash_is_free_8_8 (clib_bihash_kv_8_8_t * v)
{
  if (v->key == ~0ULL && v->value == ~0ULL)
    return 1;
  return 0;
}

/** Hash a clib_bihash_kv_8_8_t instance
    @param v - pointer to the (key,value) pair, hash the key (only)
*/
static inline u64
clib_bihash_hash_8_8 (clib_bihash_kv_8_8_t * v)
{
  /* Note: to torture-test linear scan, make this fn return a constant */
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) & v->key, 8);
#else
  return clib_xxhash (v->key);
#endif
}

/** Format a clib_bihash_kv_8_8_t instance
    @param s - u8 * vector under construction
    @param args (vararg) - the (key,value) pair to format
    @return s - the u8 * vector under construction
*/
static inline u8 *
format_bihash_kvp_8_8 (u8 * s, va_list * args)
{
  clib_bihash_kv_8_8_t *v = va_arg (*args, clib_bihash_kv_8_8_t *);

  s = format (s, "key %llu value %llu", v->key, v->value);
  return s;
}

/** Compare two clib_bihash_kv_8_8_t instances
    @param a - first key
    @param b - second key
*/
static inline int
clib_bihash_key_compare_8_8 (u64 a, u64 b)
{
  return a == b;
}

#undef __included_bihash_template_h__
#include <vppinfra/bihash_template.h>

#endif /* __included_bihash_8_8_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
