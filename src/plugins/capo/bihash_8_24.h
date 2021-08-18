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
#undef BIHASH_KVP_PER_PAGE
#undef BIHASH_32_64_SVM
#undef BIHASH_ENABLE_STATS
#undef BIHASH_KVP_AT_BUCKET_LEVEL
#undef BIHASH_LAZY_INSTANTIATE
#undef BIHASH_BUCKET_PREFETCH_CACHE_LINES

#define BIHASH_TYPE			   _8_24
#define BIHASH_KVP_PER_PAGE		   4
#define BIHASH_KVP_AT_BUCKET_LEVEL	   1
#define BIHASH_LAZY_INSTANTIATE		   0
#define BIHASH_BUCKET_PREFETCH_CACHE_LINES 2

#ifndef __included_bihash_8_24_h__
#define __included_bihash_8_24_h__

#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/crc32.h>

/** 8 octet key, 32 octet key value pair */
typedef struct
{
  u64 key;	/**< the key */
  u64 value[3]; /**< the value */
} clib_bihash_kv_8_24_t;

/** Decide if a clib_bihash_kv_8_24_t instance is free
    @param v- pointer to the (key,value) pair
*/
static inline int
clib_bihash_is_free_8_24 (clib_bihash_kv_8_24_t *v)
{
  if (v->key == ~0ULL && v->value[0] == ~0ULL && v->value[1] == ~0ULL &&
      v->value[2] == ~0ULL)
    return 1;
  return 0;
}

/** Hash a clib_bihash_kv_8_24_t instance
    @param v - pointer to the (key,value) pair, hash the key (only)
*/
static inline u64
clib_bihash_hash_8_24 (clib_bihash_kv_8_24_t *v)
{
  /* Note: to torture-test linear scan, make this fn return a constant */
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) &v->key, 8);
#else
  return clib_xxhash (v->key);
#endif
}

/** Format a clib_bihash_kv_8_24_t instance
    @param s - u8 * vector under construction
    @param args (vararg) - the (key,value) pair to format
    @return s - the u8 * vector under construction
*/
static inline u8 *
format_bihash_kvp_8_24 (u8 *s, va_list *args)
{
  clib_bihash_kv_8_24_t *v = va_arg (*args, clib_bihash_kv_8_24_t *);

  s = format (s, "key %lu value %lu %lu %lu", v->key, v->value[0], v->value[1],
	      v->value[2]);
  return s;
}

/** Compare two clib_bihash_kv_8_24_t instances
    @param a - first key
    @param b - second key
*/
static inline int
clib_bihash_key_compare_8_24 (u64 a, u64 b)
{
  return a == b;
}

#undef __included_bihash_template_h__
#include <vppinfra/bihash_template.h>

#endif /* __included_bihash_8_24_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
