/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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
#undef CLIB_CUCKOO_TYPE

#define CLIB_CUCKOO_TYPE _16_8
#define CLIB_CUCKOO_KVP_PER_BUCKET (4)
#define CLIB_CUCKOO_LOG2_KVP_PER_BUCKET (2)
#define CLIB_CUCKOO_BFS_MAX_STEPS (2000)
#define CLIB_CUCKOO_BFS_MAX_PATH_LENGTH (8)

#ifndef __included_cuckoo_16_8_h__
#define __included_cuckoo_16_8_h__

#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/cuckoo_debug.h>
#include <vppinfra/cuckoo_common.h>

#undef CLIB_CUCKOO_OPTIMIZE_PREFETCH
#undef CLIB_CUCKOO_OPTIMIZE_UNROLL
#undef CLIB_CUCKOO_OPTIMIZE_USE_COUNT_LIMITS_SEARCH
#define CLIB_CUCKOO_OPTIMIZE_PREFETCH 1
#define CLIB_CUCKOO_OPTIMIZE_UNROLL 1
#define CLIB_CUCKOO_OPTIMIZE_USE_COUNT_LIMITS_SEARCH 1

#if __SSE4_2__ && !defined (__i386__)
#include <x86intrin.h>
#endif

/** 8 octet key, 8 octet key value pair */
typedef struct
{
  u64 key[2];	/**< the key */
  u64 value; /**< the value */
} clib_cuckoo_kv_16_8_t;

/** Decide if a clib_cuckoo_kv_16_8_t instance is free
    @param v- pointer to the (key,value) pair
*/
always_inline int
clib_cuckoo_kv_is_free_16_8 (const clib_cuckoo_kv_16_8_t * v)
{
  if (v->key[0] == ~0ULL && v->value == ~0ULL)
    return 1;
  return 0;
}

always_inline void
clib_cuckoo_kv_set_free_16_8 (clib_cuckoo_kv_16_8_t * v)
{
  clib_memset (v, 0xff, sizeof (*v));
}

/** Format a clib_cuckoo_kv_16_8_t instance
    @param s - u8 * vector under construction
    @param args (vararg) - the (key,value) pair to format
    @return s - the u8 * vector under construction
*/
always_inline u8 *
format_cuckoo_kvp_16_8 (u8 * s, va_list * args)
{
  clib_cuckoo_kv_16_8_t *v = va_arg (*args, clib_cuckoo_kv_16_8_t *);

  if (clib_cuckoo_kv_is_free_16_8 (v))
    {
      s = format (s, " -- empty -- ");
    }
  else
    {
      s =
	format (s, "key %llu%llu value %llu", v->key[0], v->key[1], v->value);
    }
  return s;
}

always_inline u64
clib_cuckoo_hash_16_8 (clib_cuckoo_kv_16_8_t * v)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) v->key, 16);
#else
  u64 tmp = v->key[0] ^ v->key[1];
  return clib_xxhash (tmp);
#endif
}

/** Compare two clib_cuckoo_kv_16_8_t instances
    @param a - first key
    @param b - second key
*/
always_inline int
clib_cuckoo_key_compare_16_8 (u64 * a, u64 * b)
{
#if defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  u64x2 v;
  v = u64x2_load_unaligned (a) ^ u64x2_load_unaligned (b);
  return u64x2_is_all_zero (v);
#else
  return ((a[0] ^ b[0]) | (a[1] ^ b[1])) == 0;
#endif
}

#undef __included_cuckoo_template_h__
#include <vppinfra/cuckoo_template.h>

#endif /* __included_cuckoo_16_8_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
