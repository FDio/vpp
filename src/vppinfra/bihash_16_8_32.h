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
#undef BIHASH_TYPE
#undef BIHASH_KVP_PER_PAGE
#undef BIHASH_32_64_SVM
#undef BIHASH_ENABLE_STATS
#undef BIHASH_KVP_AT_BUCKET_LEVEL
#undef BIHASH_LAZY_INSTANTIATE
#undef BIHASH_BUCKET_PREFETCH_CACHE_LINES

#define BIHASH_TYPE _16_8_32
#define BIHASH_KVP_PER_PAGE 4
#define BIHASH_KVP_AT_BUCKET_LEVEL 0
#define BIHASH_LAZY_INSTANTIATE 1
#define BIHASH_BUCKET_PREFETCH_CACHE_LINES 1

#define BIHASH_32_64_SVM 1

#ifndef __included_bihash_16_18_32_h__
#define __included_bihash_16_18_32_h__

#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>
#include <vppinfra/crc32.h>

typedef struct
{
  u64 key[2];
  u64 value;
} clib_bihash_kv_16_8_32_t;

static inline int
clib_bihash_is_free_16_8_32 (clib_bihash_kv_16_8_32_t * v)
{
  /* Free values are clib_memset to 0xff, check a bit... */
  if (v->key[0] == ~0ULL && v->value == ~0ULL)
    return 1;
  return 0;
}

static inline u64
clib_bihash_hash_16_8_32 (clib_bihash_kv_16_8_32_t * v)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) v->key, 16);
#else
  u64 tmp = v->key[0] ^ v->key[1];
  return clib_xxhash (tmp);
#endif
}

static inline u8 *
format_bihash_kvp_16_8_32 (u8 * s, va_list * args)
{
  clib_bihash_kv_16_8_32_t *v = va_arg (*args, clib_bihash_kv_16_8_32_t *);

  s = format (s, "key %llu %llu value %llu", v->key[0], v->key[1], v->value);
  return s;
}

static inline int
clib_bihash_key_compare_16_8_32 (u64 * a, u64 * b)
{
#ifdef CLIB_HAVE_VEC_SCALABLE
  return u8xn_memcmp ((u8 *) a, (u8 *) b, 16);
#elif defined(CLIB_HAVE_VEC128) &&                                            \
  defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  u64x2 v;
  v = u64x2_load_unaligned (a) ^ u64x2_load_unaligned (b);
  return u64x2_is_all_zero (v);
#else
  return ((a[0] ^ b[0]) | (a[1] ^ b[1])) == 0;
#endif
}

#undef __included_bihash_template_h__
#include <vppinfra/bihash_template.h>

#endif /* __included_bihash_16_8_32_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
