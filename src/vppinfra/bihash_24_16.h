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
#undef BIHASH_USE_HEAP

#define BIHASH_TYPE _24_16
#define BIHASH_KVP_PER_PAGE 4
#define BIHASH_KVP_AT_BUCKET_LEVEL 0
#define BIHASH_LAZY_INSTANTIATE 1
#define BIHASH_BUCKET_PREFETCH_CACHE_LINES 1
#define BIHASH_USE_HEAP 1

#ifndef __included_bihash_24_16_h__
#define __included_bihash_24_16_h__

#include <vppinfra/crc32.h>
#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>

typedef struct
{
  u64 key[3];
  u64 value[2];
} clib_bihash_kv_24_16_t;

static inline int
clib_bihash_is_free_24_16 (const clib_bihash_kv_24_16_t * v)
{
  /* Free values are clib_memset to 0xff, check a bit... */
  if (v->key[0] == ~0ULL && v->value[0] == ~0ULL && v->value[1] == ~0ULL)
    return 1;
  return 0;
}

static inline u64
clib_bihash_hash_24_16 (const clib_bihash_kv_24_16_t * v)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) v->key, 24);
#else
  u64 tmp = v->key[0] ^ v->key[1] ^ v->key[2];
  return clib_xxhash (tmp);
#endif
}

static inline u8 *
format_bihash_kvp_24_16 (u8 * s, va_list * args)
{
  clib_bihash_kv_24_16_t *v = va_arg (*args, clib_bihash_kv_24_16_t *);

  s = format (s, "key %llu %llu %llu value %llu %llu",
	      v->key[0], v->key[1], v->key[2], v->value[0], v->value[1]);
  return s;
}

static inline int
clib_bihash_key_compare_24_16 (u64 * a, u64 * b)
{
#if defined (CLIB_HAVE_VEC512)
  u64x8 v = u64x8_load_unaligned (a) ^ u64x8_load_unaligned (b);
  return (u64x8_is_zero_mask (v) & 0x7) == 0;
#elif defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  u64x2 v = { a[2] ^ b[2], 0 };
  v |= u64x2_load_unaligned (a) ^ u64x2_load_unaligned (b);
  return u64x2_is_all_zero (v);
#else
  return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) == 0;
#endif
}

#undef __included_bihash_template_h__
#include <vppinfra/bihash_template.h>

#endif /* __included_bihash_24_16_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
