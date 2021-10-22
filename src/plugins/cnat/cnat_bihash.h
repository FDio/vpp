/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#undef BIHASH_TYPE
#undef BIHASH_KVP_PER_PAGE
#undef BIHASH_32_64_SVM
#undef BIHASH_ENABLE_STATS
#undef BIHASH_KVP_AT_BUCKET_LEVEL
#undef BIHASH_LAZY_INSTANTIATE
#undef BIHASH_BUCKET_PREFETCH_CACHE_LINES
#undef BIHASH_USE_HEAP

#define BIHASH_TYPE			   _40_8
#define BIHASH_KVP_PER_PAGE		   4
#define BIHASH_KVP_AT_BUCKET_LEVEL 1
#define BIHASH_LAZY_INSTANTIATE 1
#define BIHASH_BUCKET_PREFETCH_CACHE_LINES 2
#define BIHASH_USE_HEAP			   1

#ifndef __included_bihash_40_8_h__
#define __included_bihash_40_8_h__

#include <vppinfra/crc32.h>
#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>

typedef struct
{
  u64 key[5];
  u64 value;
} clib_bihash_kv_40_8_t;

static inline void
clib_bihash_mark_free_40_8 (clib_bihash_kv_40_8_t *v)
{
  v->value = 0xFEEDFACE8BADF00DULL;
}

static inline int
clib_bihash_is_free_40_8 (const clib_bihash_kv_40_8_t *v)
{
  if (v->value == 0xFEEDFACE8BADF00DULL)
    return 1;
  return 0;
}

static inline u64
clib_bihash_hash_40_8 (const clib_bihash_kv_40_8_t *v)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) v->key, 40);
#else
  u64 tmp = v->key[0] ^ v->key[1] ^ v->key[2] ^ v->key[3] ^ v->key[4];
  return clib_xxhash (tmp);
#endif
}

static inline u8 *
format_bihash_kvp_40_8 (u8 *s, va_list *args)
{
  clib_bihash_kv_40_8_t *v = va_arg (*args, clib_bihash_kv_40_8_t *);

  s = format (s,
	      "key %llu %llu %llu %llu %llu"
	      "value %llu",
	      v->key[0], v->key[1], v->key[2], v->key[3], v->key[4], v->value);
  return s;
}

static inline int
clib_bihash_key_compare_40_8 (u64 *a, u64 *b)
{
#if defined (CLIB_HAVE_VEC512)
  u64x8 v;
  v = u64x8_load_unaligned (a) ^ u64x8_load_unaligned (b);
  return (u64x8_is_zero_mask (v) & 0x1f) == 0;
#elif defined(CLIB_HAVE_VEC28)
  u64x4 v = { a[4] ^ b[4], 0, 0, 0 };
  v |= u64x4_load_unaligned (a) ^ u64x4_load_unaligned (b);
  return u64x4_is_all_zero (v);
#elif defined(CLIB_HAVE_VEC128) && defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  u64x2 v = { a[4] ^ b[4], 0 };
  v |= u64x2_load_unaligned (a) ^ u64x2_load_unaligned (b);
  v |= u64x2_load_unaligned (a + 2) ^ u64x2_load_unaligned (b + 2);
  return u64x2_is_all_zero (v);
#else
  return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])
	  | (a[4] ^ b[4])) == 0;
#endif
}

#undef __included_bihash_template_h__
#include <vppinfra/bihash_template.h>

typedef clib_bihash_kv_40_8_t cnat_bihash_kv_t;
typedef clib_bihash_40_8_t cnat_bihash_t;

#define cnat_bihash_search_i2_hash	  clib_bihash_search_inline_2_with_hash_40_8
#define cnat_bihash_search_i2		  clib_bihash_search_inline_2_40_8
#define cnat_bihash_add_del		  clib_bihash_add_del_40_8
#define cnat_bihash_add_del_hash	  clib_bihash_add_del_with_hash_40_8
#define cnat_bihash_hash		  clib_bihash_hash_40_8
#define cnat_bihash_prefetch_bucket	  clib_bihash_prefetch_bucket_40_8
#define cnat_bihash_prefetch_data	  clib_bihash_prefetch_data_40_8
#define cnat_bihash_add_with_overwrite_cb clib_bihash_add_with_overwrite_cb_40_8

#endif /* __included_bihash_40_8_h__ */
