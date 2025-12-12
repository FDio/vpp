/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#undef BIHASH_TYPE
#undef BIHASH_KVP_PER_PAGE
#undef BIHASH_32_64_SVM
#undef BIHASH_ENABLE_STATS
#undef BIHASH_KVP_AT_BUCKET_LEVEL
#undef BIHASH_LAZY_INSTANTIATE
#undef BIHASH_BUCKET_PREFETCH_CACHE_LINES

#define BIHASH_TYPE			   _56_8
#define BIHASH_KVP_PER_PAGE		   4
#define BIHASH_KVP_AT_BUCKET_LEVEL	   0
#define BIHASH_LAZY_INSTANTIATE		   1
#define BIHASH_BUCKET_PREFETCH_CACHE_LINES 1

#ifndef __included_bihash_56_8_h__
#define __included_bihash_56_8_h__

#include <vppinfra/crc32.h>
#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>

typedef struct
{
  u64 key[7];
  u64 value;
} clib_bihash_kv_56_8_t;

static inline void
clib_bihash_mark_free_56_8 (clib_bihash_kv_56_8_t *v)
{
  v->value = 0xFEEDFACE8BADF00DULL;
}

static inline int
clib_bihash_is_free_56_8 (const clib_bihash_kv_56_8_t *v)
{
  if (v->value == 0xFEEDFACE8BADF00DULL)
    return 1;
  return 0;
}

static inline u64
clib_bihash_hash_56_8 (const clib_bihash_kv_56_8_t *v)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) v->key, 56);
#else
  u64 tmp = v->key[0] ^ v->key[1] ^ v->key[2] ^ v->key[3] ^ v->key[4] ^
	    v->key[5] ^ v->key[6];
  return clib_xxhash (tmp);
#endif
}

static inline u8 *
format_bihash_kvp_56_8 (u8 *s, va_list *args)
{
  clib_bihash_kv_56_8_t *v = va_arg (*args, clib_bihash_kv_56_8_t *);

  s = format (s, "key %llu %llu %llu %llu %llu %llu %llu value %llu",
	      v->key[0], v->key[1], v->key[2], v->key[3], v->key[4], v->key[5],
	      v->key[6], v->value);
  return s;
}

static inline int
clib_bihash_key_compare_56_8 (u64 *a, u64 *b)
{
#if defined(CLIB_HAVE_VEC512)
  return u64x8_is_equal (u64x8_mask_load_zero (a, 0x7f),
			 u64x8_mask_load_zero (b, 0x7f));
#elif defined(CLIB_HAVE_VEC256) && defined(CLIB_HAVE_VEC256_MASK_LOAD_STORE)
  u64x4 v = { 0 };
  v = u64x4_mask_load_zero (a + 4, 0x7) ^ u64x4_mask_load_zero (b + 4, 0x7);
  v |= u64x4_load_unaligned (a) ^ u64x4_load_unaligned (b);
  return u64x4_is_all_zero (v);
#elif defined(CLIB_HAVE_VEC128) &&                                            \
  defined(CLIB_HAVE_VEC128_UNALIGNED_LOAD_STORE)
  u64x2 v = { 0, a[6] ^ b[6] };
  v |= u64x2_load_unaligned (a) ^ u64x2_load_unaligned (b);
  v |= u64x2_load_unaligned (a + 2) ^ u64x2_load_unaligned (b + 2);
  v |= u64x2_load_unaligned (a + 4) ^ u64x2_load_unaligned (b + 4);
  return u64x2_is_all_zero (v);
#else
  return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3]) |
	  (a[4] ^ b[4]) | (a[5] ^ b[5]) | (a[6] ^ b[6])) == 0;
#endif
}

#undef __included_bihash_template_h__
#include <vppinfra/bihash_template.h>

#endif /* __included_bihash_56_8_h__ */
