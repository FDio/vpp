/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */
#undef BIHASH_TYPE
#undef BIHASH_KVP_PER_PAGE
#undef BIHASH_32_64_SVM
#undef BIHASH_ENABLE_STATS
#undef BIHASH_KVP_AT_BUCKET_LEVEL
#undef BIHASH_LAZY_INSTANTIATE
#undef BIHASH_BUCKET_PREFETCH_CACHE_LINES
#undef BIHASH_USE_HEAP

#define BIHASH_TYPE			   _12_4
#define BIHASH_KVP_PER_PAGE		   4
#define BIHASH_KVP_AT_BUCKET_LEVEL	   0
#define BIHASH_LAZY_INSTANTIATE		   1
#define BIHASH_BUCKET_PREFETCH_CACHE_LINES 1
#define BIHASH_USE_HEAP			   1

#ifndef __included_bihash_12_4_h__
#define __included_bihash_12_4_h__

#include <vppinfra/crc32.h>
#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>

typedef union
{
  struct
  {
    u32 key[3];
    u32 value;
  };
  u64 as_u64[2];
} clib_bihash_kv_12_4_t;

static inline void
clib_bihash_mark_free_12_4 (clib_bihash_kv_12_4_t *v)
{
  v->value = 0xFEEDFACE;
}

static inline int
clib_bihash_is_free_12_4 (const clib_bihash_kv_12_4_t *v)
{
  if (v->value == 0xFEEDFACE)
    return 1;
  return 0;
}

static inline u64
clib_bihash_hash_12_4 (const clib_bihash_kv_12_4_t *v)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) v->key, 12);
#else
  u64 tmp = v->as_u64[0] ^ v->key[2];
  return clib_xxhash (tmp);
#endif
}

static inline u8 *
format_bihash_kvp_12_4 (u8 *s, va_list *args)
{
  clib_bihash_kv_12_4_t *v = va_arg (*args, clib_bihash_kv_12_4_t *);

  s = format (s, "key %u %u %u value %u", v->key[0], v->key[1], v->key[2],
	      v->value);
  return s;
}

static inline int
clib_bihash_key_compare_12_4 (u32 *a, u32 *b)
{
#if defined(CLIB_HAVE_VEC128)
  u32x4 v = (*(u32x4u *) a) ^ (*(u32x4u *) b);
  v[3] = 0;
  return u32x4_is_all_zero (v);
#else
  return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) == 0;
#endif
}

#undef __included_bihash_template_h__
#include <vppinfra/bihash_template.h>

#endif /* __included_bihash_12_4_h__ */
