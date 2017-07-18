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
#undef BIHASH_KVP_CACHE_SIZE
#undef BIHASH_KVP_PER_PAGE

#define BIHASH_TYPE _48_8
#define BIHASH_KVP_PER_PAGE 4
#define BIHASH_KVP_CACHE_SIZE 2

#ifndef __included_bihash_48_8_h__
#define __included_bihash_48_8_h__

#include <vppinfra/crc32.h>
#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/xxhash.h>

typedef struct
{
  u64 key[6];
  u64 value;
} clib_bihash_kv_48_8_t;

static inline int
clib_bihash_is_free_48_8 (const clib_bihash_kv_48_8_t * v)
{
  /* Free values are memset to 0xff, check a bit... */
  if (v->key[0] == ~0ULL && v->value == ~0ULL)
    return 1;
  return 0;
}

static inline u64
clib_bihash_hash_48_8 (const clib_bihash_kv_48_8_t * v)
{
#ifdef clib_crc32c_uses_intrinsics
  return clib_crc32c ((u8 *) v->key, 48);
#else
  u64 tmp = v->key[0] ^ v->key[1] ^ v->key[2] ^ v->key[3] ^ v->key[4]
    ^ v->key[5];
  return clib_xxhash (tmp);
#endif
}

static inline u8 *
format_bihash_kvp_48_8 (u8 * s, va_list * args)
{
  clib_bihash_kv_48_8_t *v = va_arg (*args, clib_bihash_kv_48_8_t *);

  s = format (s, "key %llu %llu %llu %llu %llu %llu value %llu", v->key[0],
	      v->key[1], v->key[2], v->key[3], v->key[4], v->key[5],
	      v->value);
  return s;
}

static inline int
clib_bihash_key_compare_48_8 (const u64 * a, const u64 * b)
{
  return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3])
	  | (a[4] ^ b[4]) | (a[5] ^ b[5])) == 0;
}

#undef __included_bihash_template_h__
#include <vppinfra/bihash_template.h>

#endif /* __included_bihash_48_8_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
