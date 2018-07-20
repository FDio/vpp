/*
  Copyright (c) 2014 Cisco and/or its affiliates.

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

/** @cond DOCUMENTATION_IS_IN_BIHASH_DOC_H */

/*
 * Note: to instantiate the template multiple times in a single file,
 * #undef __included_bihash_template_h__...
 */
#ifndef __included_bihash_template_h__
#define __included_bihash_template_h__

#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/cache.h>
#include <vppinfra/lock.h>

#ifndef BIHASH_TYPE
#error BIHASH_TYPE not defined
#endif

#define _bv(a,b) a##b
#define __bv(a,b) _bv(a,b)
#define BV(a) __bv(a,BIHASH_TYPE)

#define _bvt(a,b) a##b##_t
#define __bvt(a,b) _bvt(a,b)
#define BVT(a) __bvt(a,BIHASH_TYPE)

typedef struct BV (clib_bihash_value)
{
  union
  {
    BVT (clib_bihash_kv) kvp[BIHASH_KVP_PER_PAGE];
    struct BV (clib_bihash_value) * next_free;
  };
} BVT (clib_bihash_value);

#define BIHASH_BUCKET_OFFSET_BITS 36

typedef struct
{
  union
  {
    struct
    {
      u64 offset:BIHASH_BUCKET_OFFSET_BITS;
      u64 lock:1;
      u64 linear_search:1;
      u64 log2_pages:8;
      i64 refcnt:16;
    };
    u64 as_u64;
  };
} BVT (clib_bihash_bucket);

STATIC_ASSERT_SIZEOF (BVT (clib_bihash_bucket), sizeof (u64));

typedef struct
{
  BVT (clib_bihash_value) * values;
  BVT (clib_bihash_bucket) * buckets;
  volatile u32 *alloc_lock;

    BVT (clib_bihash_value) ** working_copies;
  int *working_copy_lengths;
    BVT (clib_bihash_bucket) saved_bucket;

  u32 nbuckets;
  u32 log2_nbuckets;
  u8 *name;

  u64 cache_hits;
  u64 cache_misses;

    BVT (clib_bihash_value) ** freelists;

  /*
   * Backing store allocation. Since bihash manages its own
   * freelists, we simple dole out memory at alloc_arena_next.
   */
  uword alloc_arena;
  uword alloc_arena_next;
  uword alloc_arena_size;

  /**
    * A custom format function to print the Key and Value of bihash_key instead of default hexdump
    */
  format_function_t *fmt_fn;

} BVT (clib_bihash);

static inline void BV (clib_bihash_alloc_lock) (BVT (clib_bihash) * h)
{
  while (__atomic_test_and_set (h->alloc_lock, __ATOMIC_ACQUIRE))
    CLIB_PAUSE ();
}

static inline void BV (clib_bihash_alloc_unlock) (BVT (clib_bihash) * h)
{
  __atomic_clear (h->alloc_lock, __ATOMIC_RELEASE);
}

static inline void BV (clib_bihash_lock_bucket) (BVT (clib_bihash_bucket) * b)
{
  BVT (clib_bihash_bucket) unlocked_bucket, locked_bucket;

  do
    {
      locked_bucket.as_u64 = unlocked_bucket.as_u64 = b->as_u64;
      unlocked_bucket.lock = 0;
      locked_bucket.lock = 1;
      CLIB_PAUSE ();
    }
  while (__atomic_compare_exchange_n (&b->as_u64, &unlocked_bucket.as_u64,
				      locked_bucket.as_u64, 1 /* weak */ ,
				      __ATOMIC_ACQUIRE,
				      __ATOMIC_ACQUIRE) == 0);
}

static inline void BV (clib_bihash_unlock_bucket)
  (BVT (clib_bihash_bucket) * b)
{
  CLIB_MEMORY_BARRIER ();
  b->lock = 0;
}

static inline void *BV (clib_bihash_get_value) (BVT (clib_bihash) * h,
						uword offset)
{
  u8 *hp = (u8 *) h->alloc_arena;
  u8 *vp = hp + offset;

  return (void *) vp;
}

static inline int BV (clib_bihash_bucket_is_empty)
  (BVT (clib_bihash_bucket) * b)
{
  /* Note: applied to locked buckets, test offset */
  return b->offset == 0;
}

static inline uword BV (clib_bihash_get_offset) (BVT (clib_bihash) * h,
						 void *v)
{
  u8 *hp, *vp;

  hp = (u8 *) h->alloc_arena;
  vp = (u8 *) v;

  return vp - hp;
}

void BV (clib_bihash_init)
  (BVT (clib_bihash) * h, char *name, u32 nbuckets, uword memory_size);

void BV (clib_bihash_set_kvp_format_fn) (BVT (clib_bihash) * h,
					 format_function_t * fmt_fn);

void BV (clib_bihash_free) (BVT (clib_bihash) * h);

int BV (clib_bihash_add_del) (BVT (clib_bihash) * h,
			      BVT (clib_bihash_kv) * add_v, int is_add);
int BV (clib_bihash_search) (BVT (clib_bihash) * h,
			     BVT (clib_bihash_kv) * search_v,
			     BVT (clib_bihash_kv) * return_v);

void BV (clib_bihash_foreach_key_value_pair) (BVT (clib_bihash) * h,
					      void *callback, void *arg);

format_function_t BV (format_bihash);
format_function_t BV (format_bihash_kvp);
format_function_t BV (format_bihash_lru);

static inline int BV (clib_bihash_search_inline_with_hash)
  (BVT (clib_bihash) * h, u64 hash, BVT (clib_bihash_kv) * key_result)
{
  u32 bucket_index;
  BVT (clib_bihash_value) * v;
  BVT (clib_bihash_bucket) * b;
  int i, limit;

  bucket_index = hash & (h->nbuckets - 1);
  b = &h->buckets[bucket_index];

  if (PREDICT_FALSE (BV (clib_bihash_bucket_is_empty) (b)))
    return -1;

  if (PREDICT_FALSE (b->lock))
    {
      volatile BVT (clib_bihash_bucket) * bv = b;
      while (bv->lock)
	CLIB_PAUSE ();
    }

  hash >>= h->log2_nbuckets;

  v = BV (clib_bihash_get_value) (h, b->offset);

  /* If the bucket has unresolvable collisions, use linear search */
  limit = BIHASH_KVP_PER_PAGE;
  v += (b->linear_search == 0) ? hash & ((1 << b->log2_pages) - 1) : 0;
  if (PREDICT_FALSE (b->linear_search))
    limit <<= b->log2_pages;

  for (i = 0; i < limit; i++)
    {
      if (BV (clib_bihash_key_compare) (v->kvp[i].key, key_result->key))
	{
	  *key_result = v->kvp[i];
	  return 0;
	}
    }
  return -1;
}

static inline int BV (clib_bihash_search_inline)
  (BVT (clib_bihash) * h, BVT (clib_bihash_kv) * key_result)
{
  u64 hash;

  hash = BV (clib_bihash_hash) (key_result);

  return BV (clib_bihash_search_inline_with_hash) (h, hash, key_result);
}

static inline void BV (clib_bihash_prefetch_bucket)
  (BVT (clib_bihash) * h, u64 hash)
{
  u32 bucket_index;
  BVT (clib_bihash_bucket) * b;

  bucket_index = hash & (h->nbuckets - 1);
  b = &h->buckets[bucket_index];

  CLIB_PREFETCH (b, CLIB_CACHE_LINE_BYTES, READ);
}

static inline void BV (clib_bihash_prefetch_data)
  (BVT (clib_bihash) * h, u64 hash)
{
  u32 bucket_index;
  BVT (clib_bihash_value) * v;
  BVT (clib_bihash_bucket) * b;

  bucket_index = hash & (h->nbuckets - 1);
  b = &h->buckets[bucket_index];

  if (PREDICT_FALSE (BV (clib_bihash_bucket_is_empty) (b)))
    return;

  hash >>= h->log2_nbuckets;
  v = BV (clib_bihash_get_value) (h, b->offset);

  v += (b->linear_search == 0) ? hash & ((1 << b->log2_pages) - 1) : 0;

  CLIB_PREFETCH (v, CLIB_CACHE_LINE_BYTES, READ);
}

static inline int BV (clib_bihash_search_inline_2_with_hash)
  (BVT (clib_bihash) * h,
   u64 hash, BVT (clib_bihash_kv) * search_key, BVT (clib_bihash_kv) * valuep)
{
  u32 bucket_index;
  BVT (clib_bihash_value) * v;
  BVT (clib_bihash_bucket) * b;
  int i, limit;

  ASSERT (valuep);

  bucket_index = hash & (h->nbuckets - 1);
  b = &h->buckets[bucket_index];

  if (PREDICT_FALSE (BV (clib_bihash_bucket_is_empty) (b)))
    return -1;

  if (PREDICT_FALSE (b->lock))
    {
      volatile BVT (clib_bihash_bucket) * bv = b;
      while (bv->lock)
	CLIB_PAUSE ();
    }

  hash >>= h->log2_nbuckets;
  v = BV (clib_bihash_get_value) (h, b->offset);

  /* If the bucket has unresolvable collisions, use linear search */
  limit = BIHASH_KVP_PER_PAGE;
  v += (b->linear_search == 0) ? hash & ((1 << b->log2_pages) - 1) : 0;
  if (PREDICT_FALSE (b->linear_search))
    limit <<= b->log2_pages;

  for (i = 0; i < limit; i++)
    {
      if (BV (clib_bihash_key_compare) (v->kvp[i].key, search_key->key))
	{
	  *valuep = v->kvp[i];
	  return 0;
	}
    }
  return -1;
}

static inline int BV (clib_bihash_search_inline_2)
  (BVT (clib_bihash) * h,
   BVT (clib_bihash_kv) * search_key, BVT (clib_bihash_kv) * valuep)
{
  u64 hash;

  hash = BV (clib_bihash_hash) (search_key);

  return BV (clib_bihash_search_inline_2_with_hash) (h, hash, search_key,
						     valuep);
}


#endif /* __included_bihash_template_h__ */

/** @endcond */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
