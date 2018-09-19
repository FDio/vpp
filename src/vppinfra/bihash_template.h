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

#ifdef BIHASH_32_64_SVM
#undef HAVE_MEMFD_CREATE
#include <vppinfra/linux/syscall.h>
#include <fcntl.h>
#define F_LINUX_SPECIFIC_BASE 1024
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_SEAL_SHRINK (2)
/* Max page size 2**16 due to refcount width  */
#define BIHASH_FREELIST_LENGTH 17
#endif

#define _bv(a,b) a##b
#define __bv(a,b) _bv(a,b)
#define BV(a) __bv(a,BIHASH_TYPE)

#define _bvt(a,b) a##b##_t
#define __bvt(a,b) _bvt(a,b)
#define BVT(a) __bvt(a,BIHASH_TYPE)

#if _LP64 == 0
#define OVERFLOW_ASSERT(x) ASSERT(((x) & 0xFFFFFFFF00000000ULL) == 0)
#define u64_to_pointer(x) (void *)(u32)((x))
#define pointer_to_u64(x) (u64)(u32)((x))
#else
#define OVERFLOW_ASSERT(x)
#define u64_to_pointer(x) (void *)((x))
#define pointer_to_u64(x) (u64)((x))
#endif

typedef struct BV (clib_bihash_value)
{
  union
  {
    BVT (clib_bihash_kv) kvp[BIHASH_KVP_PER_PAGE];
    u64 next_free_as_u64;
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
      u64 refcnt:16;
    };
    u64 as_u64;
  };
} BVT (clib_bihash_bucket);

STATIC_ASSERT_SIZEOF (BVT (clib_bihash_bucket), sizeof (u64));

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  /*
   * Backing store allocation. Since bihash manages its own
   * freelists, we simple dole out memory starting from alloc_arena[alloc_arena_next].
   */
  u64 alloc_arena_next;	/* Next offset from alloc_arena to allocate, definitely NOT a constant */
  u64 alloc_arena_size;	/* Size of the arena */
  /* Two SVM pointers stored as 8-byte integers */
  u64 alloc_lock_as_u64;
  u64 buckets_as_u64;
  /* freelist list-head arrays/vectors */
  u64 freelists_as_u64;
  u32 nbuckets;	/* Number of buckets */
  /* Set when header valid */
  volatile u32 ready;
  u64 pad[2];
}) BVT (clib_bihash_shared_header);
/* *INDENT-ON* */

STATIC_ASSERT_SIZEOF (BVT (clib_bihash_shared_header), 8 * sizeof (u64));

typedef struct
{
  BVT (clib_bihash_bucket) * buckets;
  volatile u32 *alloc_lock;

    BVT (clib_bihash_value) ** working_copies;
  int *working_copy_lengths;
    BVT (clib_bihash_bucket) saved_bucket;

  u32 nbuckets;
  u32 log2_nbuckets;
  u8 *name;

  u64 *freelists;

#if BIHASH_32_64_SVM
    BVT (clib_bihash_shared_header) * sh;
  int memfd;
#else
    BVT (clib_bihash_shared_header) sh;
#endif

  u64 alloc_arena;		/* Base of the allocation arena */

  /**
    * A custom format function to print the Key and Value of bihash_key instead of default hexdump
    */
  format_function_t *fmt_fn;

} BVT (clib_bihash);

#if BIHASH_32_64_SVM
#undef alloc_arena_next
#undef alloc_arena_size
#undef alloc_arena
#undef CLIB_BIHASH_READY_MAGIC
#define alloc_arena_next(h) (((h)->sh)->alloc_arena_next)
#define alloc_arena_size(h) (((h)->sh)->alloc_arena_size)
#define alloc_arena(h) ((h)->alloc_arena)
#define CLIB_BIHASH_READY_MAGIC 0xFEEDFACE
#else
#undef alloc_arena_next
#undef alloc_arena_size
#undef alloc_arena
#undef CLIB_BIHASH_READY_MAGIC
#define alloc_arena_next(h) ((h)->sh.alloc_arena_next)
#define alloc_arena_size(h) ((h)->sh.alloc_arena_size)
#define alloc_arena(h) ((h)->alloc_arena)
#define CLIB_BIHASH_READY_MAGIC 0
#endif

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
  u8 *hp = (u8 *) (uword) alloc_arena (h);
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

  hp = (u8 *) (uword) alloc_arena (h);
  vp = (u8 *) v;

  return vp - hp;
}

void BV (clib_bihash_init)
  (BVT (clib_bihash) * h, char *name, u32 nbuckets, uword memory_size);

#if BIHASH_32_64_SVM
void BV (clib_bihash_master_init_svm)
  (BVT (clib_bihash) * h, char *name, u32 nbuckets, u64 memory_size);
void BV (clib_bihash_slave_init_svm)
  (BVT (clib_bihash) * h, char *name, int fd);
#endif

void BV (clib_bihash_set_kvp_format_fn) (BVT (clib_bihash) * h,
					 format_function_t * fmt_fn);

void BV (clib_bihash_free) (BVT (clib_bihash) * h);

int BV (clib_bihash_add_del) (BVT (clib_bihash) * h,
			      BVT (clib_bihash_kv) * add_v, int is_add);
int BV (clib_bihash_add_or_overwrite_stale) (BVT (clib_bihash) * h,
					     BVT (clib_bihash_kv) * add_v,
					     int (*is_stale_cb) (BVT
								 (clib_bihash_kv)
								 *, void *),
					     void *arg);
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
