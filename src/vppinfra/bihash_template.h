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
#include <vppinfra/linux/syscall.h>
#include <fcntl.h>
#define F_LINUX_SPECIFIC_BASE 1024
#define F_ADD_SEALS (F_LINUX_SPECIFIC_BASE + 9)
#define F_SEAL_SHRINK (2)
/* Max page size 2**16 due to refcount width  */
#define BIHASH_FREELIST_LENGTH 17
#endif

/* default is 2MB, use 30 for 1GB */
#ifndef BIHASH_LOG2_HUGEPAGE_SIZE
#define BIHASH_LOG2_HUGEPAGE_SIZE 21
#endif

#define _bv(a,b) a##b
#define __bv(a,b) _bv(a,b)
#define BV(a) __bv(a,BIHASH_TYPE)

#define _bvt(a,b) a##b##_t
#define __bvt(a,b) _bvt(a,b)
#define BVT(a) __bvt(a,BIHASH_TYPE)

#define _bvs(a,b) struct a##b
#define __bvs(a,b) _bvs(a,b)
#define BVS(a) __bvs(a,BIHASH_TYPE)

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
      u64 refcnt : 13;	  /* limit kvp per bucket */
      u64 generation : 5; /* incremented each update */
    };
    u64 as_u64;
  };
} BVT (clib_bihash_bucket);

STATIC_ASSERT_SIZEOF (BVT (clib_bihash_bucket), sizeof (u64));

typedef CLIB_PACKED (struct {
  /*
   * Backing store allocation. Since bihash manages its own
   * freelists, we simple dole out memory starting from alloc_arena[alloc_arena_next].
   */
  u64 alloc_arena_next;	/* Next offset from alloc_arena to allocate, definitely NOT a constant */
  u64 alloc_arena_size;	/* Size of the arena */
  u64 alloc_arena_mapped;	/* Size of the mapped memory in the arena */
  /* Two SVM pointers stored as 8-byte integers */
  u64 alloc_lock_as_u64;
  u64 buckets_as_u64;
  /* freelist list-head arrays/vectors */
  u64 freelists_as_u64;
  u32 nbuckets;	/* Number of buckets */
  /* Set when header valid */
  volatile u32 ready;
  u64 pad[1];
}) BVT (clib_bihash_shared_header);

STATIC_ASSERT_SIZEOF (BVT (clib_bihash_shared_header), 8 * sizeof (u64));

typedef
BVS (clib_bihash_alloc_chunk)
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* chunk size */
  uword size;

  /* pointer to the next allocation */
  u8 *next_alloc;

  /* number of bytes left in this chunk */
  uword bytes_left;

  /* doubly linked list of heap allocated chunks */
  BVS (clib_bihash_alloc_chunk) * prev, *next;

} BVT (clib_bihash_alloc_chunk);

typedef
BVS (clib_bihash)
{
  BVT (clib_bihash_bucket) * buckets;
  volatile u32 *alloc_lock;

  BVT (clib_bihash_value) ** working_copies;
  int *working_copy_lengths;
  BVT (clib_bihash_bucket) saved_bucket;

  u32 nbuckets;
  u32 log2_nbuckets;
  u64 memory_size;
  u8 *name;
  format_function_t *fmt_fn;
  void *heap;
  BVT (clib_bihash_alloc_chunk) * chunks;

  u64 *freelists;

#if BIHASH_32_64_SVM
  BVT (clib_bihash_shared_header) * sh;
  int memfd;
#else
  BVT (clib_bihash_shared_header) sh;
#endif

  u64 alloc_arena;		/* Base of the allocation arena */
  volatile u8 instantiated;
  u8 dont_add_to_all_bihash_list;

  /**
    * A custom format function to print the Key and Value of bihash_key instead of default hexdump
    */
  format_function_t *kvp_fmt_fn;

  /** Optional statistics-gathering callback */
#if BIHASH_ENABLE_STATS
  void (*inc_stats_callback) (BVS (clib_bihash) *, int stat_id, u64 count);

  /** Statistics callback context (e.g. address of stats data structure) */
  void *inc_stats_context;
#endif

} BVT (clib_bihash);

typedef struct
{
  BVT (clib_bihash) * h;
  char *name;
  u32 nbuckets;
  uword memory_size;
  format_function_t *kvp_fmt_fn;
  u8 instantiate_immediately;
  u8 dont_add_to_all_bihash_list;
} BVT (clib_bihash_init2_args);

extern void **clib_all_bihashes;

#if BIHASH_32_64_SVM
#undef alloc_arena_next
#undef alloc_arena_size
#undef alloc_arena_mapped
#undef alloc_arena
#undef CLIB_BIHASH_READY_MAGIC
#define alloc_arena_next(h) (((h)->sh)->alloc_arena_next)
#define alloc_arena_size(h) (((h)->sh)->alloc_arena_size)
#define alloc_arena_mapped(h) (((h)->sh)->alloc_arena_mapped)
#define alloc_arena(h) ((h)->alloc_arena)
#define CLIB_BIHASH_READY_MAGIC 0xFEEDFACE
#else
#undef alloc_arena_next
#undef alloc_arena_size
#undef alloc_arena_mapped
#undef alloc_arena
#undef CLIB_BIHASH_READY_MAGIC
#define alloc_arena_next(h) ((h)->sh.alloc_arena_next)
#define alloc_arena_size(h) ((h)->sh.alloc_arena_size)
#define alloc_arena_mapped(h) ((h)->sh.alloc_arena_mapped)
#define alloc_arena(h) ((h)->alloc_arena)
#define CLIB_BIHASH_READY_MAGIC 0
#endif

#ifndef BIHASH_STAT_IDS
#define BIHASH_STAT_IDS 1

#define foreach_bihash_stat                     \
_(alloc_add)                                    \
_(add)                                          \
_(split_add)                                    \
_(replace)                                      \
_(update)                                       \
_(del)                                          \
_(del_free)                                     \
_(linear)                                       \
_(resplit)                                      \
_(working_copy_lost)                            \
_(splits)			/* must be last */

typedef enum
{
#define _(a) BIHASH_STAT_##a,
  foreach_bihash_stat
#undef _
    BIHASH_STAT_N_STATS,
} BVT (clib_bihash_stat_id);
#endif /* BIHASH_STAT_IDS */

static inline void BV (clib_bihash_increment_stat) (BVT (clib_bihash) * h,
						    int stat_id, u64 count)
{
#if BIHASH_ENABLE_STATS
  if (PREDICT_FALSE (h->inc_stats_callback != 0))
    h->inc_stats_callback (h, stat_id, count);
#endif
}

#if BIHASH_ENABLE_STATS
static inline void BV (clib_bihash_set_stats_callback)
  (BVT (clib_bihash) * h, void (*cb) (BVT (clib_bihash) *, int, u64),
   void *ctx)
{
  h->inc_stats_callback = cb;
  h->inc_stats_context = ctx;
}
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
  BVT (clib_bihash_bucket) mask = { .lock = 1 };
  u64 old;

try_again:
  old = clib_atomic_fetch_or (&b->as_u64, mask.as_u64);

  if (PREDICT_FALSE (old & mask.as_u64))
    {
      /* somebody else flipped the bit, try again */
      CLIB_PAUSE ();
      goto try_again;
    }
}

static inline void BV (clib_bihash_unlock_bucket)
  (BVT (clib_bihash_bucket) * b)
{
  b->lock = 0;
  clib_atomic_store_rel_n (&b->as_u64, b->as_u64);
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
  if (BIHASH_KVP_AT_BUCKET_LEVEL == 0)
    return b->offset == 0;
  else
    return (b->log2_pages == 0 && b->refcnt == 1);
}

static inline uword BV (clib_bihash_get_offset) (BVT (clib_bihash) * h,
						 void *v)
{
  u8 *hp, *vp;

  hp = (u8 *) (uword) alloc_arena (h);
  vp = (u8 *) v;

  return vp - hp;
}

#define BIHASH_ADD 1
#define BIHASH_DEL 0

void BV (clib_bihash_init)
  (BVT (clib_bihash) * h, char *name, u32 nbuckets, uword memory_size);

void BV (clib_bihash_init2) (BVT (clib_bihash_init2_args) * a);

#if BIHASH_32_64_SVM
void BV (clib_bihash_initiator_init_svm)
  (BVT (clib_bihash) * h, char *name, u32 nbuckets, u64 memory_size);
void BV (clib_bihash_responder_init_svm)
  (BVT (clib_bihash) * h, char *name, int fd);
#endif

void BV (clib_bihash_set_kvp_format_fn) (BVT (clib_bihash) * h,
					 format_function_t * kvp_fmt_fn);

void BV (clib_bihash_free) (BVT (clib_bihash) * h);

int BV (clib_bihash_add_del) (BVT (clib_bihash) * h,
			      BVT (clib_bihash_kv) * add_v, int is_add);

int BV (clib_bihash_add_del_with_hash) (BVT (clib_bihash) * h,
					BVT (clib_bihash_kv) * add_v, u64 hash,
					int is_add);
int BV (clib_bihash_add_or_overwrite_stale) (BVT (clib_bihash) * h,
					     BVT (clib_bihash_kv) * add_v,
					     int (*is_stale_cb) (BVT
								 (clib_bihash_kv)
								 *, void *),
					     void *arg);
int BV (clib_bihash_add_with_overwrite_cb) (
  BVT (clib_bihash) * h, BVT (clib_bihash_kv) * add_v,
  void (*overwrite_cb) (BVT (clib_bihash_kv) *, void *), void *arg);
int BV (clib_bihash_search) (BVT (clib_bihash) * h,
			     BVT (clib_bihash_kv) * search_v,
			     BVT (clib_bihash_kv) * return_v);

int BV (clib_bihash_is_initialised) (const BVT (clib_bihash) * h);

#define BIHASH_WALK_STOP 0
#define BIHASH_WALK_CONTINUE 1

typedef
  int (*BV (clib_bihash_foreach_key_value_pair_cb)) (BVT (clib_bihash_kv) *,
						     void *);
void BV (clib_bihash_foreach_key_value_pair) (BVT (clib_bihash) * h,
					      BV
					      (clib_bihash_foreach_key_value_pair_cb)
					      cb, void *arg);
void *clib_all_bihash_set_heap (void);
void clib_bihash_copied (void *dst, void *src);

format_function_t BV (format_bihash);
format_function_t BV (format_bihash_kvp);
format_function_t BV (format_bihash_lru);

static inline
BVT (clib_bihash_bucket) *
BV (clib_bihash_get_bucket) (BVT (clib_bihash) * h, u64 hash)
{
#if BIHASH_KVP_AT_BUCKET_LEVEL
  uword offset;
  offset = (hash & (h->nbuckets - 1));
  offset = offset * (sizeof (BVT (clib_bihash_bucket))
		     + (BIHASH_KVP_PER_PAGE * sizeof (BVT (clib_bihash_kv))));
  return ((BVT (clib_bihash_bucket) *) (((u8 *) h->buckets) + offset));
#else
  return h->buckets + (hash & (h->nbuckets - 1));
#endif
}

static inline int
BV (clib_bihash_search_need_retry) (BVT (clib_bihash_bucket) * b,
				    BVT (clib_bihash_bucket) * savedb)
{
  BVT (clib_bihash_bucket) tmpb;
  tmpb.as_u64 = clib_atomic_load_relax_n (&b->as_u64);
  if (PREDICT_TRUE (tmpb.as_u64 == savedb->as_u64))
    return 0;

  savedb->as_u64 = tmpb.as_u64;
  return 1;
}

static inline void
BV (clib_bihash_wait_bucket_lock) (BVT (clib_bihash_bucket) * b,
				   BVT (clib_bihash_bucket) * savedb)
{
  while (PREDICT_FALSE (savedb->lock))
    {
      CLIB_PAUSE ();
      savedb->as_u64 = clib_atomic_load_acq_n (&b->as_u64);
    }
}

static inline int BV (clib_bihash_search_inline_with_hash)
  (BVT (clib_bihash) * h, u64 hash, BVT (clib_bihash_kv) * key_result)
{
  BVT (clib_bihash_kv) rv;
  BVT (clib_bihash_value) * v;
  BVT (clib_bihash_bucket) * b, localb;
  int i, limit;

  static const BVT (clib_bihash_bucket) mask = {
    .linear_search = 1,
    .log2_pages = -1
  };

#if BIHASH_LAZY_INSTANTIATE
  if (PREDICT_FALSE (h->instantiated == 0))
    return -1;
#endif

  b = BV (clib_bihash_get_bucket) (h, hash);
  localb.as_u64 = clib_atomic_load_acq_n (&b->as_u64);

bucket_changed_retry:
  BV (clib_bihash_wait_bucket_lock) (b, &localb);

  if (PREDICT_FALSE (BV (clib_bihash_bucket_is_empty) (&localb)))
    return -1;

  v = BV (clib_bihash_get_value) (h, localb.offset);

  /* If the bucket has unresolvable collisions, use linear search */
  limit = BIHASH_KVP_PER_PAGE;

  if (PREDICT_FALSE (localb.as_u64 & mask.as_u64))
    {
      if (PREDICT_FALSE (localb.linear_search))
	limit <<= localb.log2_pages;
      else
	v += extract_bits (hash, h->log2_nbuckets, localb.log2_pages);
    }

  for (i = 0; i < limit; i++)
    {
      if (BV (clib_bihash_key_compare) (v->kvp[i].key, key_result->key))
	{
	  rv = v->kvp[i];
	  if (BV (clib_bihash_is_free) (&rv))
	    return -1;

	  *key_result = rv;

	  if (PREDICT_FALSE (BV (clib_bihash_search_need_retry) (b, &localb)))
	    goto bucket_changed_retry;

	  return 0;
	}
    }

  /* Could have been reading state in the middle of split operation */
  if (PREDICT_FALSE (BV (clib_bihash_search_need_retry) (b, &localb)))
    goto bucket_changed_retry;

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
  CLIB_PREFETCH (BV (clib_bihash_get_bucket) (h, hash),
		 BIHASH_BUCKET_PREFETCH_CACHE_LINES * CLIB_CACHE_LINE_BYTES,
		 LOAD);
}

static inline void BV (clib_bihash_prefetch_data)
  (BVT (clib_bihash) * h, u64 hash)
{
  BVT (clib_bihash_value) * v;
  BVT (clib_bihash_bucket) * b;

#if BIHASH_LAZY_INSTANTIATE
  if (PREDICT_FALSE (h->instantiated == 0))
    return;
#endif

  b = BV (clib_bihash_get_bucket) (h, hash);

  if (PREDICT_FALSE (BV (clib_bihash_bucket_is_empty) (b)))
    return;

  v = BV (clib_bihash_get_value) (h, b->offset);

  if (PREDICT_FALSE (b->log2_pages && b->linear_search == 0))
    v += extract_bits (hash, h->log2_nbuckets, b->log2_pages);

  CLIB_PREFETCH (v, BIHASH_KVP_PER_PAGE * sizeof (BVT (clib_bihash_kv)),
		 LOAD);
}

static inline int BV (clib_bihash_search_inline_2_with_hash)
  (BVT (clib_bihash) * h,
   u64 hash, BVT (clib_bihash_kv) * search_key, BVT (clib_bihash_kv) * valuep)
{
  BVT (clib_bihash_kv) rv;
  BVT (clib_bihash_value) * v;
  BVT (clib_bihash_bucket) * b, localb;
  int i, limit;

  static const BVT (clib_bihash_bucket) mask = {
    .linear_search = 1,
    .log2_pages = -1
  };

  ASSERT (valuep);

#if BIHASH_LAZY_INSTANTIATE
  if (PREDICT_FALSE (h->instantiated == 0))
    return -1;
#endif

  b = BV (clib_bihash_get_bucket) (h, hash);
  localb.as_u64 = clib_atomic_load_acq_n (&b->as_u64);

bucket_changed_retry:
  BV (clib_bihash_wait_bucket_lock) (b, &localb);

  if (PREDICT_FALSE (BV (clib_bihash_bucket_is_empty) (&localb)))
    return -1;

  v = BV (clib_bihash_get_value) (h, localb.offset);

  /* If the bucket has unresolvable collisions, use linear search */
  limit = BIHASH_KVP_PER_PAGE;

  if (PREDICT_FALSE (localb.as_u64 & mask.as_u64))
    {
      if (PREDICT_FALSE (localb.linear_search))
	limit <<= localb.log2_pages;
      else
	v += extract_bits (hash, h->log2_nbuckets, localb.log2_pages);
    }

  for (i = 0; i < limit; i++)
    {
      if (BV (clib_bihash_key_compare) (v->kvp[i].key, search_key->key))
	{
	  rv = v->kvp[i];
	  if (BV (clib_bihash_is_free) (&rv))
	    return -1;

	  *valuep = rv;

	  if (PREDICT_FALSE (BV (clib_bihash_search_need_retry) (b, &localb)))
	    goto bucket_changed_retry;

	  return 0;
	}
    }

  /* Could have been reading state in the middle of split operation */
  if (PREDICT_FALSE (BV (clib_bihash_search_need_retry) (b, &localb)))
    goto bucket_changed_retry;

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
