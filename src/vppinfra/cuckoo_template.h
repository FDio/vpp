/*
  Copyright (c) 2017 Cisco and/or its affiliates.

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

/*
 * cuckoo hash implementation based on paper
 * 'Algorithmic Improvements for Fast Concurrent Cuckoo Hashing'
 * by Xiaozhou Li, David G. Andersen, Michael Kaminsky, Michael J. Freedman
 * and their libcuckoo implementation (https://github.com/efficient/libcuckoo)
 */

/*
 * Note: to instantiate the template multiple times in a single file,
 * #undef __included_cuckoo_template_h__...
 */
#ifndef __included_cuckoo_template_h__
#define __included_cuckoo_template_h__

#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>
#include <vppinfra/cuckoo_8_8.h>

#ifndef CLIB_CUCKOO_TYPE
#error CLIB_CUCKOO_TYPE not defined
#endif

#ifndef CLIB_CUCKOO_BFS_MAX_STEPS
#error CLIB_CUCKOO_BFS_MAX_STEPS not defined
#endif

#ifndef CLIB_CUCKOO_KVP_PER_BUCKET
#error CLIB_CUCKOO_KVP_PER_BUCKET not defined
#endif

#ifndef CLIB_CUCKOO_LOG2_KVP_PER_BUCKET
#error CLIB_CUCKOO_LOG2_KVP_PER_BUCKET not defined
#endif

#ifndef CLIB_CUCKOO_BFS_MAX_PATH_LENGTH
#error CLIB_CUCKOO_BFS_MAX_PATH_LENGTH not defined
#endif

STATIC_ASSERT (CLIB_CUCKOO_KVP_PER_BUCKET ==
	       (1 << CLIB_CUCKOO_LOG2_KVP_PER_BUCKET),
	       "CLIB_CUCKOO_KVP_PER_BUCKET != (1 << CLIB_CUCKOO_LOG2_KVP_PER_BUCKET");

#define _cv(a, b) a##b
#define __cv(a, b) _cv (a, b)
#define CV(a) __cv (a, CLIB_CUCKOO_TYPE)

#define _cvt(a, b) a##b##_t
#define __cvt(a, b) _cvt (a, b)
#define CVT(a) __cvt (a, CLIB_CUCKOO_TYPE)

typedef u64 clib_cuckoo_bucket_aux_t;

#define CLIB_CUCKOO_USE_COUNT_BIT_WIDTH (1 + CLIB_CUCKOO_LOG2_KVP_PER_BUCKET)

always_inline u64
clib_cuckoo_bucket_aux_get_version (clib_cuckoo_bucket_aux_t aux)
{
  return aux >> (1 + CLIB_CUCKOO_USE_COUNT_BIT_WIDTH);
}

always_inline int
clib_cuckoo_bucket_aux_get_use_count (clib_cuckoo_bucket_aux_t aux)
{
  u64 use_count_mask = (1 << CLIB_CUCKOO_USE_COUNT_BIT_WIDTH) - 1;
  return (aux >> 1) & use_count_mask;
}

always_inline int
clib_cuckoo_bucket_aux_get_writer_flag (clib_cuckoo_bucket_aux_t aux)
{
  return aux & 1;
}

always_inline clib_cuckoo_bucket_aux_t
clib_cuckoo_bucket_aux_pack (u64 version, int use_count, int writer_flag)
{
  return (version << (1 + CLIB_CUCKOO_USE_COUNT_BIT_WIDTH)) +
    (use_count << 1) + writer_flag;
}

always_inline clib_cuckoo_bucket_aux_t
clib_cuckoo_bucket_aux_set_version (clib_cuckoo_bucket_aux_t aux, u64 version)
{
  int use_count = clib_cuckoo_bucket_aux_get_use_count (aux);
  int writer_flag = clib_cuckoo_bucket_aux_get_writer_flag (aux);
  return clib_cuckoo_bucket_aux_pack (version, use_count, writer_flag);
}

always_inline clib_cuckoo_bucket_aux_t
clib_cuckoo_bucket_aux_set_use_count (clib_cuckoo_bucket_aux_t aux,
				      int use_count)
{
  u64 version = clib_cuckoo_bucket_aux_get_version (aux);
  int writer_flag = clib_cuckoo_bucket_aux_get_writer_flag (aux);
  return clib_cuckoo_bucket_aux_pack (version, use_count, writer_flag);
}

always_inline clib_cuckoo_bucket_aux_t
clib_cuckoo_bucket_aux_set_writer_flag (clib_cuckoo_bucket_aux_t aux,
					int writer_flag)
{
  u64 version = clib_cuckoo_bucket_aux_get_version (aux);
  int use_count = clib_cuckoo_bucket_aux_get_use_count (aux);
  return clib_cuckoo_bucket_aux_pack (version, use_count, writer_flag);
}

#define PATH_BITS_REQ \
  (CLIB_CUCKOO_BFS_MAX_PATH_LENGTH * CLIB_CUCKOO_LOG2_KVP_PER_BUCKET)

#if PATH_BITS_REQ <= 8
typedef u8 path_data_t;
#elif PATH_BITS_REQ <= 16
typedef u16 path_data_t;
#elif PATH_BITS_REQ <= 32
typedef u32 path_data_t;
#elif PATH_BITS_REQ <= 64
typedef u64 path_data_t;
#else
#error no suitable datatype for path storage...
#endif

typedef struct
{
  /** bucket where this path begins */
  u64 start;
  /** bucket at end of path */
  u64 bucket;
  /** length of the path */
  u8 length;
  /** holds compressed offsets in buckets along path */
  path_data_t data;
} clib_cuckoo_path_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /** reduced hashes corresponding to elements */
  u8 reduced_hashes[CLIB_CUCKOO_KVP_PER_BUCKET];

  /** auxiliary data - version, writer flag and used count */
  volatile clib_cuckoo_bucket_aux_t aux;

  /** cuckoo elements in this bucket */
    CVT (clib_cuckoo_kv) elts[CLIB_CUCKOO_KVP_PER_BUCKET];
} CVT (clib_cuckoo_bucket);

#define clib_cuckoo_bucket_foreach_idx(var) \
  for (var = 0; var < CLIB_CUCKOO_KVP_PER_BUCKET; var++)

#if CLIB_CUCKOO_OPTIMIZE_UNROLL
#if CLIB_CUCKOO_KVP_PER_BUCKET == 2
#define clib_cuckoo_bucket_foreach_idx_unrolled(var, body) \
  do                                                       \
    {                                                      \
      var = 0;                                             \
      body;                                                \
      var = 1;                                             \
      body;                                                \
    }                                                      \
  while (0);
#elif CLIB_CUCKOO_KVP_PER_BUCKET == 4
#define clib_cuckoo_bucket_foreach_idx_unrolled(var, body) \
  do                                                       \
    {                                                      \
      var = 0;                                             \
      body;                                                \
      var = 1;                                             \
      body;                                                \
      var = 2;                                             \
      body;                                                \
      var = 3;                                             \
      body;                                                \
    }                                                      \
  while (0);
#elif CLIB_CUCKOO_KVP_PER_BUCKET == 8
#define clib_cuckoo_bucket_foreach_idx_unrolled(var, body) \
  do                                                       \
    {                                                      \
      var = 0;                                             \
      body;                                                \
      var = 1;                                             \
      body;                                                \
      var = 2;                                             \
      body;                                                \
      var = 3;                                             \
      body;                                                \
      var = 4;                                             \
      body;                                                \
      var = 5;                                             \
      body;                                                \
      var = 6;                                             \
      body;                                                \
      var = 7;                                             \
      body;                                                \
    }                                                      \
  while (0);
#else
#define clib_cuckoo_bucket_foreach_idx_unrolled(var, body) \
  clib_cuckoo_bucket_foreach_idx (var)                     \
  {                                                        \
    body;                                                  \
  }
#endif
#else /* CLIB_CUCKOO_OPTIMIZE_UNROLL */
#define clib_cuckoo_bucket_foreach_idx_unrolled(var, body) \
  clib_cuckoo_bucket_foreach_idx (var)                     \
  {                                                        \
    body;                                                  \
  }
#endif /* CLIB_CUCKOO_OPTIMIZE_UNROLL */

#define clib_cuckoo_bucket_foreach_elt_index(var, bucket) \
  for (var = 0; var < CLIB_CUCKOO_KVP_PER_BUCKET; ++i)

#define clib_cuckoo_foreach_bucket(var, h, body)        \
  do                                                    \
    {                                                   \
      CVT (clib_cuckoo_bucket) *__buckets = h->buckets; \
      vec_foreach (var, __buckets)                      \
      {                                                 \
        body;                                           \
      }                                                 \
    }                                                   \
  while (0)

typedef struct CV (clib_cuckoo)
{
  /** vector of elements containing key-value pairs and auxiliary data */
  CVT (clib_cuckoo_bucket) * volatile buckets;

  /** garbage to be freed once its safe to do so .. */
  CVT (clib_cuckoo_bucket) * *to_be_freed;

  /** hash table name */
  const char *name;

  /** pool of cuckoo paths (reused when doing bfd search) */
  clib_cuckoo_path_t *paths;

  /**
   * vector used as queue when doing cuckoo path searches - holds offsets
   * in paths pool
   */
  uword *bfs_search_queue;

  /**
   * writer lock - whether this lock is taken or not has zero effect on
   * readers
   */
  clib_spinlock_t writer_lock;

  /** caller context passed to callback with garbage notification */
  void *garbage_ctx;

  /**
   * garbage notify function - called when some garbage needs to be collected
   * in main thread while other threads are stopped
   */
  void (*garbage_callback) (struct CV (clib_cuckoo) * h, void *garbage_ctx);

#if CLIB_CUCKOO_DEBUG_COUNTERS
  u64 steps_exceeded;
  u64 bfs_queue_emptied;
  u64 fast_adds;
  u64 slow_adds;
  u64 rehashes;
#endif

} CVT (clib_cuckoo);

void CV (clib_cuckoo_init) (CVT (clib_cuckoo) * h, const char *name,
			    uword nbuckets,
			    void (*garbage_callback) (CVT (clib_cuckoo) *,
						      void *),
			    void *garbage_ctx);

void CV (clib_cuckoo_garbage_collect) (CVT (clib_cuckoo) * h);

void CV (clib_cuckoo_free) (CVT (clib_cuckoo) * h);

int CV (clib_cuckoo_add_del) (CVT (clib_cuckoo) * h,
			      CVT (clib_cuckoo_kv) * add_v, int is_add);
int CV (clib_cuckoo_search) (CVT (clib_cuckoo) * h,
			     CVT (clib_cuckoo_kv) * search_v,
			     CVT (clib_cuckoo_kv) * return_v);

void CV (clib_cuckoo_foreach_key_value_pair) (CVT (clib_cuckoo) * h,
					      void *callback, void *arg);

float CV (clib_cuckoo_calc_load) (CVT (clib_cuckoo) * h);

format_function_t CV (format_cuckoo);
format_function_t CV (format_cuckoo_kvp);

always_inline u8
clib_cuckoo_reduce_hash (u64 hash)
{
  u32 v32 = ((u32) hash) ^ ((u32) (hash >> 32));
  u16 v16 = ((u16) v32) ^ ((u16) (v32 >> 16));
  u8 v8 = ((u8) v16) ^ ((u8) (v16 >> 8));
  return v8;
}

always_inline u64
clib_cuckoo_get_other_bucket (u64 nbuckets, u64 bucket, u8 reduced_hash)
{
  u64 mask = (nbuckets - 1);
  return (bucket ^ ((reduced_hash + 1) * 0xc6a4a7935bd1e995)) & mask;
}

always_inline clib_cuckoo_lookup_info_t
CV (clib_cuckoo_calc_lookup) (CVT (clib_cuckoo_bucket) * buckets, u64 hash)
{
  clib_cuckoo_lookup_info_t lookup;
  u64 nbuckets = vec_len (buckets);
  u64 mask = (nbuckets - 1);
  lookup.bucket1 = hash & mask;
#if CLIB_CUCKOO_OPTIMIZE_PREFETCH
  CLIB_PREFETCH (vec_elt_at_index (buckets, lookup.bucket1),
		 sizeof (*buckets), LOAD);
#endif
  u8 reduced_hash = clib_cuckoo_reduce_hash (hash);
  lookup.bucket2 =
    clib_cuckoo_get_other_bucket (nbuckets, lookup.bucket1, reduced_hash);
#if CLIB_CUCKOO_OPTIMIZE_PREFETCH
  CLIB_PREFETCH (vec_elt_at_index (buckets, lookup.bucket2),
		 sizeof (*buckets), LOAD);
#endif
  lookup.reduced_hash = reduced_hash;
  ASSERT (lookup.bucket1 < nbuckets);
  ASSERT (lookup.bucket2 < nbuckets);
  return lookup;
}

/**
 * search for key within bucket
 */
always_inline int CV (clib_cuckoo_bucket_search) (CVT (clib_cuckoo_bucket) *
						  b,
						  CVT (clib_cuckoo_kv) * kvp,
						  u8 reduced_hash)
{
  clib_cuckoo_bucket_aux_t bucket_aux;
  u8 writer_flag;
  do
    {
      bucket_aux = b->aux;
      writer_flag = clib_cuckoo_bucket_aux_get_writer_flag (bucket_aux);
    }
  while (PREDICT_FALSE (writer_flag));	/* loop while writer flag is set */

  int i;
#if CLIB_CUCKOO_OPTIMIZE_USE_COUNT_LIMITS_SEARCH
  const int use_count = clib_cuckoo_bucket_aux_get_use_count (bucket_aux);
#endif
  /* *INDENT-OFF* */
  clib_cuckoo_bucket_foreach_idx_unrolled (i, {
#if CLIB_CUCKOO_OPTIMIZE_USE_COUNT_LIMITS_SEARCH
    if (i > use_count)
      {
        break;
      }
#endif
    if (
#if CLIB_CUCKOO_OPTIMIZE_CMP_REDUCED_HASH
        reduced_hash == b->reduced_hashes[i] &&
#endif
        0 == memcmp (&kvp->key, &b->elts[i].key, sizeof (kvp->key)))
      {
        kvp->value = b->elts[i].value;
        clib_cuckoo_bucket_aux_t bucket_aux2 = b->aux;
        if (PREDICT_TRUE (clib_cuckoo_bucket_aux_get_version (bucket_aux) ==
                          clib_cuckoo_bucket_aux_get_version (bucket_aux2)))
          {
            /* yay, fresh data */
            return CLIB_CUCKOO_ERROR_SUCCESS;
          }
        else
          {
            /* oops, modification detected */
            return CLIB_CUCKOO_ERROR_AGAIN;
          }
      }
  });
  /* *INDENT-ON* */
  return CLIB_CUCKOO_ERROR_NOT_FOUND;
}

always_inline int CV (clib_cuckoo_search_inline) (CVT (clib_cuckoo) * h,
						  CVT (clib_cuckoo_kv) * kvp)
{
  clib_cuckoo_lookup_info_t lookup;
  int rv;

  u64 hash = CV (clib_cuckoo_hash) (kvp);
  CVT (clib_cuckoo_bucket) * buckets;
again:
  buckets = h->buckets;
  lookup = CV (clib_cuckoo_calc_lookup) (buckets, hash);
  do
    {
      rv =
	CV (clib_cuckoo_bucket_search) (vec_elt_at_index
					(buckets, lookup.bucket1), kvp,
					lookup.reduced_hash);
    }
  while (PREDICT_FALSE (CLIB_CUCKOO_ERROR_AGAIN == rv));
  if (CLIB_CUCKOO_ERROR_SUCCESS == rv)
    {
      return CLIB_CUCKOO_ERROR_SUCCESS;
    }

  rv =
    CV (clib_cuckoo_bucket_search) (vec_elt_at_index
				    (buckets, lookup.bucket2), kvp,
				    lookup.reduced_hash);
  if (PREDICT_FALSE (CLIB_CUCKOO_ERROR_AGAIN == rv))
    {
      /*
       * change to 2nd bucket could bump the item to 1st bucket and the bucket
       * indexes might not even be valid anymore - restart the search
       */
      goto again;
    }
  return rv;
}

#endif /* __included_cuckoo_template_h__ */

/** @endcond */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
