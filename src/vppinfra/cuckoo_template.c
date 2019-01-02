/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vppinfra/vec.h>
#include <vppinfra/cuckoo_template.h>

int CV (clib_cuckoo_search) (CVT (clib_cuckoo) * h,
			     CVT (clib_cuckoo_kv) * search_v,
			     CVT (clib_cuckoo_kv) * return_v)
{
  CVT (clib_cuckoo_kv) tmp = *search_v;
  int rv = CV (clib_cuckoo_search_inline) (h, &tmp);
  if (CLIB_CUCKOO_ERROR_SUCCESS == rv)
    {
      *return_v = tmp;
    }
  return rv;
}

static
CVT (clib_cuckoo_bucket) *
CV (clib_cuckoo_bucket_at_index) (CVT (clib_cuckoo) * h, uword bucket)
{
  return vec_elt_at_index (h->buckets, bucket);
}

static uword CV (clib_cuckoo_get_nbuckets) (CVT (clib_cuckoo) * h)
{
  return vec_len (h->buckets);
}

static inline uword
CV (clib_cuckoo_elt_in_bucket_to_offset) (CVT (clib_cuckoo_bucket) * b,
					  CVT (clib_cuckoo_kv) * e)
{
  ASSERT (e >= b->elts);
  ASSERT (e <= &b->elts[sizeof (b->elts) / sizeof (b->elts[0]) - 1]);
  return e - b->elts;
}

u8 *CV (format_cuckoo_elt) (u8 * s, va_list * args)
{
  CVT (clib_cuckoo_kv) * elt = va_arg (*args, CVT (clib_cuckoo_kv) *);
  unsigned reduced_hash = va_arg (*args, unsigned);
  if (CV (clib_cuckoo_kv_is_free) (elt))
    {
      s = format (s, "[ -- empty -- ]");
    }
  else
    {
      s = format (s, "[%U, reduced hash: %u]", CV (format_cuckoo_kvp), elt,
		  reduced_hash);
    }
  return s;
}

u8 *CV (format_cuckoo_bucket) (u8 * s, va_list * args)
{
  CVT (clib_cuckoo_bucket) * bucket =
    va_arg (*args, CVT (clib_cuckoo_bucket) *);
  int i = 0;

  /* *INDENT-OFF* */
  clib_cuckoo_bucket_foreach_idx (i)
  {
    CVT (clib_cuckoo_kv) *elt = bucket->elts + i;
    s = format (s, "bucket %p, offset %d: %U\n", bucket, i,
                CV (format_cuckoo_elt), elt, bucket->reduced_hashes[i]);
  }
  /* *INDENT-ON* */
  clib_cuckoo_bucket_aux_t aux = bucket->aux;
  s = format (s, "version: %lld, use count: %d\n",
	      clib_cuckoo_bucket_aux_get_version (aux),
	      clib_cuckoo_bucket_aux_get_use_count (aux));
  return s;
}

#if CLIB_CUCKOO_DEBUG
static void CV (clib_cuckoo_deep_self_check) (CVT (clib_cuckoo) * h)
{
  CVT (clib_cuckoo_bucket) * bucket;
  uword bucket_idx = 0;
  /* *INDENT-OFF* */
  clib_cuckoo_foreach_bucket (bucket, h)
  {
    int i = 0;
    int used = 0;
    clib_cuckoo_bucket_foreach_idx (i)
    {
      CVT (clib_cuckoo_kv) *elt = bucket->elts + i;
      if (!CV (clib_cuckoo_kv_is_free) (elt))
        {
          u64 hash = CV (clib_cuckoo_hash) (elt);
          clib_cuckoo_lookup_info_t lookup = CV (clib_cuckoo_calc_lookup) (
              CV (clib_cuckoo_get_snapshot) (h), hash);
          CVT (clib_cuckoo_kv) kv = *elt;
          int rv = CV (clib_cuckoo_search) (h, &kv, &kv);
          if (CLIB_CUCKOO_ERROR_SUCCESS != rv)
            {
              CLIB_CUCKOO_DBG ("Search for elt `%U' failed!",
                               CV (format_cuckoo_elt), elt,
                               bucket->reduced_hashes[i]);
              CLIB_CUCKOO_DBG ("%U", CV (format_cuckoo), h, 1);
            }
          ASSERT (aux.bucket1 == bucket_idx || aux.bucket2 == bucket_idx);
          ASSERT (CLIB_CUCKOO_ERROR_SUCCESS == rv);
          ++used;
        }
    }
    clib_cuckoo_bucket_aux_t aux = bucket->aux;
    ASSERT (used == clib_cuckoo_bucket_aux_get_use_count (aux));
    ++bucket_idx;
  }
  /* *INDENT-ON* */
  // CLIB_CUCKOO_DBG ("Deep self check passed: %U", CV (format_cuckoo), h);
}

#define CLIB_CUCKOO_DEEP_SELF_CHECK(h) CV (clib_cuckoo_deep_self_check) (h)
#define CLIB_CUCKOO_ASSERT_BUCKET_SORTED(b)                                 \
  do                                                                        \
    {                                                                       \
      int i;                                                                \
      int min_free = CLIB_CUCKOO_KVP_PER_BUCKET;                            \
      int max_used = 0;                                                     \
      clib_cuckoo_bucket_foreach_idx (i)                                    \
      {                                                                     \
        if (!CV (clib_cuckoo_kv_is_free) (b->elts + i))                     \
          {                                                                 \
            max_used = i;                                                   \
          }                                                                 \
        if (CV (clib_cuckoo_kv_is_free) (b->elts +                          \
                                         (CLIB_CUCKOO_KVP_PER_BUCKET - i))) \
          {                                                                 \
            min_free = i;                                                   \
          }                                                                 \
      }                                                                     \
      ASSERT (min_free > max_used);                                         \
    }                                                                       \
  while (0)

#else
#define CLIB_CUCKOO_DEEP_SELF_CHECK(h)
#define CLIB_CUCKOO_ASSERT_BUCKET_SORTED(b)
#endif

void CV (clib_cuckoo_init) (CVT (clib_cuckoo) * h, const char *name,
			    uword nbuckets,
			    void (*garbage_callback) (CVT (clib_cuckoo) *,
						      void *),
			    void *garbage_ctx)
{
  uword log2_nbuckets = max_log2 (nbuckets);
  nbuckets = 1 << (log2_nbuckets);
  CLIB_CUCKOO_DBG ("New cuckoo, adjusted nbuckets %wu", nbuckets);
  CVT (clib_cuckoo_bucket) * buckets = NULL;
  vec_validate_aligned (buckets, nbuckets - 1, CLIB_CACHE_LINE_BYTES);
  ASSERT (nbuckets == vec_len (buckets));
  h->buckets = buckets;
  clib_spinlock_init (&h->writer_lock);
  /* mark all elements free ... */
  CVT (clib_cuckoo_bucket) * bucket;
  /* *INDENT-OFF* */
  clib_cuckoo_foreach_bucket (
      bucket, h, { clib_memset (bucket->elts, 0xff, sizeof (bucket->elts)); });
  /* *INDENT-ON* */
  h->name = name;
  h->garbage_callback = garbage_callback;
  h->garbage_ctx = garbage_ctx;
}

void CV (clib_cuckoo_free) (CVT (clib_cuckoo) * h)
{
  clib_memset (h, 0, sizeof (*h));
}

static clib_cuckoo_bucket_aux_t
CV (clib_cuckoo_bucket_version_bump_and_lock) (CVT (clib_cuckoo_bucket) * b)
{
  clib_cuckoo_bucket_aux_t aux = b->aux;
  u64 version = clib_cuckoo_bucket_aux_get_version (aux);
  u8 use_count = clib_cuckoo_bucket_aux_get_use_count (aux);
  u8 writer_flag = clib_cuckoo_bucket_aux_get_writer_flag (aux);
  ASSERT (0 == writer_flag);
  aux = clib_cuckoo_bucket_aux_pack (version + 1, use_count, 1);
  b->aux = aux;
  return aux;
}

static void CV (clib_cuckoo_bucket_unlock) (CVT (clib_cuckoo_bucket) * b,
					    clib_cuckoo_bucket_aux_t aux)
{
  u64 version = clib_cuckoo_bucket_aux_get_version (aux);
  u8 use_count = clib_cuckoo_bucket_aux_get_use_count (aux);
  u8 writer_flag = clib_cuckoo_bucket_aux_get_writer_flag (aux);
  ASSERT (1 == writer_flag);
  aux = clib_cuckoo_bucket_aux_pack (version, use_count, 0);
  b->aux = aux;
}

#define CLIB_CUCKOO_DEBUG_PATH (1)
#define CLIB_CUCKOO_DEBUG_PATH_DETAIL (0)

#if CLIB_CUCKOO_DEBUG && CLIB_CUCKOO_DEBUG_PATH
static u8 *CV (format_cuckoo_path) (u8 * s, va_list * args);
#endif

static clib_cuckoo_path_t *CV (clib_cuckoo_path_get) (CVT (clib_cuckoo) * h)
{
  clib_cuckoo_path_t *path;
  pool_get (h->paths, path);
  clib_memset (path, 0, sizeof (*path));
#if CLIB_CUCKOO_DEBUG_PATH_DETAIL
  CLIB_CUCKOO_DBG ("Get path @%lu", (long unsigned) (path - h->paths));
#endif
  return path;
}

static void CV (clib_cuckoo_path_put) (CVT (clib_cuckoo) * h, uword path_idx)
{
  clib_cuckoo_path_t *path = pool_elt_at_index (h->paths, path_idx);
#if CLIB_CUCKOO_DEBUG_PATH_DETAIL
  CLIB_CUCKOO_DBG ("Put path @%lu", (long unsigned) (path - h->paths));
#endif
  pool_put (h->paths, path);
}

static clib_cuckoo_path_t *CV (clib_cuckoo_path_begin) (CVT (clib_cuckoo) * h,
							uword bucket,
							uword next_offset)
{
  ASSERT (next_offset < CLIB_CUCKOO_KVP_PER_BUCKET);
  clib_cuckoo_path_t *new_path = CV (clib_cuckoo_path_get) (h);
  new_path->length = 1;
  new_path->data = next_offset;
  new_path->start = bucket;
  new_path->bucket = bucket;
#if CLIB_CUCKOO_DEBUG_PATH
  CLIB_CUCKOO_DBG ("Create new path @%wu, length: %u data: %llu bucket: %wu "
		   "next-offset: %wu",
		   new_path - h->paths, new_path->length,
		   (long long unsigned) new_path->data, new_path->bucket,
		   next_offset);
#endif
  return new_path;
}

/**
 * create a new path based on existing path extended by adding a bucket
 * and offset
 */
static uword CV (clib_cuckoo_path_extend) (CVT (clib_cuckoo) * h,
					   uword path_idx, uword bucket,
					   unsigned offset)
{
  ASSERT (offset < CLIB_CUCKOO_KVP_PER_BUCKET);
  clib_cuckoo_path_t *new_path = CV (clib_cuckoo_path_get) (h);
  uword new_path_idx = new_path - h->paths;
  clib_cuckoo_path_t *path = pool_elt_at_index (h->paths, path_idx);
  new_path->start = path->start;
  new_path->length = path->length + 1;
  new_path->data = (path->data << CLIB_CUCKOO_LOG2_KVP_PER_BUCKET) + offset;
  new_path->bucket = bucket;
#if CLIB_CUCKOO_DEBUG_PATH
  CLIB_CUCKOO_DBG ("Extend path @%wu, new path @%wu, %U", path_idx,
		   new_path_idx, CV (format_cuckoo_path), h, new_path_idx);
#endif
  return new_path_idx;
}

/** return the offset of the last element in the path */
static uword CV (clib_cuckoo_path_peek_offset) (const clib_cuckoo_path_t *
						path)
{
  ASSERT (path->length > 0);
  uword mask = (1 << CLIB_CUCKOO_LOG2_KVP_PER_BUCKET) - 1;
  uword offset = path->data & mask;
  return offset;
}

static
CVT (clib_cuckoo_kv) *
CV (clib_cuckoo_bucket_find_empty) (CVT (clib_cuckoo_bucket) * bucket)
{
  clib_cuckoo_bucket_aux_t aux = bucket->aux;
  u8 use_count = clib_cuckoo_bucket_aux_get_use_count (aux);
  if (use_count < CLIB_CUCKOO_KVP_PER_BUCKET)
    {
      return bucket->elts + use_count;
    }
  return NULL;
}

/**
 * walk the cuckoo path two ways,
 * first backwards, extracting offsets,
 * then forward, extracting buckets
 *
 * buckets and offsets are arrays filled with elements extracted from path
 * the arrays must be able to contain CLIB_CUCKOO_BFS_MAX_PATH_LENGTH elements
 */
static void
clib_cuckoo_path_walk (CVT (clib_cuckoo) * h, uword path_idx,
		       uword * buckets, uword * offsets)
{
  clib_cuckoo_path_t *path = pool_elt_at_index (h->paths, path_idx);
  ASSERT (path->length > 0);
  u64 data = path->data;
  uword mask = (1 << CLIB_CUCKOO_LOG2_KVP_PER_BUCKET) - 1;
  uword i;
  for (i = path->length; i > 0; --i)
    {
      uword offset = data & mask;
      offsets[i - 1] = offset;
      data >>= CLIB_CUCKOO_LOG2_KVP_PER_BUCKET;
    }
  buckets[0] = path->start;
  for (i = 1; i < path->length; ++i)
    {
      CVT (clib_cuckoo_bucket) * b =
	CV (clib_cuckoo_bucket_at_index) (h, buckets[i - 1]);
      buckets[i] =
	clib_cuckoo_get_other_bucket (CV (clib_cuckoo_get_nbuckets) (h),
				      buckets[i - 1],
				      b->reduced_hashes[offsets[i - 1]]);
    }
}

#if CLIB_CUCKOO_DEBUG && CLIB_CUCKOO_DEBUG_PATH
static u8 *CV (format_cuckoo_path) (u8 * s, va_list * args)
{
  CVT (clib_cuckoo) * h = va_arg (*args, CVT (clib_cuckoo) *);
  uword path_idx = va_arg (*args, uword);
  clib_cuckoo_path_t *p = pool_elt_at_index (h->paths, path_idx);
  uword buckets[CLIB_CUCKOO_BFS_MAX_PATH_LENGTH];
  uword offsets[CLIB_CUCKOO_BFS_MAX_PATH_LENGTH];
  clib_cuckoo_path_walk (h, path_idx, buckets, offsets);
  s = format (s, "length %u: ", p->length);
  for (uword i = p->length - 1; i > 0; --i)
    {
      s = format (s, "%wu[%wu]->", buckets[i], offsets[i]);
    }
  if (p->length)
    {
      s = format (s, "%wu[%wu]", buckets[0], offsets[0]);
    }
  return s;
}
#endif

/*
 * perform breadth-first search in the cuckoo hash, finding the closest
 * empty slot, i.e. one which requires minimum swaps to move it
 * to one of the buckets provided
 */
static inline int CV (clib_cuckoo_find_empty_slot_bfs) (CVT (clib_cuckoo) * h,
							clib_cuckoo_lookup_info_t
							* lookup,
							uword * path_idx_out,
							uword * found_bucket,
							CVT (clib_cuckoo_kv) *
							*found_elt)
{
  uword *tail;
  ASSERT (!vec_len (h->bfs_search_queue));
  clib_cuckoo_path_t *tmp;
  pool_flush (tmp, h->paths,);
  int rv = CLIB_CUCKOO_ERROR_AGAIN;
  int counter = 0;

  *path_idx_out = ~0U;		/* -Wmaybe-uninitialized in caller */
  *found_bucket = ~0U;		/* -Wmaybe-uninitialized in caller */

  /* start by creating paths starting in each of the buckets ... */
  vec_add2 (h->bfs_search_queue, tail, CLIB_CUCKOO_KVP_PER_BUCKET);
  int i;
  for (i = 0; i < CLIB_CUCKOO_KVP_PER_BUCKET; ++i)
    {
      clib_cuckoo_path_t *path =
	CV (clib_cuckoo_path_begin) (h, lookup->bucket1, i);
      tail[i] = path - h->paths;
    }
  if (lookup->bucket1 != lookup->bucket2)
    {
      vec_add2 (h->bfs_search_queue, tail, CLIB_CUCKOO_KVP_PER_BUCKET);
      for (i = 0; i < CLIB_CUCKOO_KVP_PER_BUCKET; ++i)
	{
	  clib_cuckoo_path_t *path =
	    CV (clib_cuckoo_path_begin) (h, lookup->bucket2, i);
	  tail[i] = path - h->paths;
	}
    }
  while (1)
    {
      if (counter >= CLIB_CUCKOO_BFS_MAX_STEPS)
	{
#if CLIB_CUCKOO_DEBUG_COUNTERS
	  ++h->steps_exceeded;
#endif
	  break;
	}
      if (counter >= vec_len (h->bfs_search_queue))
	{
#if CLIB_CUCKOO_DEBUG_COUNTERS
	  ++h->bfs_queue_emptied;
#endif
	  break;
	}
      const uword path_idx = vec_elt (h->bfs_search_queue, counter);
      const clib_cuckoo_path_t *path = pool_elt_at_index (h->paths, path_idx);
#if CLIB_CUCKOO_DEBUG_PATH
      CLIB_CUCKOO_DBG ("Examine path @%wu: %U", path_idx,
		       CV (format_cuckoo_path), h, path_idx);
#endif
      /* TODO prefetch ? */
      /* search the alternative bucket for free space */
      int offset = CV (clib_cuckoo_path_peek_offset) (path);
      CVT (clib_cuckoo_bucket) * bucket =
	CV (clib_cuckoo_bucket_at_index) (h, path->bucket);
      uword other_bucket =
	clib_cuckoo_get_other_bucket (CV (clib_cuckoo_get_nbuckets) (h),
				      path->bucket,
				      bucket->reduced_hashes[offset]);
      CLIB_CUCKOO_DBG
	("Path ends in bucket %wu, offset #%wu, other bucket is %wu",
	 path->bucket, CV (clib_cuckoo_path_peek_offset) (path),
	 other_bucket);
      if (path->bucket != other_bucket)
	{
	  if ((*found_elt =
	       CV (clib_cuckoo_bucket_find_empty) (CV
						   (clib_cuckoo_bucket_at_index)
						   (h, other_bucket))))
	    {
	      /* found empty element */
	      *found_bucket = other_bucket;
	      *path_idx_out = path_idx;
	      rv = CLIB_CUCKOO_ERROR_SUCCESS;
#if CLIB_CUCKOO_DEBUG_PATH
	      CLIB_CUCKOO_DBG ("Bucket with empty slot:\n%U",
			       CV (format_cuckoo_bucket),
			       CV (clib_cuckoo_bucket_at_index) (h,
								 other_bucket));
#endif
	      goto out;
	    }
	  /* extend the current path with possible next buckets and add to
	   * queue */
	  if (path->length < CLIB_CUCKOO_BFS_MAX_PATH_LENGTH &&
	      vec_len (h->bfs_search_queue) < CLIB_CUCKOO_BFS_MAX_STEPS)
	    {
	      uword *tail;
	      vec_add2 (h->bfs_search_queue, tail,
			CLIB_CUCKOO_KVP_PER_BUCKET);
	      for (i = 0; i < CLIB_CUCKOO_KVP_PER_BUCKET; ++i)
		{
		  uword new_path_idx =
		    CV (clib_cuckoo_path_extend) (h, path_idx, other_bucket,
						  i);
		  tail[i] = new_path_idx;
		}
	    }
	}
      else
	{
	  CLIB_CUCKOO_DBG ("Discard path @%wu, loop detected", path_idx);
	}
      /* done with this path - put back to pool for later reuse */
      CV (clib_cuckoo_path_put) (h, path_idx);
      ++counter;
    }
out:
  vec_reset_length (h->bfs_search_queue);
  return rv;
}

static void CV (clib_cuckoo_swap_elts_in_bucket) (CVT (clib_cuckoo_bucket) *
						  b, uword e1, uword e2)
{
  CVT (clib_cuckoo_kv) kv;
  clib_memcpy (&kv, b->elts + e1, sizeof (kv));
  clib_memcpy (b->elts + e1, b->elts + e2, sizeof (kv));
  clib_memcpy (b->elts + e2, &kv, sizeof (kv));
  u8 reduced_hash = b->reduced_hashes[e1];
  b->reduced_hashes[e1] = b->reduced_hashes[e2];
  b->reduced_hashes[e2] = reduced_hash;
}

static void CV (clib_cuckoo_bucket_tidy) (CVT (clib_cuckoo_bucket) * b)
{
  int i = 0;
  int j = CLIB_CUCKOO_KVP_PER_BUCKET - 1;
  while (i != j)
    {
      int min_free = i;
      int max_used = j;
      while (!CV (clib_cuckoo_kv_is_free) (&b->elts[min_free]))
	{
	  ++min_free;
	}
      while (CV (clib_cuckoo_kv_is_free) (&b->elts[max_used]))
	{
	  --max_used;
	}
      if (min_free < max_used)
	{
	  CV (clib_cuckoo_swap_elts_in_bucket) (b, min_free, max_used);
	  i = min_free + 1;
	  j = max_used - 1;
	}
      else
	{
	  break;
	}
    }
}

static void CV (clib_cuckoo_free_locked_elt) (CVT (clib_cuckoo_kv) * elt)
{
  /*
   * FIXME - improve performance by getting rid of this clib_memset - make all
   * functions in this file not rely on clib_cuckoo_kv_is_free but instead
   * take use_count into account */
  clib_memset (elt, 0xff, sizeof (*elt));
}

static void CV (clib_cuckoo_free_elt_in_bucket) (CVT (clib_cuckoo_bucket) * b,
						 CVT (clib_cuckoo_kv) * elt)
{
  clib_cuckoo_bucket_aux_t aux =
    CV (clib_cuckoo_bucket_version_bump_and_lock) (b);
  int use_count = clib_cuckoo_bucket_aux_get_use_count (aux);
  int offset = elt - b->elts;
  ASSERT (offset < use_count);
  CV (clib_cuckoo_free_locked_elt) (elt);
  if (offset != use_count - 1)
    {
      CV (clib_cuckoo_bucket_tidy) (b);
    }
  aux = clib_cuckoo_bucket_aux_set_use_count (aux, use_count - 1);
  CV (clib_cuckoo_bucket_unlock) (b, aux);
}

static void CV (clib_cuckoo_set_locked_elt) (CVT (clib_cuckoo_bucket) * b,
					     CVT (clib_cuckoo_kv) * elt,
					     CVT (clib_cuckoo_kv) * kvp,
					     u8 reduced_hash)
{
  int offset = CV (clib_cuckoo_elt_in_bucket_to_offset) (b, elt);
  clib_memcpy (elt, kvp, sizeof (*elt));
  b->reduced_hashes[offset] = reduced_hash;
  CLIB_CUCKOO_DBG ("Set bucket %p, offset %d, %U", b, offset,
		   CV (format_cuckoo_elt), elt, b->reduced_hashes[offset]);
}

static void CV (clib_cuckoo_set_elt) (CVT (clib_cuckoo_bucket) * b,
				      CVT (clib_cuckoo_kv) * elt,
				      CVT (clib_cuckoo_kv) * kvp,
				      u8 reduced_hash)
{
  clib_cuckoo_bucket_aux_t aux =
    CV (clib_cuckoo_bucket_version_bump_and_lock) (b);
  CV (clib_cuckoo_set_locked_elt) (b, elt, kvp, reduced_hash);
  CV (clib_cuckoo_bucket_unlock) (b, aux);
}

static int CV (clib_cuckoo_add_slow) (CVT (clib_cuckoo) * h,
				      CVT (clib_cuckoo_kv) * kvp,
				      clib_cuckoo_lookup_info_t * lookup,
				      u8 reduced_hash)
{
  uword path_idx;
  uword empty_bucket_idx;
  CVT (clib_cuckoo_kv) * empty_elt;
  int rv = CV (clib_cuckoo_find_empty_slot_bfs) (h, lookup, &path_idx,
						 &empty_bucket_idx,
						 &empty_elt);
  if (CLIB_CUCKOO_ERROR_SUCCESS == rv)
    {
      uword buckets[CLIB_CUCKOO_BFS_MAX_PATH_LENGTH];
      uword offsets[CLIB_CUCKOO_BFS_MAX_PATH_LENGTH];
      clib_cuckoo_path_walk (h, path_idx, buckets, offsets);
      /*
       * walk back the path, moving the free element forward to one of our
       * buckets ...
       */
      clib_cuckoo_path_t *path = pool_elt_at_index (h->paths, path_idx);
      CVT (clib_cuckoo_bucket) * empty_bucket =
	CV (clib_cuckoo_bucket_at_index) (h, empty_bucket_idx);
      int i;
      for (i = path->length - 1; i >= 0; --i)
	{
	  /* copy the key-value in path to the bucket with empty element */
	  CVT (clib_cuckoo_bucket) * b =
	    CV (clib_cuckoo_bucket_at_index) (h, buckets[i]);
	  CVT (clib_cuckoo_kv) * elt = b->elts + offsets[i];
	  clib_cuckoo_bucket_aux_t empty_aux =
	    CV (clib_cuckoo_bucket_version_bump_and_lock) (empty_bucket);
	  CV (clib_cuckoo_set_locked_elt)
	    (empty_bucket, empty_elt, elt, b->reduced_hashes[elt - b->elts]);
	  if (i == path->length - 1)
	    {
	      /* we only need to increase the use count for the bucket with
	       * free element - all other buckets' use counts won't change */
	      empty_aux = clib_cuckoo_bucket_aux_set_use_count (empty_aux,
								clib_cuckoo_bucket_aux_get_use_count
								(empty_aux) +
								1);
	    }
	  CV (clib_cuckoo_bucket_unlock) (empty_bucket, empty_aux);
	  /*
	   * the element now exists in both places - in the previously empty
	   * element and in its original bucket - we can now safely overwrite
	   * the element in the original bucket with previous element in path
	   * without loosing data (and we don't need to modify the use count)
	   */
	  empty_bucket = b;
	  empty_elt = elt;
	}
      /* now we have a place to put the kvp in ... */
      CV (clib_cuckoo_set_elt) (empty_bucket, empty_elt, kvp, reduced_hash);
      CLIB_CUCKOO_DBG ("Slow insert success, bucket: %p\n%U", empty_bucket,
		       CV (format_cuckoo_bucket), empty_bucket);
#if CLIB_CUCKOO_DEBUG_COUNTERS
      ++h->slow_adds;
#endif
    }
  return rv;
}

static int CV (clib_cuckoo_add_fast) (CVT (clib_cuckoo) * h,
				      clib_cuckoo_lookup_info_t * lookup,
				      CVT (clib_cuckoo_kv) * kvp,
				      u8 reduced_hash)
{
  CVT (clib_cuckoo_kv) * elt;
  CVT (clib_cuckoo_bucket) * bucket1 =
    CV (clib_cuckoo_bucket_at_index) (h, lookup->bucket1);
  if ((elt = CV (clib_cuckoo_bucket_find_empty) (bucket1)))
    {
      clib_cuckoo_bucket_aux_t aux =
	CV (clib_cuckoo_bucket_version_bump_and_lock) (bucket1);
      CV (clib_cuckoo_set_locked_elt) (bucket1, elt, kvp, reduced_hash);
      aux =
	clib_cuckoo_bucket_aux_set_use_count (aux,
					      clib_cuckoo_bucket_aux_get_use_count
					      (aux) + 1);
      CV (clib_cuckoo_bucket_unlock) (bucket1, aux);
#if CLIB_CUCKOO_DEBUG_COUNTERS
      ++h->fast_adds;
#endif
      return CLIB_CUCKOO_ERROR_SUCCESS;
    }
  CVT (clib_cuckoo_bucket) * bucket2 =
    CV (clib_cuckoo_bucket_at_index) (h, lookup->bucket2);
  if ((elt =
       CV (clib_cuckoo_bucket_find_empty) (CV (clib_cuckoo_bucket_at_index)
					   (h, lookup->bucket2))))
    {
      clib_cuckoo_bucket_aux_t aux =
	CV (clib_cuckoo_bucket_version_bump_and_lock) (bucket2);
      CV (clib_cuckoo_set_locked_elt) (bucket2, elt, kvp, reduced_hash);
      aux =
	clib_cuckoo_bucket_aux_set_use_count (aux,
					      clib_cuckoo_bucket_aux_get_use_count
					      (aux) + 1);
      CV (clib_cuckoo_bucket_unlock) (bucket2, aux);
#if CLIB_CUCKOO_DEBUG_COUNTERS
      ++h->fast_adds;
#endif
      return CLIB_CUCKOO_ERROR_SUCCESS;
    }
  return CLIB_CUCKOO_ERROR_AGAIN;
}

/**
 * perform garbage collection
 *
 * this function assumes there is no other thread touching the cuckoo hash,
 * not even a reader, it's meant to be called from main thread
 * in a stop-the-world situation
 */
void CV (clib_cuckoo_garbage_collect) (CVT (clib_cuckoo) * h)
{
  CLIB_MEMORY_BARRIER ();
  CVT (clib_cuckoo_bucket) * *b;
  /* *INDENT-OFF* */
  vec_foreach (b, h->to_be_freed)
  {
    if (*b == h->buckets)
      {
        continue;
      }
#if CLIB_CUCKOO_DEBUG_GC
    fformat (stdout, "gc: free %p\n", *b);
#endif
    vec_free (*b);
  }
  /* *INDENT-ON* */
  vec_free (h->to_be_freed);
  CLIB_MEMORY_BARRIER ();
}

/**
 * expand and rehash a cuckoo hash
 *
 * 1. double the size of the hash table
 * 2. move items to new locations derived from the new size
 */
static void CV (clib_cuckoo_rehash) (CVT (clib_cuckoo) * h)
{
  CVT (clib_cuckoo_bucket) * old = h->buckets;
  uword old_nbuckets = vec_len (old);
  uword new_nbuckets = 2 * old_nbuckets;
  CVT (clib_cuckoo_bucket) * new =
    vec_dup_aligned (old, CLIB_CACHE_LINE_BYTES);
  /* allocate space */
  vec_validate_aligned (new, new_nbuckets - 1, CLIB_CACHE_LINE_BYTES);
  ASSERT (new_nbuckets == vec_len (new));
  /* store old pointer in to-be-freed list */
  vec_add1 (h->to_be_freed, old);
  /* mark new elements as free */
  CVT (clib_cuckoo_bucket) * bucket;
  for (bucket = new + old_nbuckets; bucket < vec_end (new); ++bucket)
    {
      clib_memset (bucket->elts, 0xff, sizeof (bucket->elts));
    }
  /*
   * this for loop manipulates the new (unseen) memory, so no locks
   * are required here
   */
  uword old_bucket_idx;
  for (old_bucket_idx = 0; old_bucket_idx < old_nbuckets; ++old_bucket_idx)
    {
      /* items in old bucket might be moved to new bucket */
      uword new_bucket_idx = old_bucket_idx + old_nbuckets;
      CVT (clib_cuckoo_bucket) * old_bucket = new + old_bucket_idx;
      CVT (clib_cuckoo_bucket) * new_bucket = new + new_bucket_idx;
      int i = 0;
      int moved = 0;
      clib_cuckoo_bucket_aux_t aux = old_bucket->aux;
      for (i = 0; i < clib_cuckoo_bucket_aux_get_use_count (aux); ++i)
	{
	  CVT (clib_cuckoo_kv) * elt = old_bucket->elts + i;
	  u64 hash = CV (clib_cuckoo_hash) (elt);
	  clib_cuckoo_lookup_info_t old_lookup =
	    CV (clib_cuckoo_calc_lookup) (old, hash);
	  clib_cuckoo_lookup_info_t new_lookup =
	    CV (clib_cuckoo_calc_lookup) (new, hash);
	  if ((old_bucket_idx == old_lookup.bucket1 &&
	       new_bucket_idx == new_lookup.bucket1) ||
	      (old_bucket_idx == old_lookup.bucket2 &&
	       new_bucket_idx == new_lookup.bucket2))
	    {
	      /* move the item to new bucket */
	      CVT (clib_cuckoo_kv) * empty_elt = new_bucket->elts + moved;
	      ASSERT (empty_elt);
	      CV (clib_cuckoo_set_locked_elt)
		(new_bucket, empty_elt, elt, old_bucket->reduced_hashes[i]);
	      CV (clib_cuckoo_free_locked_elt) (elt);
	      ++moved;
	    }
	}
      if (moved)
	{
	  CV (clib_cuckoo_bucket_tidy) (old_bucket);
	  aux =
	    clib_cuckoo_bucket_aux_set_use_count (aux,
						  clib_cuckoo_bucket_aux_get_use_count
						  (aux) - moved);
	  old_bucket->aux = aux;
	  aux = new_bucket->aux;
	  aux =
	    clib_cuckoo_bucket_aux_set_use_count (aux,
						  clib_cuckoo_bucket_aux_get_use_count
						  (aux) + moved);
	  new_bucket->aux = aux;
	}
    }
  h->buckets = new;
#if CLIB_CUCKOO_DEBUG_COUNTERS
  ++h->rehashes;
#endif
  h->garbage_callback (h, h->garbage_ctx);
}

static int CV (clib_cuckoo_bucket_search_internal) (CVT (clib_cuckoo) * h,
						    uword bucket,
						    CVT (clib_cuckoo_kv) *
						    kvp,
						    CVT (clib_cuckoo_kv) *
						    *found)
{
  CVT (clib_cuckoo_bucket) * b = CV (clib_cuckoo_bucket_at_index) (h, bucket);
  int i;
  /* *INDENT-OFF* */
  clib_cuckoo_bucket_foreach_idx_unrolled (i, {
    CVT (clib_cuckoo_kv) *elt = &b->elts[i];
    if (CV (clib_cuckoo_key_compare) (elt->key, kvp->key))
      {
        *found = elt;
        return CLIB_CUCKOO_ERROR_SUCCESS;
      }
  });
  /* *INDENT-ON* */
  return CLIB_CUCKOO_ERROR_NOT_FOUND;
}

int CV (clib_cuckoo_add_del) (CVT (clib_cuckoo) * h,
			      CVT (clib_cuckoo_kv) * kvp, int is_add)
{
  CLIB_CUCKOO_DBG ("%s %U", is_add ? "Add" : "Del", CV (format_cuckoo_kvp),
		   kvp);
  clib_cuckoo_lookup_info_t lookup;
  u64 hash = CV (clib_cuckoo_hash) (kvp);
  clib_spinlock_lock (&h->writer_lock);
  u8 reduced_hash = clib_cuckoo_reduce_hash (hash);
restart:
  lookup = CV (clib_cuckoo_calc_lookup) (h->buckets, hash);
  CVT (clib_cuckoo_bucket) * b =
    CV (clib_cuckoo_bucket_at_index) (h, lookup.bucket1);
  CVT (clib_cuckoo_kv) * found;
  int rv =
    CV (clib_cuckoo_bucket_search_internal) (h, lookup.bucket1, kvp, &found);
  if (CLIB_CUCKOO_ERROR_SUCCESS != rv)
    {
      ASSERT (CLIB_CUCKOO_ERROR_NOT_FOUND == rv);
      b = CV (clib_cuckoo_bucket_at_index) (h, lookup.bucket2);
      rv = CV (clib_cuckoo_bucket_search_internal) (h, lookup.bucket2, kvp,
						    &found);
    }
  if (CLIB_CUCKOO_ERROR_SUCCESS == rv)
    {
      if (is_add)
	{
	  /* prevent readers reading this bucket while we switch the values */
	  clib_cuckoo_bucket_aux_t aux =
	    CV (clib_cuckoo_bucket_version_bump_and_lock) (b);
	  clib_memcpy (&found->value, &kvp->value, sizeof (found->value));
	  CLIB_CUCKOO_DBG ("Replaced existing %U", CV (format_cuckoo_elt),
			   found, b->reduced_hashes[found - b->elts]);
	  CV (clib_cuckoo_bucket_unlock) (b, aux);
	}
      else
	{
	  CV (clib_cuckoo_free_elt_in_bucket) (b, found);
	}
      rv = CLIB_CUCKOO_ERROR_SUCCESS;
      CLIB_CUCKOO_DEEP_SELF_CHECK (h);
      goto unlock;
    }
  if (!is_add)
    {
      CLIB_CUCKOO_DBG ("%U not present in table", CV (format_cuckoo_kvp),
		       kvp);
      rv = CLIB_CUCKOO_ERROR_NOT_FOUND;
      goto unlock;
    }
  /* from this point on, it's add code only */
  ASSERT (CLIB_CUCKOO_ERROR_NOT_FOUND == rv);
  /* fast path: try to search for unoccupied slot in one of the buckets */
  rv = CV (clib_cuckoo_add_fast) (h, &lookup, kvp, reduced_hash);
  CLIB_CUCKOO_DEEP_SELF_CHECK (h);
  if (CLIB_CUCKOO_ERROR_SUCCESS != rv)
    {
    CLIB_CUCKOO_DBG ("Fast insert failed, bucket 1: %wu, bucket 2: %wu\n%U%U", aux.bucket1, aux.bucket2, CV (format_cuckoo_bucket), CV (clib_cuckoo_bucindent: Standaindent: Standard input: 903: Error: Unmatched 'else' rd input: 865: Error:Unmatched 'else' ket_at_index) (h, aux.bucket1),
		       CV (format_cuckoo_bucket),
		       CV (clib_cuckoo_bucket_at_index) (h, aux.bucket2));
      /* slow path */
      rv = CV (clib_cuckoo_add_slow) (h, kvp, &lookup, reduced_hash);
      CLIB_CUCKOO_DEEP_SELF_CHECK (h);
      if (CLIB_CUCKOO_ERROR_SUCCESS != rv)
	{
	  CLIB_CUCKOO_DBG ("Slow insert failed, rehash required:\n%U",
			   CV (format_cuckoo), h, 1);
	  /* ultra slow path */
	  CV (clib_cuckoo_rehash) (h);
	  CLIB_CUCKOO_DEEP_SELF_CHECK (h);
	  CLIB_CUCKOO_DBG ("Restarting add after rehash...");
	  goto restart;
	}
    }
unlock:
  clib_spinlock_unlock (&h->writer_lock);
  return rv;
}

u8 *CV (format_cuckoo) (u8 * s, va_list * args)
{
  CVT (clib_cuckoo) * h = va_arg (*args, CVT (clib_cuckoo) *);
  int verbose = va_arg (*args, int);

  s = format (s, "Hash table %s\n", h->name ? h->name : "(unnamed)");

  uword free = 0;
  uword used = 0;
  uword use_count_total = 0;
  float load_factor;
  CVT (clib_cuckoo_bucket) * b;
  /* *INDENT-OFF* */
  clib_cuckoo_foreach_bucket (b, h, {
    if (verbose)
      {
        s = format (s, "%U", CV (format_cuckoo_bucket), b);
      }
    int i;
    clib_cuckoo_bucket_foreach_idx (i)
    {
      CVT (clib_cuckoo_kv) *elt = &b->elts[i];
      if (CV (clib_cuckoo_kv_is_free) (elt))
        {
          ++free;
        }
      else
        {
          ++used;
        }
    }
    clib_cuckoo_bucket_aux_t aux = b->aux;
    use_count_total += clib_cuckoo_bucket_aux_get_use_count (aux);
  });
  /* *INDENT-ON* */
  s = format (s, "Used slots: %wu\n", used);
  s = format (s, "Use count total: %wu\n", use_count_total);
  s = format (s, "Free slots: %wu\n", free);
  if (free + used != 0)
    load_factor = ((float) used) / ((float) (free + used));
  else
    load_factor = 0.0;
  s = format (s, "Load factor: %.2f\n", load_factor);
#if CLIB_CUCKOO_DEBUG_COUNTERS
  s = format (s, "BFS attempts limited by max steps: %lld\n",
	      h->steps_exceeded);
  s = format (s, "BFS cutoffs due to empty queue: %lld\n",
	      h->bfs_queue_emptied);
  s = format (s, "Fast adds: %lld\n", h->fast_adds);
  s = format (s, "Slow adds: %lld\n", h->slow_adds);
  s = format (s, "Rehashes: %lld\n", h->rehashes);
#endif
  return s;
}

float CV (clib_cuckoo_calculate_load_factor) (CVT (clib_cuckoo) * h)
{
  uword nonfree = 0;
  uword all = 0;
  CVT (clib_cuckoo_bucket) * bucket;
  /* *INDENT-OFF* */
  clib_cuckoo_foreach_bucket (bucket, h, {
    int i;
    clib_cuckoo_bucket_foreach_idx (i)
    {
      CVT (clib_cuckoo_kv) *elt = bucket->elts + i;
      ++all;
      if (!CV (clib_cuckoo_kv_is_free) (elt))
        {
          ++nonfree;
        }
    }
  });
  /* *INDENT-ON* */
  if (all)
    return (float) nonfree / (float) all;
  else
    return 0.0;
}

/** @endcond */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
