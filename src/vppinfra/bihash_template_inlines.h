/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco Systems, Inc.
 */
#ifndef __included_bihash_template_inlines_h__
#define __included_bihash_template_inlines_h__
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

#ifndef BIIHASH_MIN_ALLOC_LOG2_PAGES
#define BIIHASH_MIN_ALLOC_LOG2_PAGES 10
#endif

#ifndef BIHASH_USE_HEAP
#define BIHASH_USE_HEAP 1
#endif

static inline void *
BV (alloc_aligned) (BVT (clib_bihash) * h, uword nbytes)
{
  uword rv;

  /* Round to an even number of cache lines */
  nbytes = round_pow2 (nbytes, CLIB_CACHE_LINE_BYTES);

  if (BIHASH_USE_HEAP)
    {
      void *rv, *oldheap;
      uword page_sz = sizeof (BVT (clib_bihash_value));
      uword chunk_sz = round_pow2 (page_sz << BIIHASH_MIN_ALLOC_LOG2_PAGES,
				   CLIB_CACHE_LINE_BYTES);

      BVT (clib_bihash_alloc_chunk) *chunk = h->chunks;

      /* if there is enough space in the currenrt chunk */
      if (chunk && chunk->bytes_left >= nbytes)
	{
	  rv = chunk->next_alloc;
	  chunk->bytes_left -= nbytes;
	  chunk->next_alloc += nbytes;
	  return rv;
	}

      /* requested allocation is bigger than chunk size */
      if (nbytes >= chunk_sz)
	{
	  oldheap = clib_mem_set_heap (h->heap);
	  chunk = clib_mem_alloc_aligned (nbytes + sizeof (*chunk),
					  CLIB_CACHE_LINE_BYTES);
	  clib_mem_set_heap (oldheap);
	  clib_memset_u8 (chunk, 0, sizeof (*chunk));
	  chunk->size = nbytes;
	  rv = (u8 *) (chunk + 1);
	  if (h->chunks)
	    {
	      /* take 2nd place in the list */
	      chunk->next = h->chunks->next;
	      chunk->prev = h->chunks;
	      h->chunks->next = chunk;
	      if (chunk->next)
		chunk->next->prev = chunk;
	    }
	  else
	    h->chunks = chunk;

	  return rv;
	}

      oldheap = clib_mem_set_heap (h->heap);
      chunk = clib_mem_alloc_aligned (chunk_sz + sizeof (*chunk),
				      CLIB_CACHE_LINE_BYTES);
      clib_mem_set_heap (oldheap);
      chunk->size = chunk_sz;
      chunk->bytes_left = chunk_sz;
      chunk->next_alloc = (u8 *) (chunk + 1);
      chunk->next = h->chunks;
      chunk->prev = 0;
      if (chunk->next)
	chunk->next->prev = chunk;
      h->chunks = chunk;
      rv = chunk->next_alloc;
      chunk->bytes_left -= nbytes;
      chunk->next_alloc += nbytes;
      return rv;
    }

  rv = alloc_arena_next (h);
  alloc_arena_next (h) += nbytes;

  if (alloc_arena_next (h) > alloc_arena_size (h))
    os_out_of_memory ();

  if (alloc_arena_next (h) > alloc_arena_mapped (h))
    {
      void *base, *rv;
      uword alloc = alloc_arena_next (h) - alloc_arena_mapped (h);
      int mmap_flags = MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS;
#if __linux__
      int mmap_flags_huge = (mmap_flags | MAP_HUGETLB | MAP_LOCKED |
			     BIHASH_LOG2_HUGEPAGE_SIZE << MAP_HUGE_SHIFT);
#endif /* __linux__ */

      /* new allocation is 25% of existing one */
      if (alloc_arena_mapped (h) >> 2 > alloc)
	alloc = alloc_arena_mapped (h) >> 2;

      /* round allocation to page size */
      alloc = round_pow2 (alloc, 1 << BIHASH_LOG2_HUGEPAGE_SIZE);

      base = (void *) (uword) (alloc_arena (h) + alloc_arena_mapped (h));

#if __linux__
      rv = mmap (base, alloc, PROT_READ | PROT_WRITE, mmap_flags_huge, -1, 0);
#elif __FreeBSD__
      rv = MAP_FAILED;
#endif /* __linux__ */

      /* fallback - maybe we are still able to allocate normal pages */
      if (rv == MAP_FAILED || mlock (base, alloc) != 0)
	rv = mmap (base, alloc, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);

      if (rv == MAP_FAILED)
	os_out_of_memory ();

      alloc_arena_mapped (h) += alloc;
    }

  return (void *) (uword) (rv + alloc_arena (h));
}

static void
BV (clib_bihash_instantiate) (BVT (clib_bihash) * h)
{
  uword bucket_size;

  if (BIHASH_USE_HEAP)
    {
      h->heap = clib_mem_get_heap ();
      h->chunks = 0;
      alloc_arena (h) = (uword) clib_mem_get_heap_base (h->heap);
    }
  else
    {
      alloc_arena (h) =
	clib_mem_vm_reserve (0, h->memory_size, BIHASH_LOG2_HUGEPAGE_SIZE);
      if (alloc_arena (h) == ~0)
	os_out_of_memory ();
      alloc_arena_next (h) = 0;
      alloc_arena_size (h) = h->memory_size;
      alloc_arena_mapped (h) = 0;
    }

  bucket_size = h->nbuckets * sizeof (h->buckets[0]);

  if (BIHASH_KVP_AT_BUCKET_LEVEL)
    bucket_size +=
      h->nbuckets * BIHASH_KVP_PER_PAGE * sizeof (BVT (clib_bihash_kv));

  h->buckets = BV (alloc_aligned) (h, bucket_size);
  clib_memset_u8 (h->buckets, 0, bucket_size);

  if (BIHASH_KVP_AT_BUCKET_LEVEL)
    {
      int i, j;
      BVT (clib_bihash_bucket) * b;

      b = h->buckets;

      for (i = 0; i < h->nbuckets; i++)
	{
	  BVT (clib_bihash_kv) * v;
	  b->offset = BV (clib_bihash_get_offset) (h, (void *) (b + 1));
	  b->refcnt = 1;
	  /* Mark all elements free */
	  v = (void *) (b + 1);
	  for (j = 0; j < BIHASH_KVP_PER_PAGE; j++)
	    {
	      BV (clib_bihash_mark_free) (v);
	      v++;
	    }
	  /* Compute next bucket start address */
	  b = (void *) (((uword) b) + sizeof (*b) +
			(BIHASH_KVP_PER_PAGE * sizeof (BVT (clib_bihash_kv))));
	}
    }
  CLIB_MEMORY_STORE_BARRIER ();
  h->instantiated = 1;
}

static BVT (clib_bihash_value) *
  BV (value_alloc) (BVT (clib_bihash) * h, u32 log2_pages)
{
  int i;
  BVT (clib_bihash_value) *rv = 0;

  ASSERT (h->alloc_lock[0]);

#if BIHASH_32_64_SVM
  ASSERT (log2_pages < vec_len (h->freelists));
#endif

  if (log2_pages >= vec_len (h->freelists) || h->freelists[log2_pages] == 0)
    {
      vec_validate_init_empty (h->freelists, log2_pages, 0);
      rv = BV (alloc_aligned) (h, (sizeof (*rv) * (1 << log2_pages)));
      goto initialize;
    }
  rv = BV (clib_bihash_get_value) (h, (uword) h->freelists[log2_pages]);
  h->freelists[log2_pages] = rv->next_free_as_u64;

initialize:
  ASSERT (rv);

  BVT (clib_bihash_kv) * v;
  v = (BVT (clib_bihash_kv) *) rv;

  for (i = 0; i < BIHASH_KVP_PER_PAGE * (1 << log2_pages); i++)
    {
      BV (clib_bihash_mark_free) (v);
      v++;
    }
  return rv;
}

static void
BV (value_free) (BVT (clib_bihash) * h, BVT (clib_bihash_value) * v,
		 u32 log2_pages)
{
  ASSERT (h->alloc_lock[0]);

  ASSERT (vec_len (h->freelists) > log2_pages);

  if (BIHASH_USE_HEAP && log2_pages >= BIIHASH_MIN_ALLOC_LOG2_PAGES)
    {
      /* allocations bigger or equal to chunk size always contain single
       * alloc and they can be given back to heap */
      void *oldheap;
      BVT (clib_bihash_alloc_chunk) * c;
      c = (BVT (clib_bihash_alloc_chunk) *) v - 1;

      if (c->prev)
	c->prev->next = c->next;
      else
	h->chunks = c->next;

      if (c->next)
	c->next->prev = c->prev;

      oldheap = clib_mem_set_heap (h->heap);
      clib_mem_free (c);
      clib_mem_set_heap (oldheap);
      return;
    }

  if (CLIB_DEBUG > 0)
    clib_memset_u8 (v, 0xFE, sizeof (*v) * (1 << log2_pages));

  v->next_free_as_u64 = (u64) h->freelists[log2_pages];
  h->freelists[log2_pages] = (u64) BV (clib_bihash_get_offset) (h, v);
}

static inline void
BV (make_working_copy) (BVT (clib_bihash) * h, BVT (clib_bihash_bucket) * b)
{
  BVT (clib_bihash_value) * v;
  BVT (clib_bihash_bucket) working_bucket __attribute__ ((aligned (8)));
  BVT (clib_bihash_value) * working_copy;
  clib_thread_index_t thread_index = os_get_thread_index ();
  int log2_working_copy_length;

  ASSERT (h->alloc_lock[0]);

  if (thread_index >= vec_len (h->working_copies))
    {
      vec_validate (h->working_copies, thread_index);
      vec_validate_init_empty (h->working_copy_lengths, thread_index, ~0);
    }

  /*
   * working_copies are per-cpu so that near-simultaneous
   * updates from multiple threads will not result in sporadic, spurious
   * lookup failures.
   */
  working_copy = h->working_copies[thread_index];
  log2_working_copy_length = h->working_copy_lengths[thread_index];

  h->saved_bucket.as_u64 = b->as_u64;

  if (b->log2_pages > log2_working_copy_length)
    {
      /*
       * It's not worth the bookkeeping to free working copies
       *   if (working_copy)
       *     clib_mem_free (working_copy);
       */
      working_copy = BV (alloc_aligned) (h, sizeof (working_copy[0]) *
					      (1 << b->log2_pages));
      h->working_copy_lengths[thread_index] = b->log2_pages;
      h->working_copies[thread_index] = working_copy;

      BV (clib_bihash_increment_stat)
      (h, BIHASH_STAT_working_copy_lost, 1ULL << b->log2_pages);
    }

  v = BV (clib_bihash_get_value) (h, b->offset);

  clib_memcpy_fast (working_copy, v, sizeof (*v) * (1 << b->log2_pages));
  working_bucket.as_u64 = b->as_u64;
  working_bucket.offset = BV (clib_bihash_get_offset) (h, working_copy);
  clib_atomic_store_rel_n (&b->as_u64, working_bucket.as_u64);
  h->working_copies[thread_index] = working_copy;
}

static BVT (clib_bihash_value) *
  BV (split_and_rehash) (BVT (clib_bihash) * h,
			 BVT (clib_bihash_value) * old_values,
			 u32 old_log2_pages, u32 new_log2_pages)
{
  BVT (clib_bihash_value) * new_values, *new_v;
  int i, j, length_in_kvs;

  ASSERT (h->alloc_lock[0]);

  new_values = BV (value_alloc) (h, new_log2_pages);
  length_in_kvs = (1 << old_log2_pages) * BIHASH_KVP_PER_PAGE;

  for (i = 0; i < length_in_kvs; i++)
    {
      u64 new_hash;

      /* Entry not in use? Forget it */
      if (BV (clib_bihash_is_free) (&(old_values->kvp[i])))
	continue;

      /* rehash the item onto its new home-page */
      new_hash = BV (clib_bihash_hash) (&(old_values->kvp[i]));
      new_hash = extract_bits (new_hash, h->log2_nbuckets, new_log2_pages);
      new_v = &new_values[new_hash];

      /* Across the new home-page */
      for (j = 0; j < BIHASH_KVP_PER_PAGE; j++)
	{
	  /* Empty slot */
	  if (BV (clib_bihash_is_free) (&(new_v->kvp[j])))
	    {
	      clib_memcpy_fast (&(new_v->kvp[j]), &(old_values->kvp[i]),
				sizeof (new_v->kvp[j]));
	      goto doublebreak;
	    }
	}
      /* Crap. Tell caller to try again */
      BV (value_free) (h, new_values, new_log2_pages);
      return 0;
    doublebreak:;
    }

  return new_values;
}

static BVT (clib_bihash_value) *
  BV (split_and_rehash_linear) (BVT (clib_bihash) * h,
				BVT (clib_bihash_value) * old_values,
				u32 old_log2_pages, u32 new_log2_pages)
{
  BVT (clib_bihash_value) * new_values;
  int i, j, new_length, old_length;

  ASSERT (h->alloc_lock[0]);

  new_values = BV (value_alloc) (h, new_log2_pages);
  new_length = (1 << new_log2_pages) * BIHASH_KVP_PER_PAGE;
  old_length = (1 << old_log2_pages) * BIHASH_KVP_PER_PAGE;

  j = 0;
  /* Across the old value array */
  for (i = 0; i < old_length; i++)
    {
      /* Find a free slot in the new linear scan bucket */
      for (; j < new_length; j++)
	{
	  /* Old value not in use? Forget it. */
	  if (BV (clib_bihash_is_free) (&(old_values->kvp[i])))
	    goto doublebreak;

	  /* New value should never be in use */
	  if (BV (clib_bihash_is_free) (&(new_values->kvp[j])))
	    {
	      /* Copy the old value and move along */
	      clib_memcpy_fast (&(new_values->kvp[j]), &(old_values->kvp[i]),
				sizeof (new_values->kvp[j]));
	      j++;
	      goto doublebreak;
	    }
	}
      /* This should never happen... */
      clib_warning ("BUG: linear rehash failed!");
      BV (value_free) (h, new_values, new_log2_pages);
      return 0;

    doublebreak:;
    }
  return new_values;
}

static_always_inline int
BV (clib_bihash_add_del_inline_with_hash) (
  BVT (clib_bihash) * h, BVT (clib_bihash_kv) * add_v, u64 hash, int is_add,
  int (*is_stale_cb) (BVT (clib_bihash_kv) *, void *), void *is_stale_arg,
  void (*overwrite_cb) (BVT (clib_bihash_kv) *, void *), void *overwrite_arg)
{
  BVT (clib_bihash_bucket) * b, tmp_b;
  BVT (clib_bihash_value) * v, *new_v, *save_new_v, *working_copy;
  int i, limit;
  u64 new_hash;
  u32 new_log2_pages, old_log2_pages;
  clib_thread_index_t thread_index = os_get_thread_index ();
  int mark_bucket_linear;
  int resplit_once;

  static const BVT (clib_bihash_bucket)
    mask = { .linear_search = 1, .log2_pages = -1 };

#if BIHASH_LAZY_INSTANTIATE
  /*
   * Create the table (is_add=1,2), or flunk the request now (is_add=0)
   * Use the alloc_lock to protect the instantiate operation.
   */
  if (PREDICT_FALSE (h->instantiated == 0))
    {
      if (is_add == 0)
	return (-1);

      BV (clib_bihash_alloc_lock) (h);
      if (h->instantiated == 0)
	BV (clib_bihash_instantiate) (h);
      BV (clib_bihash_alloc_unlock) (h);
    }
#else
  /* Debug image: make sure the table has been instantiated */
  ASSERT (h->instantiated != 0);
#endif

  /*
   * Debug image: make sure that an item being added doesn't accidentally
   * look like a free item.
   */
  ASSERT ((is_add && BV (clib_bihash_is_free) (add_v)) == 0);

  b = BV (clib_bihash_get_bucket) (h, hash);

  BV (clib_bihash_lock_bucket) (b);
  /* other writers will not touch this bucket  */

  /* First elt in the bucket? */
  if (BIHASH_KVP_AT_BUCKET_LEVEL == 0 && BV (clib_bihash_bucket_is_empty) (b))
    {
      if (is_add == 0)
	{
	  BV (clib_bihash_unlock_bucket) (b);
	  return (-1);
	}

      BV (clib_bihash_alloc_lock) (h);
      v = BV (value_alloc) (h, 0);
      BV (clib_bihash_alloc_unlock) (h);

      v->kvp[0] = *add_v;
      tmp_b.as_u64 = 0; /* clears bucket lock */
      tmp_b.offset = BV (clib_bihash_get_offset) (h, v);
      tmp_b.refcnt = 1;

      clib_atomic_store_rel_n (&b->as_u64,
			       tmp_b.as_u64); /* unlocks the bucket */
      BV (clib_bihash_increment_stat) (h, BIHASH_STAT_alloc_add, 1);

      return (0);
    }

  /* WARNING: we're still looking at the live copy... */
  limit = BIHASH_KVP_PER_PAGE;
  v = BV (clib_bihash_get_value) (h, b->offset);

  if (PREDICT_FALSE (b->as_u64 & mask.as_u64))
    {
      if (PREDICT_FALSE (b->linear_search))
	limit <<= b->log2_pages;
      else
	v += extract_bits (hash, h->log2_nbuckets, b->log2_pages);
    }

  if (is_add)
    {
      /*
       * Because reader threads are looking at live data,
       * we have to be extra careful. Readers do NOT hold the
       * bucket lock. We need to be SLOWER than a search, past the
       * point where readers CHECK the bucket lock.
       */

      /*
       * For obvious (in hindsight) reasons, see if we're supposed to
       * replace an existing key, then look for an empty slot.
       */
      for (i = 0; i < limit; i++)
	{
	  if (BV (clib_bihash_is_free) (&(v->kvp[i])))
	    continue;
	  if (BV (clib_bihash_key_compare) (v->kvp[i].key, add_v->key))
	    {
	      /* Add but do not overwrite? */
	      if (is_add == 2)
		{
		  BV (clib_bihash_unlock_bucket) (b);
		  return (-2);
		}
	      if (overwrite_cb)
		overwrite_cb (&(v->kvp[i]), overwrite_arg);
	      clib_memcpy_fast (&(v->kvp[i].value), &add_v->value,
				sizeof (add_v->value));
	      BV (clib_bihash_unlock_bucket) (b);
	      BV (clib_bihash_increment_stat) (h, BIHASH_STAT_replace, 1);
	      return (0);
	    }
	}
      /*
       * Look for an empty slot. If found, use it
       */
      for (i = 0; i < limit; i++)
	{
	  if (BV (clib_bihash_is_free) (&(v->kvp[i])))
	    {
	      /*
	       * Copy the value first, so that if a reader manages
	       * to match the new key, the value will be right...
	       */
	      clib_memcpy_fast (&(v->kvp[i].value), &add_v->value,
				sizeof (add_v->value));
	      CLIB_MEMORY_STORE_BARRIER (); /* Make sure the value has settled
					     */
	      clib_memcpy_fast (&(v->kvp[i]), &add_v->key,
				sizeof (add_v->key));
	      b->refcnt++;
	      ASSERT (b->refcnt > 0);
	      BV (clib_bihash_unlock_bucket) (b);
	      BV (clib_bihash_increment_stat) (h, BIHASH_STAT_add, 1);
	      return (0);
	    }
	}
      /* look for stale data to overwrite */
      if (is_stale_cb)
	{
	  for (i = 0; i < limit; i++)
	    {
	      if (is_stale_cb (&(v->kvp[i]), is_stale_arg))
		{
		  clib_memcpy_fast (&(v->kvp[i]), add_v, sizeof (*add_v));
		  b->generation++;
		  BV (clib_bihash_unlock_bucket) (b);
		  BV (clib_bihash_increment_stat) (h, BIHASH_STAT_replace, 1);
		  return (0);
		}
	    }
	}
      /* Out of space in this bucket, split the bucket... */
    }
  else /* delete case */
    {
      for (i = 0; i < limit; i++)
	{
	  /* no sense even looking at this one */
	  if (BV (clib_bihash_is_free) (&(v->kvp[i])))
	    continue;
	  /* Found the key? Kill it... */
	  if (BV (clib_bihash_key_compare) (v->kvp[i].key, add_v->key))
	    {
	      BV (clib_bihash_mark_free) (&(v->kvp[i]));
	      /* Is the bucket empty? */
	      if (PREDICT_TRUE (b->refcnt > 1))
		{
		  b->refcnt--;
		  /* Switch back to the bucket-level kvp array? */
		  if (BIHASH_KVP_AT_BUCKET_LEVEL && b->refcnt == 1 &&
		      b->log2_pages > 0)
		    {
		      tmp_b.as_u64 = b->as_u64;
		      b->offset =
			BV (clib_bihash_get_offset) (h, (void *) (b + 1));
		      b->linear_search = 0;
		      b->log2_pages = 0;
		      /* Clean up the bucket-level kvp array */
		      BVT (clib_bihash_kv) *v = (void *) (b + 1);
		      int j;
		      for (j = 0; j < BIHASH_KVP_PER_PAGE; j++)
			{
			  BV (clib_bihash_mark_free) (v);
			  v++;
			}
		      CLIB_MEMORY_STORE_BARRIER ();
		      BV (clib_bihash_unlock_bucket) (b);
		      BV (clib_bihash_increment_stat) (h, BIHASH_STAT_del, 1);
		      goto free_backing_store;
		    }

		  CLIB_MEMORY_STORE_BARRIER ();
		  BV (clib_bihash_unlock_bucket) (b);
		  BV (clib_bihash_increment_stat) (h, BIHASH_STAT_del, 1);
		  return (0);
		}
	      else /* yes, free it */
		{
		  /* Save old bucket value, need log2_pages to free it */
		  tmp_b.as_u64 = b->as_u64;

		  /* Kill and unlock the bucket */
		  b->as_u64 = 0;

		free_backing_store:
		  /* And free the backing storage */
		  BV (clib_bihash_alloc_lock) (h);
		  /* Note: v currently points into the middle of the bucket */
		  v = BV (clib_bihash_get_value) (h, tmp_b.offset);
		  BV (value_free) (h, v, tmp_b.log2_pages);
		  BV (clib_bihash_alloc_unlock) (h);
		  BV (clib_bihash_increment_stat) (h, BIHASH_STAT_del_free, 1);
		  return (0);
		}
	    }
	}
      /* Not found... */
      BV (clib_bihash_unlock_bucket) (b);
      return (-3);
    }

  /* Move readers to a (locked) temp copy of the bucket */
  BV (clib_bihash_alloc_lock) (h);
  BV (make_working_copy) (h, b);

  v = BV (clib_bihash_get_value) (h, h->saved_bucket.offset);

  old_log2_pages = h->saved_bucket.log2_pages;
  new_log2_pages = old_log2_pages + 1;
  mark_bucket_linear = 0;
  BV (clib_bihash_increment_stat) (h, BIHASH_STAT_split_add, 1);
  BV (clib_bihash_increment_stat) (h, BIHASH_STAT_splits, old_log2_pages);

  working_copy = h->working_copies[thread_index];
  resplit_once = 0;
  BV (clib_bihash_increment_stat) (h, BIHASH_STAT_splits, 1);

  new_v =
    BV (split_and_rehash) (h, working_copy, old_log2_pages, new_log2_pages);
  if (new_v == 0)
    {
    try_resplit:
      resplit_once = 1;
      new_log2_pages++;
      /* Try re-splitting. If that fails, fall back to linear search */
      new_v = BV (split_and_rehash) (h, working_copy, old_log2_pages,
				     new_log2_pages);
      if (new_v == 0)
	{
	mark_linear:
	  new_log2_pages--;
	  /* pinned collisions, use linear search */
	  new_v = BV (split_and_rehash_linear) (
	    h, working_copy, old_log2_pages, new_log2_pages);
	  mark_bucket_linear = 1;
	  BV (clib_bihash_increment_stat) (h, BIHASH_STAT_linear, 1);
	}
      BV (clib_bihash_increment_stat) (h, BIHASH_STAT_resplit, 1);
      BV (clib_bihash_increment_stat)
      (h, BIHASH_STAT_splits, old_log2_pages + 1);
    }

  /* Try to add the new entry */
  save_new_v = new_v;
  new_hash = BV (clib_bihash_hash) (add_v);
  limit = BIHASH_KVP_PER_PAGE;
  if (mark_bucket_linear)
    limit <<= new_log2_pages;
  else
    new_v += extract_bits (new_hash, h->log2_nbuckets, new_log2_pages);

  for (i = 0; i < limit; i++)
    {
      if (BV (clib_bihash_is_free) (&(new_v->kvp[i])))
	{
	  clib_memcpy_fast (&(new_v->kvp[i]), add_v, sizeof (*add_v));
	  goto expand_ok;
	}
    }

  /* Crap. Try again */
  BV (value_free) (h, save_new_v, new_log2_pages);
  /*
   * If we've already doubled the size of the bucket once,
   * fall back to linear search now.
   */
  if (resplit_once)
    goto mark_linear;
  else
    goto try_resplit;

expand_ok:
  tmp_b.log2_pages = new_log2_pages;
  tmp_b.offset = BV (clib_bihash_get_offset) (h, save_new_v);
  tmp_b.linear_search = mark_bucket_linear;
  tmp_b.generation = h->saved_bucket.generation + 1;
#if BIHASH_KVP_AT_BUCKET_LEVEL
  /* Compensate for permanent refcount bump at the bucket level */
  if (new_log2_pages > 0)
#endif
    tmp_b.refcnt = h->saved_bucket.refcnt + 1;
  ASSERT (tmp_b.refcnt > 0);
  tmp_b.lock = 0;
  clib_atomic_store_rel_n (&b->as_u64, tmp_b.as_u64);

#if BIHASH_KVP_AT_BUCKET_LEVEL
  if (h->saved_bucket.log2_pages > 0)
    {
#endif

      /* free the old bucket, except at the bucket level if so configured */
      v = BV (clib_bihash_get_value) (h, h->saved_bucket.offset);
      BV (value_free) (h, v, h->saved_bucket.log2_pages);

#if BIHASH_KVP_AT_BUCKET_LEVEL
    }
#endif

  BV (clib_bihash_alloc_unlock) (h);
  return (0);
}

static_always_inline int
BV (clib_bihash_add_del_inline) (
  BVT (clib_bihash) * h, BVT (clib_bihash_kv) * add_v, int is_add,
  int (*is_stale_cb) (BVT (clib_bihash_kv) *, void *), void *arg)
{
  u64 hash = BV (clib_bihash_hash) (add_v);
  return BV (clib_bihash_add_del_inline_with_hash) (h, add_v, hash, is_add,
						    is_stale_cb, arg, 0, 0);
}

#endif /* __included_bihash_template_inlines_h__ */
