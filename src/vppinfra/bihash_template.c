/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

static inline void *BV (alloc_aligned) (BVT (clib_bihash) * h, uword nbytes)
{
  uword rv;

  /* Round to an even number of cache lines */
  nbytes += CLIB_CACHE_LINE_BYTES - 1;
  nbytes &= ~(CLIB_CACHE_LINE_BYTES - 1);

  rv = alloc_arena_next (h);
  alloc_arena_next (h) += nbytes;

  if (rv >= alloc_arena_size (h))
    os_out_of_memory ();

  return (void *) (uword) (rv + alloc_arena (h));
}


void BV (clib_bihash_init)
  (BVT (clib_bihash) * h, char *name, u32 nbuckets, uword memory_size)
{
  uword bucket_size;

  nbuckets = 1 << (max_log2 (nbuckets));

  h->name = (u8 *) name;
  h->nbuckets = nbuckets;
  h->log2_nbuckets = max_log2 (nbuckets);

  /*
   * Make sure the requested size is rational. The max table
   * size without playing the alignment card is 64 Gbytes.
   * If someone starts complaining that's not enough, we can shift
   * the offset by CLIB_LOG2_CACHE_LINE_BYTES...
   */
  ASSERT (memory_size < (1ULL << BIHASH_BUCKET_OFFSET_BITS));

  alloc_arena (h) = (uword) clib_mem_vm_alloc (memory_size);
  alloc_arena_next (h) = 0;
  alloc_arena_size (h) = memory_size;

  bucket_size = nbuckets * sizeof (h->buckets[0]);
  h->buckets = BV (alloc_aligned) (h, bucket_size);

  h->alloc_lock = BV (alloc_aligned) (h, CLIB_CACHE_LINE_BYTES);
  h->alloc_lock[0] = 0;

  h->fmt_fn = NULL;
}

#if BIHASH_32_64_SVM
#if !defined (MFD_ALLOW_SEALING)
#define MFD_ALLOW_SEALING 0x0002U
#endif

void BV (clib_bihash_master_init_svm)
  (BVT (clib_bihash) * h, char *name, u32 nbuckets, u64 memory_size)
{
  uword bucket_size;
  u8 *mmap_addr;
  vec_header_t *freelist_vh;
  int fd;

  ASSERT (memory_size < (1ULL << 32));
  /* Set up for memfd sharing */
  if ((fd = memfd_create (name, MFD_ALLOW_SEALING)) == -1)
    {
      clib_unix_warning ("memfd_create");
      return;
    }

  if (ftruncate (fd, memory_size) < 0)
    {
      clib_unix_warning ("ftruncate");
      return;
    }

  /* Not mission-critical, complain and continue */
  if ((fcntl (fd, F_ADD_SEALS, F_SEAL_SHRINK)) == -1)
    clib_unix_warning ("fcntl (F_ADD_SEALS)");

  mmap_addr = mmap (0, memory_size,
		    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 /* offset */ );

  if (mmap_addr == MAP_FAILED)
    {
      clib_unix_warning ("mmap failed");
      ASSERT (0);
    }

  h->sh = (void *) mmap_addr;
  h->memfd = fd;
  nbuckets = 1 << (max_log2 (nbuckets));

  h->name = (u8 *) name;
  h->sh->nbuckets = h->nbuckets = nbuckets;
  h->log2_nbuckets = max_log2 (nbuckets);

  alloc_arena (h) = (u64) (uword) mmap_addr;
  alloc_arena_next (h) = CLIB_CACHE_LINE_BYTES;
  alloc_arena_size (h) = memory_size;

  bucket_size = nbuckets * sizeof (h->buckets[0]);
  h->buckets = BV (alloc_aligned) (h, bucket_size);
  h->sh->buckets_as_u64 = (u64) BV (clib_bihash_get_offset) (h, h->buckets);

  h->alloc_lock = BV (alloc_aligned) (h, CLIB_CACHE_LINE_BYTES);
  h->alloc_lock[0] = 0;

  h->sh->alloc_lock_as_u64 =
    (u64) BV (clib_bihash_get_offset) (h, (void *) h->alloc_lock);
  freelist_vh =
    BV (alloc_aligned) (h,
			sizeof (vec_header_t) +
			BIHASH_FREELIST_LENGTH * sizeof (u64));
  freelist_vh->len = BIHASH_FREELIST_LENGTH;
  freelist_vh->dlmalloc_header_offset = 0xDEADBEEF;
  h->sh->freelists_as_u64 =
    (u64) BV (clib_bihash_get_offset) (h, freelist_vh->vector_data);
  h->freelists = (void *) (freelist_vh->vector_data);

  h->fmt_fn = NULL;
}

void BV (clib_bihash_slave_init_svm)
  (BVT (clib_bihash) * h, char *name, int fd)
{
  u8 *mmap_addr;
  u64 memory_size;
  BVT (clib_bihash_shared_header) * sh;

  /* Trial mapping, to learn the segment size */
  mmap_addr = mmap (0, 4096, PROT_READ, MAP_SHARED, fd, 0 /* offset */ );
  if (mmap_addr == MAP_FAILED)
    {
      clib_unix_warning ("trial mmap failed");
      ASSERT (0);
    }

  sh = (BVT (clib_bihash_shared_header) *) mmap_addr;

  memory_size = sh->alloc_arena_size;

  munmap (mmap_addr, 4096);

  /* Actual mapping, at the required size */
  mmap_addr = mmap (0, memory_size,
		    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0 /* offset */ );

  if (mmap_addr == MAP_FAILED)
    {
      clib_unix_warning ("mmap failed");
      ASSERT (0);
    }

  (void) close (fd);

  h->sh = (void *) mmap_addr;
  alloc_arena (h) = (u64) (uword) mmap_addr;
  h->memfd = -1;

  h->name = (u8 *) name;
  h->buckets = BV (clib_bihash_get_value) (h, h->sh->buckets_as_u64);
  h->nbuckets = h->sh->nbuckets;
  h->log2_nbuckets = max_log2 (h->nbuckets);

  h->alloc_lock = BV (clib_bihash_get_value) (h, h->sh->alloc_lock_as_u64);
  h->freelists = BV (clib_bihash_get_value) (h, h->sh->freelists_as_u64);
  h->fmt_fn = NULL;
}
#endif /* BIHASH_32_64_SVM */

void BV (clib_bihash_set_kvp_format_fn) (BVT (clib_bihash) * h,
					 format_function_t * fmt_fn)
{
  h->fmt_fn = fmt_fn;
}

void BV (clib_bihash_free) (BVT (clib_bihash) * h)
{
  vec_free (h->working_copies);
#if BIHASH_32_64_SVM == 0
  vec_free (h->freelists);
#else
  if (h->memfd > 0)
    (void) close (h->memfd);
#endif
  clib_mem_vm_free ((void *) (uword) (alloc_arena (h)), alloc_arena_size (h));
  memset (h, 0, sizeof (*h));
}

static
BVT (clib_bihash_value) *
BV (value_alloc) (BVT (clib_bihash) * h, u32 log2_pages)
{
  BVT (clib_bihash_value) * rv = 0;

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
  /*
   * Latest gcc complains that the length arg is zero
   * if we replace (1<<log2_pages) with vec_len(rv).
   * No clue.
   */
  memset (rv, 0xff, sizeof (*rv) * (1 << log2_pages));
  return rv;
}

static void
BV (value_free) (BVT (clib_bihash) * h, BVT (clib_bihash_value) * v,
		 u32 log2_pages)
{
  ASSERT (h->alloc_lock[0]);

  ASSERT (vec_len (h->freelists) > log2_pages);

  if (CLIB_DEBUG > 0)
    memset (v, 0xFE, sizeof (*v) * (1 << log2_pages));

  v->next_free_as_u64 = (u64) h->freelists[log2_pages];
  h->freelists[log2_pages] = (u64) BV (clib_bihash_get_offset) (h, v);
}

static inline void
BV (make_working_copy) (BVT (clib_bihash) * h, BVT (clib_bihash_bucket) * b)
{
  BVT (clib_bihash_value) * v;
  BVT (clib_bihash_bucket) working_bucket __attribute__ ((aligned (8)));
  BVT (clib_bihash_value) * working_copy;
  u32 thread_index = os_get_thread_index ();
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
      working_copy = BV (alloc_aligned)
	(h, sizeof (working_copy[0]) * (1 << b->log2_pages));
      h->working_copy_lengths[thread_index] = b->log2_pages;
      h->working_copies[thread_index] = working_copy;
    }

  v = BV (clib_bihash_get_value) (h, b->offset);

  clib_memcpy (working_copy, v, sizeof (*v) * (1 << b->log2_pages));
  working_bucket.as_u64 = b->as_u64;
  working_bucket.offset = BV (clib_bihash_get_offset) (h, working_copy);
  CLIB_MEMORY_BARRIER ();
  b->as_u64 = working_bucket.as_u64;
  h->working_copies[thread_index] = working_copy;
}

static
BVT (clib_bihash_value) *
BV (split_and_rehash)
  (BVT (clib_bihash) * h,
   BVT (clib_bihash_value) * old_values, u32 old_log2_pages,
   u32 new_log2_pages)
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
      new_hash >>= h->log2_nbuckets;
      new_hash &= (1 << new_log2_pages) - 1;
      new_v = &new_values[new_hash];

      /* Across the new home-page */
      for (j = 0; j < BIHASH_KVP_PER_PAGE; j++)
	{
	  /* Empty slot */
	  if (BV (clib_bihash_is_free) (&(new_v->kvp[j])))
	    {
	      clib_memcpy (&(new_v->kvp[j]), &(old_values->kvp[i]),
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

static
BVT (clib_bihash_value) *
BV (split_and_rehash_linear)
  (BVT (clib_bihash) * h,
   BVT (clib_bihash_value) * old_values, u32 old_log2_pages,
   u32 new_log2_pages)
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
	      clib_memcpy (&(new_values->kvp[j]), &(old_values->kvp[i]),
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

static inline int BV (clib_bihash_add_del_inline)
  (BVT (clib_bihash) * h, BVT (clib_bihash_kv) * add_v, int is_add,
   int (*is_stale_cb) (BVT (clib_bihash_kv) *, void *), void *arg)
{
  u32 bucket_index;
  BVT (clib_bihash_bucket) * b, tmp_b;
  BVT (clib_bihash_value) * v, *new_v, *save_new_v, *working_copy;
  int i, limit;
  u64 hash, new_hash;
  u32 new_log2_pages, old_log2_pages;
  u32 thread_index = os_get_thread_index ();
  int mark_bucket_linear;
  int resplit_once;

  hash = BV (clib_bihash_hash) (add_v);

  bucket_index = hash & (h->nbuckets - 1);
  b = &h->buckets[bucket_index];

  hash >>= h->log2_nbuckets;

  BV (clib_bihash_lock_bucket) (b);

  /* First elt in the bucket? */
  if (BV (clib_bihash_bucket_is_empty) (b))
    {
      if (is_add == 0)
	{
	  BV (clib_bihash_unlock_bucket) (b);
	  return (-1);
	}

      BV (clib_bihash_alloc_lock) (h);
      v = BV (value_alloc) (h, 0);
      BV (clib_bihash_alloc_unlock) (h);

      *v->kvp = *add_v;
      tmp_b.as_u64 = 0;		/* clears bucket lock */
      tmp_b.offset = BV (clib_bihash_get_offset) (h, v);
      tmp_b.refcnt = 1;
      CLIB_MEMORY_BARRIER ();

      b->as_u64 = tmp_b.as_u64;
      BV (clib_bihash_unlock_bucket) (b);
      return (0);
    }

  /* WARNING: we're still looking at the live copy... */
  limit = BIHASH_KVP_PER_PAGE;
  v = BV (clib_bihash_get_value) (h, b->offset);

  v += (b->linear_search == 0) ? hash & ((1 << b->log2_pages) - 1) : 0;
  if (b->linear_search)
    limit <<= b->log2_pages;

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
	  if (!memcmp (&(v->kvp[i]), &add_v->key, sizeof (add_v->key)))
	    {
	      CLIB_MEMORY_BARRIER ();	/* Add a delay */
	      clib_memcpy (&(v->kvp[i]), add_v, sizeof (*add_v));
	      BV (clib_bihash_unlock_bucket) (b);
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
	      clib_memcpy (&(v->kvp[i].value),
			   &add_v->value, sizeof (add_v->value));
	      CLIB_MEMORY_BARRIER ();	/* Make sure the value has settled */
	      clib_memcpy (&(v->kvp[i]), &add_v->key, sizeof (add_v->key));
	      b->refcnt++;
	      ASSERT (b->refcnt > 0);
	      BV (clib_bihash_unlock_bucket) (b);
	      return (0);
	    }
	}
      /* look for stale data to overwrite */
      if (is_stale_cb)
	{
	  for (i = 0; i < limit; i++)
	    {
	      if (is_stale_cb (&(v->kvp[i]), arg))
		{
		  CLIB_MEMORY_BARRIER ();
		  clib_memcpy (&(v->kvp[i]), add_v, sizeof (*add_v));
		  BV (clib_bihash_unlock_bucket) (b);
		  return (0);
		}
	    }
	}
      /* Out of space in this bucket, split the bucket... */
    }
  else				/* delete case */
    {
      for (i = 0; i < limit; i++)
	{
	  /* Found the key? Kill it... */
	  if (!memcmp (&(v->kvp[i]), &add_v->key, sizeof (add_v->key)))
	    {
	      memset (&(v->kvp[i]), 0xff, sizeof (*(add_v)));
	      /* Is the bucket empty? */
	      if (PREDICT_TRUE (b->refcnt > 1))
		{
		  b->refcnt--;
		  BV (clib_bihash_unlock_bucket) (b);
		  return (0);
		}
	      else		/* yes, free it */
		{
		  /* Save old bucket value, need log2_pages to free it */
		  tmp_b.as_u64 = b->as_u64;
		  CLIB_MEMORY_BARRIER ();

		  /* Kill and unlock the bucket */
		  b->as_u64 = 0;

		  /* And free the backing storage */
		  BV (clib_bihash_alloc_lock) (h);
		  /* Note: v currently points into the middle of the bucket */
		  v = BV (clib_bihash_get_value) (h, tmp_b.offset);
		  BV (value_free) (h, v, tmp_b.log2_pages);
		  BV (clib_bihash_alloc_unlock) (h);
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

  working_copy = h->working_copies[thread_index];
  resplit_once = 0;

  new_v = BV (split_and_rehash) (h, working_copy, old_log2_pages,
				 new_log2_pages);
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
	  new_v =
	    BV (split_and_rehash_linear) (h, working_copy, old_log2_pages,
					  new_log2_pages);
	  mark_bucket_linear = 1;
	}
    }

  /* Try to add the new entry */
  save_new_v = new_v;
  new_hash = BV (clib_bihash_hash) (add_v);
  limit = BIHASH_KVP_PER_PAGE;
  if (mark_bucket_linear)
    limit <<= new_log2_pages;
  new_hash >>= h->log2_nbuckets;
  new_hash &= (1 << new_log2_pages) - 1;
  new_v += mark_bucket_linear ? 0 : new_hash;

  for (i = 0; i < limit; i++)
    {
      if (BV (clib_bihash_is_free) (&(new_v->kvp[i])))
	{
	  clib_memcpy (&(new_v->kvp[i]), add_v, sizeof (*add_v));
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
  tmp_b.refcnt = h->saved_bucket.refcnt + 1;
  ASSERT (tmp_b.refcnt > 0);
  tmp_b.lock = 0;
  CLIB_MEMORY_BARRIER ();
  b->as_u64 = tmp_b.as_u64;
  /* free the old bucket */
  v = BV (clib_bihash_get_value) (h, h->saved_bucket.offset);
  BV (value_free) (h, v, h->saved_bucket.log2_pages);
  BV (clib_bihash_alloc_unlock) (h);
  return (0);
}

int BV (clib_bihash_add_del)
  (BVT (clib_bihash) * h, BVT (clib_bihash_kv) * add_v, int is_add)
{
  return BV (clib_bihash_add_del_inline) (h, add_v, is_add, 0, 0);
}

int BV (clib_bihash_add_or_overwrite_stale)
  (BVT (clib_bihash) * h, BVT (clib_bihash_kv) * add_v,
   int (*stale_callback) (BVT (clib_bihash_kv) *, void *), void *arg)
{
  return BV (clib_bihash_add_del_inline) (h, add_v, 1, stale_callback, arg);
}

int BV (clib_bihash_search)
  (BVT (clib_bihash) * h,
   BVT (clib_bihash_kv) * search_key, BVT (clib_bihash_kv) * valuep)
{
  u64 hash;
  u32 bucket_index;
  BVT (clib_bihash_value) * v;
  BVT (clib_bihash_bucket) * b;
  int i, limit;

  ASSERT (valuep);

  hash = BV (clib_bihash_hash) (search_key);

  bucket_index = hash & (h->nbuckets - 1);
  b = &h->buckets[bucket_index];

  if (BV (clib_bihash_bucket_is_empty) (b))
    return -1;

  if (PREDICT_FALSE (b->lock))
    {
      volatile BVT (clib_bihash_bucket) * bv = b;
      while (bv->lock)
	CLIB_PAUSE ();
    }

  hash >>= h->log2_nbuckets;

  v = BV (clib_bihash_get_value) (h, b->offset);
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

u8 *BV (format_bihash) (u8 * s, va_list * args)
{
  BVT (clib_bihash) * h = va_arg (*args, BVT (clib_bihash) *);
  int verbose = va_arg (*args, int);
  BVT (clib_bihash_bucket) * b;
  BVT (clib_bihash_value) * v;
  int i, j, k;
  u64 active_elements = 0;
  u64 active_buckets = 0;
  u64 linear_buckets = 0;
  u64 used_bytes;

  s = format (s, "Hash table %s\n", h->name ? h->name : (u8 *) "(unnamed)");

  for (i = 0; i < h->nbuckets; i++)
    {
      b = &h->buckets[i];
      if (BV (clib_bihash_bucket_is_empty) (b))
	{
	  if (verbose > 1)
	    s = format (s, "[%d]: empty\n", i);
	  continue;
	}

      active_buckets++;

      if (b->linear_search)
	linear_buckets++;

      if (verbose)
	{
	  s = format (s, "[%d]: heap offset %lld, len %d, linear %d\n", i,
		      b->offset, (1 << b->log2_pages), b->linear_search);
	}

      v = BV (clib_bihash_get_value) (h, b->offset);
      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
	    {
	      if (BV (clib_bihash_is_free) (&v->kvp[k]))
		{
		  if (verbose > 1)
		    s = format (s, "    %d: empty\n",
				j * BIHASH_KVP_PER_PAGE + k);
		  continue;
		}
	      if (verbose)
		{
		  if (h->fmt_fn)
		    {
		      s = format (s, "    %d: %U\n",
				  j * BIHASH_KVP_PER_PAGE + k,
				  h->fmt_fn, &(v->kvp[k]));
		    }
		  else
		    {
		      s = format (s, "    %d: %U\n",
				  j * BIHASH_KVP_PER_PAGE + k,
				  BV (format_bihash_kvp), &(v->kvp[k]));
		    }
		}
	      active_elements++;
	    }
	  v++;
	}
    }

  s = format (s, "    %lld active elements %lld active buckets\n",
	      active_elements, active_buckets);
  s = format (s, "    %d free lists\n", vec_len (h->freelists));

  for (i = 0; i < vec_len (h->freelists); i++)
    {
      u32 nfree = 0;
      BVT (clib_bihash_value) * free_elt;
      u64 free_elt_as_u64 = h->freelists[i];

      while (free_elt_as_u64)
	{
	  free_elt = BV (clib_bihash_get_value) (h, free_elt_as_u64);
	  nfree++;
	  free_elt_as_u64 = free_elt->next_free_as_u64;
	}

      if (nfree || verbose)
	s = format (s, "       [len %d] %u free elts\n", 1 << i, nfree);
    }

  s = format (s, "    %lld linear search buckets\n", linear_buckets);
  used_bytes = alloc_arena_next (h);
  s = format (s,
	      "    arena: base %llx, next %llx\n"
	      "           used %lld b (%lld Mbytes) of %lld b (%lld Mbytes)\n",
	      alloc_arena (h), alloc_arena_next (h),
	      used_bytes, used_bytes >> 20,
	      alloc_arena_size (h), alloc_arena_size (h) >> 20);
  return s;
}

void BV (clib_bihash_foreach_key_value_pair)
  (BVT (clib_bihash) * h, void *callback, void *arg)
{
  int i, j, k;
  BVT (clib_bihash_bucket) * b;
  BVT (clib_bihash_value) * v;
  void (*fp) (BVT (clib_bihash_kv) *, void *) = callback;

  for (i = 0; i < h->nbuckets; i++)
    {
      b = &h->buckets[i];
      if (BV (clib_bihash_bucket_is_empty) (b))
	continue;

      v = BV (clib_bihash_get_value) (h, b->offset);
      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
	    {
	      if (BV (clib_bihash_is_free) (&v->kvp[k]))
		continue;

	      (*fp) (&v->kvp[k], arg);
	      /*
	       * In case the callback deletes the last entry in the bucket...
	       */
	      if (BV (clib_bihash_bucket_is_empty) (b))
		goto doublebreak;
	    }
	  v++;
	}
    doublebreak:
      ;
    }
}

/** @endcond */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
