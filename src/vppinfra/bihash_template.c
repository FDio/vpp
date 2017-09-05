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

void BV (clib_bihash_init)
  (BVT (clib_bihash) * h, char *name, u32 nbuckets, uword memory_size)
{
  void *oldheap;
  int i;

  nbuckets = 1 << (max_log2 (nbuckets));

  h->name = (u8 *) name;
  h->nbuckets = nbuckets;
  h->log2_nbuckets = max_log2 (nbuckets);
  h->cache_hits = 0;
  h->cache_misses = 0;

  h->mheap = mheap_alloc (0 /* use VM */ , memory_size);

  oldheap = clib_mem_set_heap (h->mheap);
  vec_validate_aligned (h->buckets, nbuckets - 1, CLIB_CACHE_LINE_BYTES);
  h->writer_lock = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
					   CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < nbuckets; i++)
    BV (clib_bihash_reset_cache) (h->buckets + i);

  clib_mem_set_heap (oldheap);
}

void BV (clib_bihash_free) (BVT (clib_bihash) * h)
{
  mheap_free (h->mheap);
  memset (h, 0, sizeof (*h));
}

static
BVT (clib_bihash_value) *
BV (value_alloc) (BVT (clib_bihash) * h, u32 log2_pages)
{
  BVT (clib_bihash_value) * rv = 0;
  void *oldheap;

  ASSERT (h->writer_lock[0]);
  if (log2_pages >= vec_len (h->freelists) || h->freelists[log2_pages] == 0)
    {
      oldheap = clib_mem_set_heap (h->mheap);

      vec_validate (h->freelists, log2_pages);
      rv = clib_mem_alloc_aligned ((sizeof (*rv) * (1 << log2_pages)),
				   CLIB_CACHE_LINE_BYTES);
      clib_mem_set_heap (oldheap);
      goto initialize;
    }
  rv = h->freelists[log2_pages];
  h->freelists[log2_pages] = rv->next_free;

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
  ASSERT (h->writer_lock[0]);

  ASSERT (vec_len (h->freelists) > log2_pages);

  v->next_free = h->freelists[log2_pages];
  h->freelists[log2_pages] = v;
}

static inline void
BV (make_working_copy) (BVT (clib_bihash) * h, BVT (clib_bihash_bucket) * b)
{
  BVT (clib_bihash_value) * v;
  BVT (clib_bihash_bucket) working_bucket __attribute__ ((aligned (8)));
  void *oldheap;
  BVT (clib_bihash_value) * working_copy;
  u32 thread_index = os_get_thread_index ();
  int log2_working_copy_length;

  if (thread_index >= vec_len (h->working_copies))
    {
      oldheap = clib_mem_set_heap (h->mheap);
      vec_validate (h->working_copies, thread_index);
      vec_validate_init_empty (h->working_copy_lengths, thread_index, ~0);
      clib_mem_set_heap (oldheap);
    }

  /*
   * working_copies are per-cpu so that near-simultaneous
   * updates from multiple threads will not result in sporadic, spurious
   * lookup failures.
   */
  working_copy = h->working_copies[thread_index];
  log2_working_copy_length = h->working_copy_lengths[thread_index];

  h->saved_bucket.as_u64 = b->as_u64;
  oldheap = clib_mem_set_heap (h->mheap);

  if (b->log2_pages > log2_working_copy_length)
    {
      if (working_copy)
	clib_mem_free (working_copy);

      working_copy = clib_mem_alloc_aligned
	(sizeof (working_copy[0]) * (1 << b->log2_pages),
	 CLIB_CACHE_LINE_BYTES);
      h->working_copy_lengths[thread_index] = b->log2_pages;
      h->working_copies[thread_index] = working_copy;
    }

  clib_mem_set_heap (oldheap);

  /* Lock the bucket... */
  while (BV (clib_bihash_lock_bucket) (b) == 0)
    ;

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

int BV (clib_bihash_add_del)
  (BVT (clib_bihash) * h, BVT (clib_bihash_kv) * add_v, int is_add)
{
  u32 bucket_index;
  BVT (clib_bihash_bucket) * b, tmp_b;
  BVT (clib_bihash_value) * v, *new_v, *save_new_v, *working_copy;
  int rv = 0;
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

  tmp_b.linear_search = 0;

  while (__sync_lock_test_and_set (h->writer_lock, 1))
    ;

  /* First elt in the bucket? */
  if (b->offset == 0)
    {
      if (is_add == 0)
	{
	  rv = -1;
	  goto unlock;
	}

      v = BV (value_alloc) (h, 0);

      *v->kvp = *add_v;
      tmp_b.as_u64 = 0;
      tmp_b.offset = BV (clib_bihash_get_offset) (h, v);

      b->as_u64 = tmp_b.as_u64;
      goto unlock;
    }

  /* Note: this leaves the cache disabled */
  BV (make_working_copy) (h, b);

  v = BV (clib_bihash_get_value) (h, h->saved_bucket.offset);

  limit = BIHASH_KVP_PER_PAGE;
  v += (b->linear_search == 0) ? hash & ((1 << b->log2_pages) - 1) : 0;
  if (b->linear_search)
    limit <<= b->log2_pages;

  if (is_add)
    {
      /*
       * For obvious (in hindsight) reasons, see if we're supposed to
       * replace an existing key, then look for an empty slot.
       */
      for (i = 0; i < limit; i++)
	{
	  if (!memcmp (&(v->kvp[i]), &add_v->key, sizeof (add_v->key)))
	    {
	      clib_memcpy (&(v->kvp[i]), add_v, sizeof (*add_v));
	      CLIB_MEMORY_BARRIER ();
	      /* Restore the previous (k,v) pairs */
	      b->as_u64 = h->saved_bucket.as_u64;
	      goto unlock;
	    }
	}
      for (i = 0; i < limit; i++)
	{
	  if (BV (clib_bihash_is_free) (&(v->kvp[i])))
	    {
	      clib_memcpy (&(v->kvp[i]), add_v, sizeof (*add_v));
	      CLIB_MEMORY_BARRIER ();
	      b->as_u64 = h->saved_bucket.as_u64;
	      goto unlock;
	    }
	}
      /* no room at the inn... split case... */
    }
  else
    {
      for (i = 0; i < limit; i++)
	{
	  if (!memcmp (&(v->kvp[i]), &add_v->key, sizeof (add_v->key)))
	    {
	      memset (&(v->kvp[i]), 0xff, sizeof (*(add_v)));
	      CLIB_MEMORY_BARRIER ();
	      b->as_u64 = h->saved_bucket.as_u64;
	      goto unlock;
	    }
	}
      rv = -3;
      b->as_u64 = h->saved_bucket.as_u64;
      goto unlock;
    }

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
  /* Keep track of the number of linear-scan buckets */
  if (tmp_b.linear_search ^ mark_bucket_linear)
    h->linear_buckets += (mark_bucket_linear == 1) ? 1 : -1;

  tmp_b.log2_pages = new_log2_pages;
  tmp_b.offset = BV (clib_bihash_get_offset) (h, save_new_v);
  tmp_b.linear_search = mark_bucket_linear;

  CLIB_MEMORY_BARRIER ();
  b->as_u64 = tmp_b.as_u64;
  v = BV (clib_bihash_get_value) (h, h->saved_bucket.offset);
  BV (value_free) (h, v, old_log2_pages);

unlock:
  BV (clib_bihash_reset_cache) (b);
  BV (clib_bihash_unlock_bucket) (b);
  CLIB_MEMORY_BARRIER ();
  h->writer_lock[0] = 0;
  return rv;
}

int BV (clib_bihash_search)
  (BVT (clib_bihash) * h,
   BVT (clib_bihash_kv) * search_key, BVT (clib_bihash_kv) * valuep)
{
  u64 hash;
  u32 bucket_index;
  BVT (clib_bihash_value) * v;
#if BIHASH_KVP_CACHE_SIZE > 0
  BVT (clib_bihash_kv) * kvp;
#endif
  BVT (clib_bihash_bucket) * b;
  int i, limit;

  ASSERT (valuep);

  hash = BV (clib_bihash_hash) (search_key);

  bucket_index = hash & (h->nbuckets - 1);
  b = &h->buckets[bucket_index];

  if (b->offset == 0)
    return -1;

#if BIHASH_KVP_CACHE_SIZE > 0
  /* Check the cache, if currently enabled */
  if (PREDICT_TRUE ((b->cache_lru & (1 << 15)) == 0))
    {
      limit = BIHASH_KVP_CACHE_SIZE;
      kvp = b->cache;
      for (i = 0; i < limit; i++)
	{
	  if (BV (clib_bihash_key_compare) (kvp[i].key, search_key->key))
	    {
	      *valuep = kvp[i];
	      h->cache_hits++;
	      return 0;
	    }
	}
    }
#endif

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

#if BIHASH_KVP_CACHE_SIZE > 0
	  u8 cache_slot;
	  /* Shut off the cache */
	  if (BV (clib_bihash_lock_bucket) (b))
	    {
	      cache_slot = BV (clib_bihash_get_lru) (b);
	      b->cache[cache_slot] = v->kvp[i];
	      BV (clib_bihash_update_lru) (b, cache_slot);

	      /* Reenable the cache */
	      BV (clib_bihash_unlock_bucket) (b);
	      h->cache_misses++;
	    }
#endif
	  return 0;
	}
    }
  return -1;
}

u8 *BV (format_bihash_lru) (u8 * s, va_list * args)
{
#if BIHASH_KVP_SIZE > 0
  int i;
  BVT (clib_bihash_bucket) * b = va_arg (*args, BVT (clib_bihash_bucket) *);
  u16 cache_lru = b->cache_lru;

  s = format (s, "cache %s, order ", cache_lru & (1 << 15) ? "on" : "off");

  for (i = 0; i < BIHASH_KVP_CACHE_SIZE; i++)
    s = format (s, "[%d] ", ((cache_lru >> (3 * i)) & 7));

  return (s);
#else
  return format (s, "cache not configured");
#endif
}

void
BV (clib_bihash_update_lru_not_inline) (BVT (clib_bihash_bucket) * b, u8 slot)
{
#if BIHASH_KVP_SIZE > 0
  BV (clib_bihash_update_lru) (b, slot);
#endif
}

u8 *BV (format_bihash) (u8 * s, va_list * args)
{
  BVT (clib_bihash) * h = va_arg (*args, BVT (clib_bihash) *);
  int verbose = va_arg (*args, int);
  BVT (clib_bihash_bucket) * b;
  BVT (clib_bihash_value) * v;
  int i, j, k;
  u64 active_elements = 0;

  s = format (s, "Hash table %s\n", h->name ? h->name : (u8 *) "(unnamed)");

  for (i = 0; i < h->nbuckets; i++)
    {
      b = &h->buckets[i];
      if (b->offset == 0)
	{
	  if (verbose > 1)
	    s = format (s, "[%d]: empty\n", i);
	  continue;
	}

      if (verbose)
	{
	  s = format (s, "[%d]: heap offset %d, len %d, linear %d\n", i,
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
		  s = format (s, "    %d: %U\n",
			      j * BIHASH_KVP_PER_PAGE + k,
			      BV (format_bihash_kvp), &(v->kvp[k]));
		}
	      active_elements++;
	    }
	  v++;
	}
    }

  s = format (s, "    %lld active elements\n", active_elements);
  s = format (s, "    %d free lists\n", vec_len (h->freelists));
  s = format (s, "    %d linear search buckets\n", h->linear_buckets);
  s = format (s, "    %lld cache hits, %lld cache misses\n",
	      h->cache_hits, h->cache_misses);
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
      if (b->offset == 0)
	continue;

      v = BV (clib_bihash_get_value) (h, b->offset);
      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
	    {
	      if (BV (clib_bihash_is_free) (&v->kvp[k]))
		continue;

	      (*fp) (&v->kvp[k], arg);
	    }
	  v++;
	}
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
