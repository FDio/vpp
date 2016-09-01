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

  nbuckets = 1 << (max_log2 (nbuckets));

  h->name = (u8 *) name;
  h->nbuckets = nbuckets;
  h->log2_nbuckets = max_log2 (nbuckets);

  h->mheap = mheap_alloc (0 /* use VM */ , memory_size);

  oldheap = clib_mem_set_heap (h->mheap);
  vec_validate_aligned (h->buckets, nbuckets - 1, CLIB_CACHE_LINE_BYTES);
  h->writer_lock = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
					   CLIB_CACHE_LINE_BYTES);

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
      vec_validate_aligned (rv, (1 << log2_pages) - 1, CLIB_CACHE_LINE_BYTES);
      clib_mem_set_heap (oldheap);
      goto initialize;
    }
  rv = h->freelists[log2_pages];
  h->freelists[log2_pages] = rv->next_free;

initialize:
  ASSERT (rv);
  ASSERT (vec_len (rv) == (1 << log2_pages));
  /*
   * Latest gcc complains that the length arg is zero
   * if we replace (1<<log2_pages) with vec_len(rv).
   * No clue.
   */
  memset (rv, 0xff, sizeof (*rv) * (1 << log2_pages));
  return rv;
}

static void
BV (value_free) (BVT (clib_bihash) * h, BVT (clib_bihash_value) * v)
{
  u32 log2_pages;

  ASSERT (h->writer_lock[0]);

  log2_pages = min_log2 (vec_len (v));

  ASSERT (vec_len (h->freelists) > log2_pages);

  v->next_free = h->freelists[log2_pages];
  h->freelists[log2_pages] = v;
}

static inline void
BV (make_working_copy) (BVT (clib_bihash) * h, clib_bihash_bucket_t * b)
{
  BVT (clib_bihash_value) * v;
  clib_bihash_bucket_t working_bucket __attribute__ ((aligned (8)));
  void *oldheap;
  BVT (clib_bihash_value) * working_copy;
  u32 cpu_number = os_get_cpu_number ();

  if (cpu_number >= vec_len (h->working_copies))
    {
      oldheap = clib_mem_set_heap (h->mheap);
      vec_validate (h->working_copies, cpu_number);
      clib_mem_set_heap (oldheap);
    }

  /*
   * working_copies are per-cpu so that near-simultaneous
   * updates from multiple threads will not result in sporadic, spurious
   * lookup failures.
   */
  working_copy = h->working_copies[cpu_number];

  h->saved_bucket.as_u64 = b->as_u64;
  oldheap = clib_mem_set_heap (h->mheap);

  if ((1 << b->log2_pages) > vec_len (working_copy))
    {
      vec_validate_aligned (working_copy, (1 << b->log2_pages) - 1,
			    sizeof (u64));
      h->working_copies[cpu_number] = working_copy;
    }

  _vec_len (working_copy) = 1 << b->log2_pages;
  clib_mem_set_heap (oldheap);

  v = BV (clib_bihash_get_value) (h, b->offset);

  clib_memcpy (working_copy, v, sizeof (*v) * (1 << b->log2_pages));
  working_bucket.as_u64 = b->as_u64;
  working_bucket.offset = BV (clib_bihash_get_offset) (h, working_copy);
  CLIB_MEMORY_BARRIER ();
  b->as_u64 = working_bucket.as_u64;
  h->working_copies[cpu_number] = working_copy;
}

static
BVT (clib_bihash_value) *
BV (split_and_rehash)
  (BVT (clib_bihash) * h,
   BVT (clib_bihash_value) * old_values, u32 new_log2_pages)
{
  BVT (clib_bihash_value) * new_values, *v, *new_v;
  int i, j, k;

  new_values = BV (value_alloc) (h, new_log2_pages);

  v = old_values;
  for (i = 0; i < vec_len (old_values); i++)
    {
      u64 new_hash;

      for (j = 0; j < BIHASH_KVP_PER_PAGE; j++)
	{
	  if (BV (clib_bihash_is_free) (&(v->kvp[j])) == 0)
	    {
	      new_hash = BV (clib_bihash_hash) (&(v->kvp[j]));
	      new_hash >>= h->log2_nbuckets;
	      new_hash &= (1 << new_log2_pages) - 1;

	      new_v = &new_values[new_hash];

	      for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
		{
		  if (BV (clib_bihash_is_free) (&(new_v->kvp[k])))
		    {
		      clib_memcpy (&(new_v->kvp[k]), &(v->kvp[j]),
				   sizeof (new_v->kvp[k]));
		      goto doublebreak;
		    }
		}
	      /* Crap. Tell caller to try again */
	      BV (value_free) (h, new_values);
	      return 0;
	    }
	doublebreak:
	  ;
	}
      v++;
    }
  return new_values;
}

int BV (clib_bihash_add_del)
  (BVT (clib_bihash) * h, BVT (clib_bihash_kv) * add_v, int is_add)
{
  u32 bucket_index;
  clib_bihash_bucket_t *b, tmp_b;
  BVT (clib_bihash_value) * v, *new_v, *save_new_v, *working_copy;
  u32 value_index;
  int rv = 0;
  int i;
  u64 hash, new_hash;
  u32 new_log2_pages;
  u32 cpu_number = os_get_cpu_number ();

  hash = BV (clib_bihash_hash) (add_v);

  bucket_index = hash & (h->nbuckets - 1);
  b = &h->buckets[bucket_index];

  hash >>= h->log2_nbuckets;

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

  BV (make_working_copy) (h, b);

  v = BV (clib_bihash_get_value) (h, h->saved_bucket.offset);
  value_index = hash & ((1 << h->saved_bucket.log2_pages) - 1);
  v += value_index;

  if (is_add)
    {
      /*
       * For obvious (in hindsight) reasons, see if we're supposed to
       * replace an existing key, then look for an empty slot.
       */
      for (i = 0; i < BIHASH_KVP_PER_PAGE; i++)
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
      for (i = 0; i < BIHASH_KVP_PER_PAGE; i++)
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
      for (i = 0; i < BIHASH_KVP_PER_PAGE; i++)
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

  new_log2_pages = h->saved_bucket.log2_pages + 1;

expand_again:
  working_copy = h->working_copies[cpu_number];
  new_v = BV (split_and_rehash) (h, working_copy, new_log2_pages);
  if (new_v == 0)
    {
      new_log2_pages++;
      goto expand_again;
    }

  /* Try to add the new entry */
  save_new_v = new_v;
  new_hash = BV (clib_bihash_hash) (add_v);
  new_hash >>= h->log2_nbuckets;
  new_hash &= (1 << min_log2 (vec_len (new_v))) - 1;
  new_v += new_hash;

  for (i = 0; i < BIHASH_KVP_PER_PAGE; i++)
    {
      if (BV (clib_bihash_is_free) (&(new_v->kvp[i])))
	{
	  clib_memcpy (&(new_v->kvp[i]), add_v, sizeof (*add_v));
	  goto expand_ok;
	}
    }
  /* Crap. Try again */
  new_log2_pages++;
  BV (value_free) (h, save_new_v);
  goto expand_again;

expand_ok:
  tmp_b.log2_pages = min_log2 (vec_len (save_new_v));
  tmp_b.offset = BV (clib_bihash_get_offset) (h, save_new_v);
  CLIB_MEMORY_BARRIER ();
  b->as_u64 = tmp_b.as_u64;
  v = BV (clib_bihash_get_value) (h, h->saved_bucket.offset);
  BV (value_free) (h, v);

unlock:
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
  uword value_index;
  BVT (clib_bihash_value) * v;
  clib_bihash_bucket_t *b;
  int i;

  ASSERT (valuep);

  hash = BV (clib_bihash_hash) (search_key);

  bucket_index = hash & (h->nbuckets - 1);
  b = &h->buckets[bucket_index];

  if (b->offset == 0)
    return -1;

  hash >>= h->log2_nbuckets;

  v = BV (clib_bihash_get_value) (h, b->offset);
  value_index = hash & ((1 << b->log2_pages) - 1);
  v += value_index;

  for (i = 0; i < BIHASH_KVP_PER_PAGE; i++)
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
  clib_bihash_bucket_t *b;
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
	  s = format (s, "[%d]: heap offset %d, len %d\n", i,
		      b->offset, (1 << b->log2_pages));
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

  return s;
}

void BV (clib_bihash_foreach_key_value_pair)
  (BVT (clib_bihash) * h, void *callback, void *arg)
{
  int i, j, k;
  clib_bihash_bucket_t *b;
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
