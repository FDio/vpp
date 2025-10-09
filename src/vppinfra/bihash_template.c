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
#include <vppinfra/bihash_template_inlines.h>

void BV (clib_bihash_init2) (BVT (clib_bihash_init2_args) * a)
{
  int i;
  void *oldheap;
  BVT (clib_bihash) * h = a->h;

  a->nbuckets = 1 << (max_log2 (a->nbuckets));

  h->name = (u8 *) a->name;
  h->nbuckets = a->nbuckets;
  h->log2_nbuckets = max_log2 (a->nbuckets);
  h->memory_size = BIHASH_USE_HEAP ? 0 : a->memory_size;
  h->instantiated = 0;
  h->dont_add_to_all_bihash_list = a->dont_add_to_all_bihash_list;
  h->fmt_fn = BV (format_bihash);
  h->kvp_fmt_fn = a->kvp_fmt_fn;

  alloc_arena (h) = 0;

  /*
   * Make sure the requested size is rational. The max table
   * size without playing the alignment card is 64 Gbytes.
   * If someone starts complaining that's not enough, we can shift
   * the offset by CLIB_LOG2_CACHE_LINE_BYTES...
   */
  if (BIHASH_USE_HEAP)
    ASSERT (h->memory_size < (1ULL << BIHASH_BUCKET_OFFSET_BITS));

  /* Add this hash table to the list */
  if (a->dont_add_to_all_bihash_list == 0)
    {
      for (i = 0; i < vec_len (clib_all_bihashes); i++)
	if (clib_all_bihashes[i] == h)
	  goto do_lock;
      oldheap = clib_all_bihash_set_heap ();
      vec_add1 (clib_all_bihashes, (void *) h);
      clib_mem_set_heap (oldheap);
    }

do_lock:
  if (h->alloc_lock)
    clib_mem_free ((void *) h->alloc_lock);

  /*
   * Set up the lock now, so we can use it to make the first add
   * thread-safe
   */
  h->alloc_lock = clib_mem_alloc_aligned (CLIB_CACHE_LINE_BYTES,
					  CLIB_CACHE_LINE_BYTES);
  h->alloc_lock[0] = 0;

#if BIHASH_LAZY_INSTANTIATE
  if (a->instantiate_immediately)
#endif
    BV (clib_bihash_instantiate) (h);
}

void BV (clib_bihash_init)
  (BVT (clib_bihash) * h, char *name, u32 nbuckets, uword memory_size)
{
  BVT (clib_bihash_init2_args) _a, *a = &_a;

  memset (a, 0, sizeof (*a));

  a->h = h;
  a->name = name;
  a->nbuckets = nbuckets;
  a->memory_size = memory_size;

  BV (clib_bihash_init2) (a);
}

#if BIHASH_32_64_SVM
#if !defined (MFD_ALLOW_SEALING)
#define MFD_ALLOW_SEALING 0x0002U
#endif

void BV (clib_bihash_initiator_init_svm)
  (BVT (clib_bihash) * h, char *name, u32 nbuckets, u64 memory_size)
{
  uword bucket_size;
  u8 *mmap_addr;
  vec_header_t *freelist_vh;
  int fd;

  ASSERT (BIHASH_USE_HEAP == 0);

  ASSERT (memory_size < (1ULL << 32));
  /* Set up for memfd sharing */
  if ((fd = clib_mem_vm_create_fd (CLIB_MEM_PAGE_SZ_DEFAULT, name) == -1)
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
  clib_memset_u8 (h->buckets, 0, bucket_size);
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
  h->sh->freelists_as_u64 =
    (u64) BV (clib_bihash_get_offset) (h, freelist_vh->vector_data);
  h->freelists = (void *) (freelist_vh->vector_data);

  h->fmt_fn = BV (format_bihash);
  h->kvp_fmt_fn = NULL;
  h->instantiated = 1;
}

void BV (clib_bihash_responder_init_svm)
  (BVT (clib_bihash) * h, char *name, int fd)
{
  u8 *mmap_addr;
  u64 memory_size;
  BVT (clib_bihash_shared_header) * sh;

  ASSERT (BIHASH_USE_HEAP == 0);

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
  h->fmt_fn = BV (format_bihash);
  h->kvp_fmt_fn = NULL;
}
#endif /* BIHASH_32_64_SVM */

void BV (clib_bihash_set_kvp_format_fn) (BVT (clib_bihash) * h,
					 format_function_t * kvp_fmt_fn)
{
  h->kvp_fmt_fn = kvp_fmt_fn;
}

int BV (clib_bihash_is_initialised) (const BVT (clib_bihash) * h)
{
  return (h->instantiated != 0);
}

void BV (clib_bihash_free) (BVT (clib_bihash) * h)
{
  int i;

  if (PREDICT_FALSE (h->instantiated == 0))
    goto never_initialized;

  h->instantiated = 0;

  if (BIHASH_USE_HEAP)
    {
      BVT (clib_bihash_alloc_chunk) * next, *chunk;
      void *oldheap = clib_mem_set_heap (h->heap);

      chunk = h->chunks;
      while (chunk)
	{
	  next = chunk->next;
	  clib_mem_free (chunk);
	  chunk = next;
	}
      clib_mem_set_heap (oldheap);
    }

  vec_free (h->working_copies);
  vec_free (h->working_copy_lengths);
  clib_mem_free ((void *) h->alloc_lock);
#if BIHASH_32_64_SVM == 0
  vec_free (h->freelists);
#else
  if (h->memfd > 0)
    (void) close (h->memfd);
#endif
  if (BIHASH_USE_HEAP == 0)
    clib_mem_vm_free ((void *) (uword) (alloc_arena (h)),
		      alloc_arena_size (h));
never_initialized:
  if (h->dont_add_to_all_bihash_list)
    {
      clib_memset_u8 (h, 0, sizeof (*h));
      return;
    }
  clib_memset_u8 (h, 0, sizeof (*h));
  for (i = 0; i < vec_len (clib_all_bihashes); i++)
    {
      if ((void *) h == clib_all_bihashes[i])
	{
	  vec_delete (clib_all_bihashes, 1, i);
	  return;
	}
    }
  clib_warning ("Couldn't find hash table %llx on clib_all_bihashes...",
		(u64) (uword) h);
}

int BV (clib_bihash_add_del_with_hash) (BVT (clib_bihash) * h,
					BVT (clib_bihash_kv) * add_v, u64 hash,
					int is_add)
{
  return BV (clib_bihash_add_del_inline_with_hash) (h, add_v, hash, is_add, 0,
						    0, 0, 0);
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

int BV (clib_bihash_add_with_overwrite_cb) (
  BVT (clib_bihash) * h, BVT (clib_bihash_kv) * add_v,
  void (overwrite_cb) (BVT (clib_bihash_kv) *, void *), void *arg)
{
  u64 hash = BV (clib_bihash_hash) (add_v);
  return BV (clib_bihash_add_del_inline_with_hash) (h, add_v, hash, 1, 0, 0,
						    overwrite_cb, arg);
}

int BV (clib_bihash_search)
  (BVT (clib_bihash) * h,
   BVT (clib_bihash_kv) * search_key, BVT (clib_bihash_kv) * valuep)
{
  return BV (clib_bihash_search_inline_2) (h, search_key, valuep);
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

  s = format (s, "Hash table '%s'\n", h->name ? h->name : (u8 *) "(unnamed)");

#if BIHASH_LAZY_INSTANTIATE
  if (PREDICT_FALSE (h->instantiated == 0))
    return format (s, "    empty, uninitialized");
#endif

  for (i = 0; i < h->nbuckets; i++)
    {
      b = BV (clib_bihash_get_bucket) (h, i);
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
	  s = format
	    (s, "[%d]: heap offset %lld, len %d, refcnt %d, linear %d\n", i,
	     b->offset, (1 << b->log2_pages), b->refcnt, b->linear_search);
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
		  if (h->kvp_fmt_fn)
		    {
		      s = format (s, "    %d: %U\n",
				  j * BIHASH_KVP_PER_PAGE + k,
				  h->kvp_fmt_fn, &(v->kvp[k]), verbose);
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
  if (BIHASH_USE_HEAP)
    {
      BVT (clib_bihash_alloc_chunk) * c = h->chunks;
      uword bytes_left = 0, total_size = 0, n_chunks = 0;

      while (c)
	{
	  bytes_left += c->bytes_left;
	  total_size += c->size;
	  n_chunks += 1;
	  c = c->next;
	}
      s = format (s,
		  "    heap: %u chunk(s) allocated\n"
		  "          bytes: used %U, scrap %U\n", n_chunks,
		  format_memory_size, total_size,
		  format_memory_size, bytes_left);
    }
  else
    {
      u64 used_bytes = alloc_arena_next (h);
      s = format (s,
		  "    arena: base %llx, next %llx\n"
		  "           used %lld b (%lld Mbytes) of %lld b (%lld Mbytes)\n",
		  alloc_arena (h), alloc_arena_next (h),
		  used_bytes, used_bytes >> 20,
		  alloc_arena_size (h), alloc_arena_size (h) >> 20);
    }
  return s;
}

void BV (clib_bihash_foreach_key_value_pair)
  (BVT (clib_bihash) * h,
   BV (clib_bihash_foreach_key_value_pair_cb) cb, void *arg)
{
  int i, j, k;
  BVT (clib_bihash_bucket) * b;
  BVT (clib_bihash_value) * v;


#if BIHASH_LAZY_INSTANTIATE
  if (PREDICT_FALSE (h->instantiated == 0))
    return;
#endif

  for (i = 0; i < h->nbuckets; i++)
    {
      b = BV (clib_bihash_get_bucket) (h, i);
      if (BV (clib_bihash_bucket_is_empty) (b))
	continue;

      v = BV (clib_bihash_get_value) (h, b->offset);
      for (j = 0; j < (1 << b->log2_pages); j++)
	{
	  for (k = 0; k < BIHASH_KVP_PER_PAGE; k++)
	    {
	      if (BV (clib_bihash_is_free) (&v->kvp[k]))
		continue;

	      if (BIHASH_WALK_STOP == cb (&v->kvp[k], arg))
		return;
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
