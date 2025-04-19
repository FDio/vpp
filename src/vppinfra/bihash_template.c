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

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif

#ifndef BIIHASH_MIN_ALLOC_LOG2_PAGES
#define BIIHASH_MIN_ALLOC_LOG2_PAGES 10
#endif

#ifndef BIHASH_USE_HEAP
#define BIHASH_USE_HEAP 1
#endif

static inline void *BV (alloc_aligned) (BVT (clib_bihash) * h, uword nbytes)
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

      BVT (clib_bihash_alloc_chunk) * chunk = h->chunks;

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

static void BV (clib_bihash_instantiate) (BVT (clib_bihash) * h)
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
      alloc_arena (h) = clib_mem_vm_reserve (0, h->memory_size,
					     BIHASH_LOG2_HUGEPAGE_SIZE);
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
			(BIHASH_KVP_PER_PAGE *
			 sizeof (BVT (clib_bihash_kv))));
	}
    }
  CLIB_MEMORY_STORE_BARRIER ();
  h->instantiated = 1;
}

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

static
BVT (clib_bihash_value) *
BV (value_alloc) (BVT (clib_bihash) * h, u32 log2_pages)
{
  int i;
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
      working_copy = BV (alloc_aligned)
	(h, sizeof (working_copy[0]) * (1 << b->log2_pages));
      h->working_copy_lengths[thread_index] = b->log2_pages;
      h->working_copies[thread_index] = working_copy;

      BV (clib_bihash_increment_stat) (h, BIHASH_STAT_working_copy_lost,
				       1ULL << b->log2_pages);
    }

  v = BV (clib_bihash_get_value) (h, b->offset);

  clib_memcpy_fast (working_copy, v, sizeof (*v) * (1 << b->log2_pages));
  working_bucket.as_u64 = b->as_u64;
  working_bucket.offset = BV (clib_bihash_get_offset) (h, working_copy);
  CLIB_MEMORY_STORE_BARRIER ();
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

static_always_inline int BV (clib_bihash_add_del_inline_with_hash) (
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

  static const BVT (clib_bihash_bucket) mask = {
    .linear_search = 1,
    .log2_pages = -1
  };

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

      *v->kvp = *add_v;
      tmp_b.as_u64 = 0;		/* clears bucket lock */
      tmp_b.offset = BV (clib_bihash_get_offset) (h, v);
      tmp_b.refcnt = 1;
      CLIB_MEMORY_STORE_BARRIER ();

      b->as_u64 = tmp_b.as_u64;	/* unlocks the bucket */
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
	      clib_memcpy_fast (&(v->kvp[i].value),
				&add_v->value, sizeof (add_v->value));
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
	      clib_memcpy_fast (&(v->kvp[i].value),
				&add_v->value, sizeof (add_v->value));
	      CLIB_MEMORY_STORE_BARRIER ();	/* Make sure the value has settled */
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
		  CLIB_MEMORY_STORE_BARRIER ();
		  BV (clib_bihash_unlock_bucket) (b);
		  BV (clib_bihash_increment_stat) (h, BIHASH_STAT_replace, 1);
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
		  if (BIHASH_KVP_AT_BUCKET_LEVEL && b->refcnt == 1
		      && b->log2_pages > 0)
		    {
		      tmp_b.as_u64 = b->as_u64;
		      b->offset = BV (clib_bihash_get_offset)
			(h, (void *) (b + 1));
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
	      else		/* yes, free it */
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
		  BV (clib_bihash_increment_stat) (h, BIHASH_STAT_del_free,
						   1);
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
	  BV (clib_bihash_increment_stat) (h, BIHASH_STAT_linear, 1);
	}
      BV (clib_bihash_increment_stat) (h, BIHASH_STAT_resplit, 1);
      BV (clib_bihash_increment_stat) (h, BIHASH_STAT_splits,
				       old_log2_pages + 1);
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
#if BIHASH_KVP_AT_BUCKET_LEVEL
  /* Compensate for permanent refcount bump at the bucket level */
  if (new_log2_pages > 0)
#endif
    tmp_b.refcnt = h->saved_bucket.refcnt + 1;
  ASSERT (tmp_b.refcnt > 0);
  tmp_b.lock = 0;
  CLIB_MEMORY_STORE_BARRIER ();
  b->as_u64 = tmp_b.as_u64;

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

static_always_inline int BV (clib_bihash_add_del_inline)
  (BVT (clib_bihash) * h, BVT (clib_bihash_kv) * add_v, int is_add,
   int (*is_stale_cb) (BVT (clib_bihash_kv) *, void *), void *arg)
{
  u64 hash = BV (clib_bihash_hash) (add_v);
  return BV (clib_bihash_add_del_inline_with_hash) (h, add_v, hash, is_add,
						    is_stale_cb, arg, 0, 0);
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
