/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
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

#include <svm/fifo_segment.h>

/**
 * Initialize fifo segment shared header
 */
int
fifo_segment_init (fifo_segment_t * fs)
{
  fifo_segment_header_t *fsh;
  ssvm_shared_header_t *sh;
  void *oldheap;

  sh = fs->ssvm.sh;
  oldheap = ssvm_push_heap (sh);

  fsh = clib_mem_alloc (sizeof (*fsh));
  clib_memset (fsh, 0, sizeof (*fsh));
  fs->h = sh->opaque[0] = fsh;

  ssvm_pop_heap (oldheap);

  sh->ready = 1;
  return (0);
}

/**
 * Create a fifo segment in process-private memory
 */
static int
fifo_segment_create_process_private (fifo_segment_main_t * sm,
				     fifo_segment_create_args_t * a)
{
  u32 pagesize = clib_mem_get_page_size ();
  ssvm_shared_header_t *sh;
  fifo_segment_t *s;
  u32 rnd_size = 0;
  u8 *heap;

  pool_get (sm->segments, s);
  clib_memset (s, 0, sizeof (*s));

  rnd_size = (a->segment_size + (pagesize - 1)) & ~pagesize;

#if USE_DLMALLOC == 0
  heap = mheap_alloc (0, rnd_size);
  if (heap == 0)
    {
      clib_unix_warning ("mheap alloc");
      pool_put (sm->segments, s);
      return -1;
    }
  {
    mheap_t *heap_header;
    heap_header = mheap_header (heap);
    heap_header->flags |= MHEAP_FLAG_THREAD_SAFE;
  }
#else
  heap = create_mspace (rnd_size, 1 /* locked */ );
#endif

  s->ssvm.ssvm_size = rnd_size;
  s->ssvm.i_am_master = 1;
  s->ssvm.my_pid = getpid ();
  s->ssvm.name = format (0, "%s%c", a->segment_name, 0);
  s->ssvm.requested_va = ~0;

  /* Allocate a [sic] shared memory header, in process memory... */
  sh = clib_mem_alloc_aligned (sizeof (*sh), CLIB_CACHE_LINE_BYTES);
  s->ssvm.sh = sh;

  clib_memset (sh, 0, sizeof (*sh));
  sh->heap = heap;

  fifo_segment_init (s);
  vec_add1 (a->new_segment_indices, s - sm->segments);

  return (0);
}

/**
 * Create a fifo segment and initialize as master
 */
int
fifo_segment_create (fifo_segment_main_t * sm, fifo_segment_create_args_t * a)
{
  fifo_segment_t *s;
  int rv;

  if (a->segment_type == SSVM_SEGMENT_PRIVATE)
    return fifo_segment_create_process_private (sm, a);

  /* Allocate a fresh segment */
  pool_get (sm->segments, s);
  clib_memset (s, 0, sizeof (*s));

  s->ssvm.ssvm_size = a->segment_size;
  s->ssvm.i_am_master = 1;
  s->ssvm.my_pid = getpid ();
  s->ssvm.name = format (0, "%s%c", a->segment_name, 0);
  s->ssvm.requested_va = sm->next_baseva;

  if ((rv = ssvm_master_init (&s->ssvm, a->segment_type)))
    {
      pool_put (sm->segments, s);
      return (rv);
    }

  /* Note: requested_va updated due to seg base addr randomization */
  sm->next_baseva = s->ssvm.sh->ssvm_va + a->segment_size;

  fifo_segment_init (s);
  vec_add1 (a->new_segment_indices, s - sm->segments);
  return (0);
}

/**
 * Attach as slave to a fifo segment
 */
int
fifo_segment_attach (fifo_segment_main_t * sm, fifo_segment_create_args_t * a)
{
  fifo_segment_t *s;
  int rv;

  pool_get_zero (sm->segments, s);

  s->ssvm.ssvm_size = a->segment_size;
  s->ssvm.my_pid = getpid ();
  s->ssvm.name = format (0, "%s%c", a->segment_name, 0);
  s->ssvm.requested_va = sm->next_baseva;
  if (a->segment_type == SSVM_SEGMENT_MEMFD)
    s->ssvm.fd = a->memfd_fd;
  else
    s->ssvm.attach_timeout = sm->timeout_in_seconds;

  if ((rv = ssvm_slave_init (&s->ssvm, a->segment_type)))
    {
      _vec_len (s) = vec_len (s) - 1;
      return (rv);
    }

  /* Fish the segment header */
  s->h = s->ssvm.sh->opaque[0];

  vec_add1 (a->new_segment_indices, s - sm->segments);
  return (0);
}

void
fifo_segment_delete (fifo_segment_main_t * sm, fifo_segment_t * s)
{
  ssvm_delete (&s->ssvm);
  clib_memset (s, 0xfe, sizeof (*s));
  pool_put (sm->segments, s);
}

u32
fifo_segment_index (fifo_segment_main_t * sm, fifo_segment_t * s)
{
  return s - sm->segments;
}

void *
svm_fifo_segment_heap (fifo_segment_t * seg)
{
  return seg->ssvm.sh->heap;
}

fifo_segment_t *
fifo_segment_get_segment (fifo_segment_main_t * sm, u32 segment_index)
{
  return pool_elt_at_index (sm->segments, segment_index);
}

void
fifo_segment_info (fifo_segment_t * seg, char **address, size_t * size)
{
  if (ssvm_type (&seg->ssvm) == SSVM_SEGMENT_PRIVATE)
    {
#if USE_DLMALLOC == 0
      mheap_t *heap_header;

      *address = pointer_to_uword (seg->ssvm.sh->heap);
      heap_header = mheap_header (seg->ssvm.sh->heap);
      *size = heap_header->max_size;
#else
      mspace_get_address_and_size (seg->ssvm.sh->heap, address, size);
#endif
    }
  else
    {
      *address = (char *) seg->ssvm.sh->ssvm_va;
      *size = seg->ssvm.ssvm_size;
    }
}

void
fifo_segment_main_init (fifo_segment_main_t * sm, u64 baseva,
			u32 timeout_in_seconds)
{
  sm->next_baseva = baseva;
  sm->timeout_in_seconds = timeout_in_seconds;
}

static void
fifo_init_for_segment (fifo_segment_header_t * fsh, svm_fifo_t * f,
		       u32 size, u32 fl_index)
{
  f->freelist_index = fl_index;
  f->default_chunk.start_byte = 0;
  f->default_chunk.length = size;
  f->default_chunk.next = f->start_chunk = f->end_chunk = &f->default_chunk;
  f->head_chunk = f->tail_chunk = f->ooo_enq = f->ooo_deq = f->start_chunk;
  f->next = fsh->free_fifos[fl_index];
  fsh->free_fifos[fl_index] = f;
}

static inline int
fs_free_list_for_size (u32 size)
{
  return max_log2 (size) - max_log2 (FIFO_SEGMENT_MIN_FIFO_SIZE);
}

static inline int
fs_chunk_size_is_valid (u32 size)
{
  /*
   * 4K minimum. It's not likely that anything good will happen
   * with a smaller FIFO.
   */
  return size >= FIFO_SEGMENT_MIN_FIFO_SIZE
    && size <= FIFO_SEGMENT_MAX_FIFO_SIZE;
}

static void
allocate_new_fifo_batch (fifo_segment_header_t * fsh,
			 u32 data_size_in_bytes, int chunk_size)
{
  u32 size, rounded_data_size;
  int i, fl_index;
  u8 *fifos_mem;
  svm_fifo_t *f;

  rounded_data_size = (1 << (max_log2 (data_size_in_bytes)));
  fl_index = fs_free_list_for_size (data_size_in_bytes);

  /* Calculate space requirement $$$ round-up data_size_in_bytes */
  size = (sizeof (*f) + rounded_data_size) * chunk_size;

  /* Allocate fifo space. May fail. */
  fifos_mem = clib_mem_alloc_aligned_at_offset (size, CLIB_CACHE_LINE_BYTES,
						0 /* align_offset */ ,
						0 /* os_out_of_memory */ );

  /* Out of space.. */
  if (fifos_mem == 0)
    return;

  /* Carve fifo space */
  for (i = 0; i < chunk_size; i++)
    {
      f = (svm_fifo_t *) fifos_mem;
      fifo_init_for_segment (fsh, f, rounded_data_size, fl_index);
      fifos_mem += sizeof (*f) + rounded_data_size;
    }
}

/**
 * Allocate fifo in fifo segment
 */
svm_fifo_t *
fifo_segment_alloc_fifo (fifo_segment_t * fs, u32 data_bytes,
			 fifo_segment_ftype_t ftype)
{
  fifo_segment_header_t *fsh;
  ssvm_shared_header_t *sh;
  svm_fifo_t *f = 0;
  void *oldheap;
  int fl_index;

  if (!fs_chunk_size_is_valid (data_bytes))
    {
      clib_warning ("fifo size out of range %d", data_bytes);
      return 0;
    }

  fl_index = fs_free_list_for_size (data_bytes);

  sh = fs->ssvm.sh;
  ssvm_lock_non_recursive (sh, 1);

  fsh = fs->h;
  vec_validate_init_empty (fsh->free_fifos, fl_index, 0);
  f = fsh->free_fifos[fl_index];

  /* Try to allocate batch of fifos */
  if (PREDICT_FALSE (!f))
    {
      oldheap = ssvm_push_heap (sh);
      allocate_new_fifo_batch (fsh, data_bytes,
			       FIFO_SEGMENT_ALLOC_BATCH_SIZE);
      ssvm_pop_heap (oldheap);
      f = fsh->free_fifos[fl_index];
    }
  if (PREDICT_TRUE (f != 0))
    {
      fsh->free_fifos[fl_index] = f->next;
      /* (re)initialize the fifo, as in svm_fifo_create */
      memset (f, 0, sizeof (*f));
      svm_fifo_init (f, data_bytes);
      goto found;
    }

  /* Failed to allocate batch, try just one fifo. This can also fail,
   * in which case, create another segment */
  oldheap = ssvm_push_heap (sh);
  f = svm_fifo_create (data_bytes);
  ssvm_pop_heap (oldheap);

  if (PREDICT_FALSE (f == 0))
    goto done;

  f->freelist_index = fl_index;

found:
  /* If rx fifo type add to active fifos list. When cleaning up segment,
   * we need a list of active sessions that should be disconnected. Since
   * both rx and tx fifos keep pointers to the session, it's enough to track
   * only one. */
  if (ftype == FIFO_SEGMENT_RX_FIFO)
    {
      if (fsh->fifos)
	{
	  fsh->fifos->prev = f;
	  f->next = fsh->fifos;
	}
      fsh->fifos = f;
      f->flags |= SVM_FIFO_F_LL_TRACKED;
    }
  fsh->n_active_fifos++;

done:
  ssvm_unlock_non_recursive (sh);
  return (f);
}

/**
 * Free fifo allocated in fifo segment
 */
void
fifo_segment_free_fifo (fifo_segment_t * fs, svm_fifo_t * f)
{
  fifo_segment_header_t *fsh;
  ssvm_shared_header_t *sh;
  int fl_index;

  ASSERT (f->refcnt > 0);

  if (--f->refcnt > 0)
    return;

  sh = fs->ssvm.sh;
  fsh = fs->h;
  fl_index = f->freelist_index;

  ASSERT (fl_index < vec_len (fsh->free_fifos));

  ssvm_lock_non_recursive (sh, 2);

  /* Remove from active list. Only rx fifos are tracked */
  if (f->flags & SVM_FIFO_F_LL_TRACKED)
    {
      if (f->prev)
	f->prev->next = f->next;
      else
	fsh->fifos = f->next;
      if (f->next)
	f->next->prev = f->prev;
      f->flags &= ~SVM_FIFO_F_LL_TRACKED;
    }

  /* Add to free list */
  f->next = fsh->free_fifos[fl_index];
  f->prev = 0;
  fsh->free_fifos[fl_index] = f;

  /* If fifo has more chunks, free them */
  if (f->flags & SVM_FIFO_F_MULTI_CHUNK)
    {
      svm_fifo_chunk_t *cur, *next;
      void *oldheap;

      next = f->start_chunk->next;
      while (next != f->start_chunk)
	{
	  cur = next;
	  next = next->next;
	  fl_index = fs_free_list_for_size (cur->length);
	  cur->next = fsh->free_chunks[fl_index];
	  fsh->free_chunks[fl_index] = cur;
	}
      oldheap = ssvm_push_heap (sh);
      svm_fifo_free_chunk_lookup (f);
      ssvm_pop_heap (oldheap);
    }

  /* not allocated on segment heap */
  svm_fifo_free_ooo_data (f);

  if (CLIB_DEBUG)
    {
      f->master_session_index = ~0;
      f->master_thread_index = ~0;
    }

  fsh->n_active_fifos--;
  ssvm_unlock_non_recursive (sh);
}

/**
 * Pre-allocates fifo pairs in fifo segment
 */
void
fifo_segment_preallocate_fifo_pairs (fifo_segment_t * fs,
				     u32 rx_fifo_size, u32 tx_fifo_size,
				     u32 * n_fifo_pairs)
{
  u32 rx_rounded_data_size, tx_rounded_data_size, pair_size;
  u32 rx_fifos_size, tx_fifos_size, pairs_to_allocate;
  ssvm_shared_header_t *sh = fs->ssvm.sh;
  fifo_segment_header_t *fsh = fs->h;
  int i, rx_fl_index, tx_fl_index;
  u8 *rx_fifo_mem, *tx_fifo_mem;
  uword space_available;
  void *oldheap;
  svm_fifo_t *f;

  /* Parameter check */
  if (rx_fifo_size == 0 || tx_fifo_size == 0 || *n_fifo_pairs == 0)
    return;

  if (!fs_chunk_size_is_valid (rx_fifo_size))
    {
      clib_warning ("rx fifo_size out of range %d", rx_fifo_size);
      return;
    }

  if (!fs_chunk_size_is_valid (tx_fifo_size))
    {
      clib_warning ("tx fifo_size out of range %d", tx_fifo_size);
      return;
    }

  rx_rounded_data_size = (1 << (max_log2 (rx_fifo_size)));
  rx_fl_index = fs_free_list_for_size (rx_fifo_size);
  tx_rounded_data_size = (1 << (max_log2 (tx_fifo_size)));
  tx_fl_index = fs_free_list_for_size (tx_fifo_size);

  /* Calculate space requirements */
  pair_size = 2 * sizeof (*f) + rx_rounded_data_size + tx_rounded_data_size;
#if USE_DLMALLOC == 0
  space_available = fs->ssvm.ssvm_size - mheap_bytes (sh->heap);
#else
  space_available = fs->ssvm.ssvm_size - mspace_usable_size (sh->heap);
#endif

  pairs_to_allocate = clib_min (space_available / pair_size, *n_fifo_pairs);
  rx_fifos_size = (sizeof (*f) + rx_rounded_data_size) * pairs_to_allocate;
  tx_fifos_size = (sizeof (*f) + tx_rounded_data_size) * pairs_to_allocate;

  vec_validate_init_empty (fsh->free_fifos,
			   clib_max (rx_fl_index, tx_fl_index), 0);

  oldheap = ssvm_push_heap (sh);

  /* Allocate rx and tx fifo memory. May fail. */
  rx_fifo_mem = clib_mem_alloc_aligned_at_offset (rx_fifos_size,
						  CLIB_CACHE_LINE_BYTES,
						  0 /* align_offset */ ,
						  0 /* os_out_of_memory */ );
  tx_fifo_mem = clib_mem_alloc_aligned_at_offset (tx_fifos_size,
						  CLIB_CACHE_LINE_BYTES,
						  0 /* align_offset */ ,
						  0 /* os_out_of_memory */ );

  /* Make sure it worked. Clean up if it didn't... */
  if (rx_fifo_mem == 0 || tx_fifo_mem == 0)
    {
      rx_fifo_mem ? clib_mem_free (rx_fifo_mem) : clib_mem_free (tx_fifo_mem);
      clib_warning ("fifo preallocation failure: rx size %d tx size %u "
		    "npairs %d", rx_fifo_size, tx_fifo_size, *n_fifo_pairs);
      ssvm_pop_heap (oldheap);
      return;
    }

  /* Carve rx and tx fifo memory */
  for (i = 0; i < pairs_to_allocate; i++)
    {
      f = (svm_fifo_t *) rx_fifo_mem;
      fifo_init_for_segment (fsh, f, rx_rounded_data_size, rx_fl_index);
      rx_fifo_mem += sizeof (*f) + rx_rounded_data_size;

      f = (svm_fifo_t *) tx_fifo_mem;
      fifo_init_for_segment (fsh, f, tx_rounded_data_size, tx_fl_index);
      tx_fifo_mem += sizeof (*f) + tx_rounded_data_size;
    }

  /* Account for the pairs allocated */
  *n_fifo_pairs -= pairs_to_allocate;
  ssvm_pop_heap (oldheap);
}

int
fifo_segment_grow_fifo (fifo_segment_t * fs, svm_fifo_t * f, u32 chunk_size)
{
  ssvm_shared_header_t *sh;
  svm_fifo_chunk_t *c;
  void *oldheap;
  int fl_index;

  if (!fs_chunk_size_is_valid (chunk_size))
    {
      clib_warning ("chunk size out of range %d", chunk_size);
      return 0;
    }

  fl_index = fs_free_list_for_size (chunk_size);

  sh = fs->ssvm.sh;
  ssvm_lock_non_recursive (sh, 1);

  vec_validate_init_empty (fs->h->free_chunks, fl_index, 0);
  c = fs->h->free_chunks[fl_index];

  oldheap = ssvm_push_heap (sh);

  if (!c)
    {
      c = svm_fifo_chunk_alloc (chunk_size);
      if (!c)
	{
	  ssvm_pop_heap (oldheap);
	  return -1;
	}
    }
  else
    {
      fs->h->free_chunks[fl_index] = c->next;
    }

  svm_fifo_add_chunk (f, c);

  ssvm_pop_heap (oldheap);
  ssvm_unlock_non_recursive (sh);
  return 0;
}

/**
 * Get number of active fifos
 */
u32
fifo_segment_num_fifos (fifo_segment_t * fs)
{
  return fs->h->n_active_fifos;
}

u32
fifo_segment_num_free_fifos (fifo_segment_t * fs, u32 fifo_size_in_bytes)
{
  u32 count = 0, rounded_data_size, fl_index;
  fifo_segment_header_t *fsh;
  ssvm_shared_header_t *sh;
  svm_fifo_t *f;
  int i;

  sh = fs->ssvm.sh;
  fsh = (fifo_segment_header_t *) sh->opaque[0];

  /* Count all free fifos? */
  if (fifo_size_in_bytes == ~0)
    {
      for (i = 0; i < vec_len (fsh->free_fifos); i++)
	{
	  f = fsh->free_fifos[i];
	  if (f == 0)
	    continue;

	  while (f)
	    {
	      f = f->next;
	      count++;
	    }
	}
      return count;
    }

  rounded_data_size = (1 << (max_log2 (fifo_size_in_bytes)));
  fl_index = fs_free_list_for_size (rounded_data_size);

  if (fl_index >= vec_len (fsh->free_fifos))
    return 0;

  f = fsh->free_fifos[fl_index];
  if (f == 0)
    return 0;

  while (f)
    {
      f = f->next;
      count++;
    }
  return count;
}

u32
fifo_segment_num_free_chunks (fifo_segment_t * fs, u32 size)
{
  u32 count = 0, rounded_size, fl_index;
  fifo_segment_header_t *fsh;
  svm_fifo_chunk_t *c;
  int i;

  fsh = fs->h;

  /* Count all free chunks? */
  if (size == ~0)
    {
      for (i = 0; i < vec_len (fsh->free_chunks); i++)
	{
	  c = fsh->free_chunks[i];
	  if (c == 0)
	    continue;

	  while (c)
	    {
	      c = c->next;
	      count++;
	    }
	}
      return count;
    }

  rounded_size = (1 << (max_log2 (size)));
  fl_index = fs_free_list_for_size (rounded_size);

  if (fl_index >= vec_len (fsh->free_chunks))
    return 0;

  c = fsh->free_chunks[fl_index];
  if (c == 0)
    return 0;

  while (c)
    {
      c = c->next;
      count++;
    }
  return count;
}

u8
fifo_segment_has_fifos (fifo_segment_t * fs)
{
  return fs->h->fifos != 0;
}

svm_fifo_t *
fifo_segment_get_fifo_list (fifo_segment_t * fs)
{
  return fs->h->fifos;
}

u8 *
format_fifo_segment_type (u8 * s, va_list * args)
{
  fifo_segment_t *sp;
  sp = va_arg (*args, fifo_segment_t *);
  ssvm_segment_type_t st = ssvm_type (&sp->ssvm);

  if (st == SSVM_SEGMENT_PRIVATE)
    s = format (s, "%s", "private-heap");
  else if (st == SSVM_SEGMENT_MEMFD)
    s = format (s, "%s", "memfd");
  else if (st == SSVM_SEGMENT_SHM)
    s = format (s, "%s", "shm");
  else
    s = format (s, "%s", "unknown");
  return s;
}

/**
 * Segment format function
 */
u8 *
format_fifo_segment (u8 * s, va_list * args)
{
  fifo_segment_t *sp = va_arg (*args, fifo_segment_t *);
  int verbose __attribute__ ((unused)) = va_arg (*args, int);
  fifo_segment_header_t *fsh = sp->h;
  u32 count, indent;
  svm_fifo_t *f;
  int i;

  indent = format_get_indent (s) + 2;
#if USE_DLMALLOC == 0
  s = format (s, "%U segment heap: %U\n", format_white_space, indent,
	      format_mheap, svm_fifo_segment_heap (sp), verbose);
  s = format (s, "%U segment has %u active fifos\n",
	      format_white_space, indent, fifo_segment_num_fifos (sp));
#endif

  for (i = 0; i < vec_len (fsh->free_fifos); i++)
    {
      f = fsh->free_fifos[i];
      if (f == 0)
	continue;
      count = 0;
      while (f)
	{
	  f = f->next;
	  count++;
	}

      s = format (s, "%U%-5u Kb: %u free",
		  format_white_space, indent + 2,
		  1 << (i + max_log2 (FIFO_SEGMENT_MIN_FIFO_SIZE) - 10),
		  count);
    }
  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
