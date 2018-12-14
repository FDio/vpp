/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <svm/svm_fifo_segment.h>

static void
allocate_new_fifo_chunk (svm_fifo_segment_header_t * fsh,
			 u32 data_size_in_bytes, int chunk_size)
{
  int freelist_index;
  u32 size;
  u8 *fifo_space;
  u32 rounded_data_size;
  svm_fifo_t *f;
  int i;

  rounded_data_size = (1 << (max_log2 (data_size_in_bytes)));
  freelist_index = max_log2 (rounded_data_size)
    - max_log2 (FIFO_SEGMENT_MIN_FIFO_SIZE);

  /* Calculate space requirement $$$ round-up data_size_in_bytes */
  size = (sizeof (*f) + rounded_data_size) * chunk_size;

  /* Allocate fifo space. May fail. */
  fifo_space = clib_mem_alloc_aligned_at_offset
    (size, CLIB_CACHE_LINE_BYTES, 0 /* align_offset */ ,
     0 /* os_out_of_memory */ );

  /* Out of space.. */
  if (fifo_space == 0)
    return;

  /* Carve fifo space */
  f = (svm_fifo_t *) fifo_space;
  for (i = 0; i < chunk_size; i++)
    {
      f->freelist_index = freelist_index;
      f->next = fsh->free_fifos[freelist_index];
      fsh->free_fifos[freelist_index] = f;
      fifo_space += sizeof (*f) + rounded_data_size;
      f = (svm_fifo_t *) fifo_space;
    }
}

/**
 * Pre-allocates fifo pairs in fifo segment
 *
 * The number of fifos pre-allocated is the minimum of the requested number
 * of pairs and the maximum number that fit within the segment. If the maximum
 * is hit, the number of fifo pairs requested is updated by subtracting the
 * number of fifos that have been successfully allocated.
 */
void
svm_fifo_segment_preallocate_fifo_pairs (svm_fifo_segment_private_t * s,
					 u32 rx_fifo_size, u32 tx_fifo_size,
					 u32 * n_fifo_pairs)
{
  u32 rx_rounded_data_size, tx_rounded_data_size, pair_size;
  u32 rx_fifos_size, tx_fifos_size, pairs_to_allocate;
  int rx_freelist_index, tx_freelist_index;
  ssvm_shared_header_t *sh = s->ssvm.sh;
  svm_fifo_segment_header_t *fsh = s->h;
  u8 *rx_fifo_space, *tx_fifo_space;
  uword space_available;
  void *oldheap;
  svm_fifo_t *f;
  int i;

  /* Parameter check */
  if (rx_fifo_size == 0 || tx_fifo_size == 0 || *n_fifo_pairs == 0)
    return;

  if (rx_fifo_size < FIFO_SEGMENT_MIN_FIFO_SIZE ||
      rx_fifo_size > FIFO_SEGMENT_MAX_FIFO_SIZE)
    {
      clib_warning ("rx fifo_size out of range %d", rx_fifo_size);
      return;
    }

  if (tx_fifo_size < FIFO_SEGMENT_MIN_FIFO_SIZE ||
      tx_fifo_size > FIFO_SEGMENT_MAX_FIFO_SIZE)
    {
      clib_warning ("tx fifo_size out of range %d", rx_fifo_size);
      return;
    }

  rx_rounded_data_size = (1 << (max_log2 (rx_fifo_size)));
  rx_freelist_index = max_log2 (rx_fifo_size)
    - max_log2 (FIFO_SEGMENT_MIN_FIFO_SIZE);
  tx_rounded_data_size = (1 << (max_log2 (tx_fifo_size)));
  tx_freelist_index = max_log2 (tx_fifo_size)
    - max_log2 (FIFO_SEGMENT_MIN_FIFO_SIZE);

  /* Calculate space requirements */
  pair_size = 2 * sizeof (*f) + rx_rounded_data_size + tx_rounded_data_size;
#if USE_DLMALLOC == 0
  space_available = s->ssvm.ssvm_size - mheap_bytes (sh->heap);
#else
  space_available = s->ssvm.ssvm_size - mspace_usable_size (sh->heap);
#endif

  pairs_to_allocate = clib_min (space_available / pair_size, *n_fifo_pairs);
  rx_fifos_size = (sizeof (*f) + rx_rounded_data_size) * pairs_to_allocate;
  tx_fifos_size = (sizeof (*f) + tx_rounded_data_size) * pairs_to_allocate;

  vec_validate_init_empty (fsh->free_fifos,
			   clib_max (rx_freelist_index, tx_freelist_index),
			   0);

  oldheap = ssvm_push_heap (sh);
  /* Allocate rx fifo space. May fail. */
  rx_fifo_space = clib_mem_alloc_aligned_at_offset
    (rx_fifos_size, CLIB_CACHE_LINE_BYTES, 0 /* align_offset */ ,
     0 /* os_out_of_memory */ );

  /* Same for TX */
  tx_fifo_space = clib_mem_alloc_aligned_at_offset
    (tx_fifos_size, CLIB_CACHE_LINE_BYTES, 0 /* align_offset */ ,
     0 /* os_out_of_memory */ );

  /* Make sure it worked. Clean up if it didn't... */
  if (rx_fifo_space == 0 || tx_fifo_space == 0)
    {
      if (rx_fifo_space)
	clib_mem_free (rx_fifo_space);
      else
	clib_warning ("rx fifo preallocation failure: size %d npairs %d",
		      rx_fifo_size, *n_fifo_pairs);

      if (tx_fifo_space)
	clib_mem_free (tx_fifo_space);
      else
	clib_warning ("tx fifo preallocation failure: size %d nfifos %d",
		      tx_fifo_size, *n_fifo_pairs);
      ssvm_pop_heap (oldheap);
      return;
    }

  /* Carve rx fifo space */
  f = (svm_fifo_t *) rx_fifo_space;
  for (i = 0; i < pairs_to_allocate; i++)
    {
      f->freelist_index = rx_freelist_index;
      f->next = fsh->free_fifos[rx_freelist_index];
      fsh->free_fifos[rx_freelist_index] = f;
      rx_fifo_space += sizeof (*f) + rx_rounded_data_size;
      f = (svm_fifo_t *) rx_fifo_space;
    }
  /* Carve tx fifo space */
  f = (svm_fifo_t *) tx_fifo_space;
  for (i = 0; i < pairs_to_allocate; i++)
    {
      f->freelist_index = tx_freelist_index;
      f->next = fsh->free_fifos[tx_freelist_index];
      fsh->free_fifos[tx_freelist_index] = f;
      tx_fifo_space += sizeof (*f) + tx_rounded_data_size;
      f = (svm_fifo_t *) tx_fifo_space;
    }

  /* Account for the pairs allocated */
  *n_fifo_pairs -= pairs_to_allocate;
  ssvm_pop_heap (oldheap);
}

/**
 * Initialize svm fifo segment shared header
 */
int
svm_fifo_segment_init (svm_fifo_segment_private_t * s)
{
  svm_fifo_segment_header_t *fsh;
  ssvm_shared_header_t *sh;
  void *oldheap;

  sh = s->ssvm.sh;
  oldheap = ssvm_push_heap (sh);

  fsh = clib_mem_alloc (sizeof (*fsh));
  clib_memset (fsh, 0, sizeof (*fsh));
  s->h = sh->opaque[0] = fsh;

  ssvm_pop_heap (oldheap);

  sh->ready = 1;
  return (0);
}

/**
 * Create an svm fifo segment and initialize as master
 */
int
svm_fifo_segment_create (svm_fifo_segment_main_t * sm,
			 svm_fifo_segment_create_args_t * a)
{
  svm_fifo_segment_private_t *s;
  int rv;

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

  svm_fifo_segment_init (s);
  vec_add1 (a->new_segment_indices, s - sm->segments);
  return (0);
}

/**
 * Create an svm fifo segment in process-private memory
 */
int
svm_fifo_segment_create_process_private (svm_fifo_segment_main_t * sm,
					 svm_fifo_segment_create_args_t * a)
{
  svm_fifo_segment_private_t *s;
  ssvm_shared_header_t *sh;
  u32 rnd_size = 0;
  u8 *heap;
  u32 pagesize = clib_mem_get_page_size ();

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

  svm_fifo_segment_init (s);
  vec_add1 (a->new_segment_indices, s - sm->segments);

  return (0);
}

/**
 * Attach as slave to an svm fifo segment
 */
int
svm_fifo_segment_attach (svm_fifo_segment_main_t * sm,
			 svm_fifo_segment_create_args_t * a)
{
  svm_fifo_segment_private_t *s;
  int rv;

  /* Allocate a fresh segment */
  pool_get (sm->segments, s);
  clib_memset (s, 0, sizeof (*s));

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
svm_fifo_segment_delete (svm_fifo_segment_main_t * sm,
			 svm_fifo_segment_private_t * s)
{
  ssvm_delete (&s->ssvm);
  clib_memset (s, 0xfe, sizeof (*s));
  pool_put (sm->segments, s);
}

/**
 * Allocate fifo in svm segment
 */
svm_fifo_t *
svm_fifo_segment_alloc_fifo (svm_fifo_segment_private_t * fs,
			     u32 data_size_in_bytes,
			     svm_fifo_segment_freelist_t list_index)
{
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;
  svm_fifo_t *f = 0;
  void *oldheap;
  int freelist_index;

  /*
   * 4K minimum. It's not likely that anything good will happen
   * with a smaller FIFO.
   */
  if (data_size_in_bytes < FIFO_SEGMENT_MIN_FIFO_SIZE ||
      data_size_in_bytes > FIFO_SEGMENT_MAX_FIFO_SIZE)
    {
      clib_warning ("fifo size out of range %d", data_size_in_bytes);
      return 0;
    }

  freelist_index = max_log2 (data_size_in_bytes)
    - max_log2 (FIFO_SEGMENT_MIN_FIFO_SIZE);

  sh = fs->ssvm.sh;
  ssvm_lock_non_recursive (sh, 1);
  fsh = (svm_fifo_segment_header_t *) sh->opaque[0];

  switch (list_index)
    {
    case FIFO_SEGMENT_RX_FREELIST:
    case FIFO_SEGMENT_TX_FREELIST:
      vec_validate_init_empty (fsh->free_fifos, freelist_index, 0);
      f = fsh->free_fifos[freelist_index];
      if (PREDICT_FALSE (!f))
	{
	  /* Preallocated and no fifo left. Don't even try */
	  if (fsh->flags & FIFO_SEGMENT_F_IS_PREALLOCATED)
	    goto done;

	  oldheap = ssvm_push_heap (sh);
	  allocate_new_fifo_chunk (fsh, data_size_in_bytes,
				   FIFO_SEGMENT_ALLOC_CHUNK_SIZE);
	  ssvm_pop_heap (oldheap);
	  f = fsh->free_fifos[freelist_index];
	}
      if (PREDICT_TRUE (f != 0))
	{
	  fsh->free_fifos[freelist_index] = f->next;
	  /* (re)initialize the fifo, as in svm_fifo_create */
	  clib_memset (f, 0, sizeof (*f));
	  f->nitems = data_size_in_bytes;
	  f->ooos_list_head = OOO_SEGMENT_INVALID_INDEX;
	  f->ct_session_index = SVM_FIFO_INVALID_SESSION_INDEX;
	  f->refcnt = 1;
	  f->freelist_index = freelist_index;
	  goto found;
	}
      break;
    case FIFO_SEGMENT_FREELIST_NONE:
      break;

    default:
      clib_warning ("ignore bogus freelist %d", list_index);
      break;
    }

  /* Catch all that allocates just one fifo. Note: this can fail,
   * in which case: create another segment */
  oldheap = ssvm_push_heap (sh);
  f = svm_fifo_create (data_size_in_bytes);
  ssvm_pop_heap (oldheap);
  if (PREDICT_FALSE (f == 0))
    goto done;
  f->freelist_index = freelist_index;

found:
  /* If rx_freelist add to active fifos list. When cleaning up segment,
   * we need a list of active sessions that should be disconnected. Since
   * both rx and tx fifos keep pointers to the session, it's enough to track
   * only one. */
  if (list_index == FIFO_SEGMENT_RX_FREELIST)
    {
      if (fsh->fifos)
	{
	  fsh->fifos->prev = f;
	  f->next = fsh->fifos;
	}
      fsh->fifos = f;
    }
  fsh->n_active_fifos++;

done:
  ssvm_unlock_non_recursive (sh);
  return (f);
}

void
svm_fifo_segment_free_fifo (svm_fifo_segment_private_t * s, svm_fifo_t * f,
			    svm_fifo_segment_freelist_t list_index)
{
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;
  void *oldheap;
  int freelist_index;

  ASSERT (f->refcnt > 0);

  if (--f->refcnt > 0)
    return;

  sh = s->ssvm.sh;
  fsh = (svm_fifo_segment_header_t *) sh->opaque[0];

  freelist_index = f->freelist_index;

  ASSERT (freelist_index < vec_len (fsh->free_fifos));

  ssvm_lock_non_recursive (sh, 2);
  oldheap = ssvm_push_heap (sh);

  switch (list_index)
    {
    case FIFO_SEGMENT_RX_FREELIST:
      /* Remove from active list */
      if (f->prev)
	f->prev->next = f->next;
      else
	fsh->fifos = f->next;
      if (f->next)
	f->next->prev = f->prev;
      /* Fall through: we add only rx fifos to active pool */
    case FIFO_SEGMENT_TX_FREELIST:
      /* Add to free list */
      f->next = fsh->free_fifos[freelist_index];
      f->prev = 0;
      fsh->free_fifos[freelist_index] = f;
      break;
    case FIFO_SEGMENT_FREELIST_NONE:
      break;

    default:
      clib_warning ("ignore bogus freelist %d", list_index);
      break;
    }

  if (CLIB_DEBUG)
    {
      f->master_session_index = ~0;
      f->master_thread_index = ~0;
    }

  fsh->n_active_fifos--;
  ssvm_pop_heap (oldheap);
  ssvm_unlock_non_recursive (sh);
}

void
svm_fifo_segment_main_init (svm_fifo_segment_main_t * sm, u64 baseva,
			    u32 timeout_in_seconds)
{
  sm->next_baseva = baseva;
  sm->timeout_in_seconds = timeout_in_seconds;
}

u32
svm_fifo_segment_index (svm_fifo_segment_main_t * sm,
			svm_fifo_segment_private_t * s)
{
  return s - sm->segments;
}

/**
 * Retrieve svm segments pool. Used only for debug purposes.
 */
svm_fifo_segment_private_t *
svm_fifo_segment_segments_pool (svm_fifo_segment_main_t * sm)
{
  return sm->segments;
}

/**
 * Get number of active fifos
 */
u32
svm_fifo_segment_num_fifos (svm_fifo_segment_private_t * fifo_segment)
{
  return fifo_segment->h->n_active_fifos;
}

u32
svm_fifo_segment_num_free_fifos (svm_fifo_segment_private_t * fifo_segment,
				 u32 fifo_size_in_bytes)
{
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;
  svm_fifo_t *f;
  int i;
  u32 count = 0, rounded_data_size, freelist_index;

  sh = fifo_segment->ssvm.sh;
  fsh = (svm_fifo_segment_header_t *) sh->opaque[0];

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
  freelist_index = max_log2 (rounded_data_size)
    - max_log2 (FIFO_SEGMENT_MIN_FIFO_SIZE);

  if (freelist_index >= vec_len (fsh->free_fifos))
    return 0;

  f = fsh->free_fifos[freelist_index];
  if (f == 0)
    return 0;

  while (f)
    {
      f = f->next;
      count++;
    }
  return count;
}

void
svm_fifo_segment_info (svm_fifo_segment_private_t * seg, char **address,
		       size_t * size)
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

void *
svm_fifo_segment_heap (svm_fifo_segment_private_t * seg)
{
  return seg->ssvm.sh->heap;
}

u8 *
format_svm_fifo_segment_type (u8 * s, va_list * args)
{
  svm_fifo_segment_private_t *sp;
  sp = va_arg (*args, svm_fifo_segment_private_t *);
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
format_svm_fifo_segment (u8 * s, va_list * args)
{
  svm_fifo_segment_private_t *sp
    = va_arg (*args, svm_fifo_segment_private_t *);
  int verbose __attribute__ ((unused)) = va_arg (*args, int);
  svm_fifo_segment_header_t *fsh = sp->h;
  u32 count, indent;
  svm_fifo_t *f;
  int i;

  indent = format_get_indent (s) + 2;
#if USE_DLMALLOC == 0
  s = format (s, "%U segment heap: %U\n", format_white_space, indent,
	      format_mheap, svm_fifo_segment_heap (sp), verbose);
  s = format (s, "%U segment has %u active fifos\n",
	      format_white_space, indent, svm_fifo_segment_num_fifos (sp));
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
