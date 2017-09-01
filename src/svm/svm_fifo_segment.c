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

svm_fifo_segment_main_t svm_fifo_segment_main;

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

static void
preallocate_fifo_pairs (svm_fifo_segment_header_t * fsh,
			svm_fifo_segment_create_args_t * a)
{
  u32 rx_fifo_size, tx_fifo_size;
  u32 rx_rounded_data_size, tx_rounded_data_size;
  svm_fifo_t *f;
  u8 *rx_fifo_space, *tx_fifo_space;
  int rx_freelist_index, tx_freelist_index;
  int i;

  /* Parameter check */
  if (a->rx_fifo_size == 0 || a->tx_fifo_size == 0
      || a->preallocated_fifo_pairs == 0)
    return;

  if (a->rx_fifo_size < FIFO_SEGMENT_MIN_FIFO_SIZE ||
      a->rx_fifo_size > FIFO_SEGMENT_MAX_FIFO_SIZE)
    {
      clib_warning ("rx fifo_size out of range %d", a->rx_fifo_size);
      return;
    }

  if (a->tx_fifo_size < FIFO_SEGMENT_MIN_FIFO_SIZE ||
      a->tx_fifo_size > FIFO_SEGMENT_MAX_FIFO_SIZE)
    {
      clib_warning ("tx fifo_size out of range %d", a->rx_fifo_size);
      return;
    }

  rx_rounded_data_size = (1 << (max_log2 (a->rx_fifo_size)));

  rx_freelist_index = max_log2 (a->rx_fifo_size)
    - max_log2 (FIFO_SEGMENT_MIN_FIFO_SIZE);

  tx_rounded_data_size = (1 << (max_log2 (a->rx_fifo_size)));

  tx_freelist_index = max_log2 (a->tx_fifo_size)
    - max_log2 (FIFO_SEGMENT_MIN_FIFO_SIZE);

  /* Calculate space requirements */
  rx_fifo_size = (sizeof (*f) + rx_rounded_data_size)
    * a->preallocated_fifo_pairs;
  tx_fifo_size = (sizeof (*f) + tx_rounded_data_size)
    * a->preallocated_fifo_pairs;

  vec_validate_init_empty (fsh->free_fifos,
			   clib_max (rx_freelist_index, tx_freelist_index),
			   0);
  if (0)
    clib_warning ("rx_fifo_size %u (%d mb), tx_fifo_size %u (%d mb)",
		  rx_fifo_size, rx_fifo_size >> 20,
		  tx_fifo_size, tx_fifo_size >> 20);

  /* Allocate rx fifo space. May fail. */
  rx_fifo_space = clib_mem_alloc_aligned_at_offset
    (rx_fifo_size, CLIB_CACHE_LINE_BYTES, 0 /* align_offset */ ,
     0 /* os_out_of_memory */ );

  /* Same for TX */
  tx_fifo_space = clib_mem_alloc_aligned_at_offset
    (tx_fifo_size, CLIB_CACHE_LINE_BYTES, 0 /* align_offset */ ,
     0 /* os_out_of_memory */ );

  /* Make sure it worked. Clean up if it didn't... */
  if (rx_fifo_space == 0 || tx_fifo_space == 0)
    {
      if (rx_fifo_space)
	clib_mem_free (rx_fifo_space);
      else
	clib_warning ("rx fifo preallocation failure: size %d npairs %d",
		      a->rx_fifo_size, a->preallocated_fifo_pairs);

      if (tx_fifo_space)
	clib_mem_free (tx_fifo_space);
      else
	clib_warning ("tx fifo preallocation failure: size %d nfifos %d",
		      a->tx_fifo_size, a->preallocated_fifo_pairs);
      return;
    }

  /* Carve rx fifo space */
  f = (svm_fifo_t *) rx_fifo_space;
  for (i = 0; i < a->preallocated_fifo_pairs; i++)
    {
      f->freelist_index = rx_freelist_index;
      f->next = fsh->free_fifos[rx_freelist_index];
      fsh->free_fifos[rx_freelist_index] = f;
      rx_fifo_space += sizeof (*f) + rx_rounded_data_size;
      f = (svm_fifo_t *) rx_fifo_space;
    }
  /* Carve tx fifo space */
  f = (svm_fifo_t *) tx_fifo_space;
  for (i = 0; i < a->preallocated_fifo_pairs; i++)
    {
      f->freelist_index = tx_freelist_index;
      f->next = fsh->free_fifos[tx_freelist_index];
      fsh->free_fifos[tx_freelist_index] = f;
      tx_fifo_space += sizeof (*f) + tx_rounded_data_size;
      f = (svm_fifo_t *) tx_fifo_space;
    }
}

/** (master) create an svm fifo segment */
int
svm_fifo_segment_create (svm_fifo_segment_create_args_t * a)
{
  int rv;
  svm_fifo_segment_private_t *s;
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;
  void *oldheap;

  /* Allocate a fresh segment */
  pool_get (sm->segments, s);
  memset (s, 0, sizeof (*s));

  s->ssvm.ssvm_size = a->segment_size;
  s->ssvm.i_am_master = 1;
  s->ssvm.my_pid = getpid ();
  s->ssvm.name = format (0, "%s%c", a->segment_name, 0);
  s->ssvm.requested_va = sm->next_baseva;

  rv = ssvm_master_init (&s->ssvm, s - sm->segments);

  if (rv)
    {
      _vec_len (s) = vec_len (s) - 1;
      return (rv);
    }

  /* Note: requested_va updated due to seg base addr randomization */
  sm->next_baseva = s->ssvm.requested_va + a->segment_size;

  sh = s->ssvm.sh;
  oldheap = ssvm_push_heap (sh);

  /* Set up svm_fifo_segment shared header */
  fsh = clib_mem_alloc (sizeof (*fsh));
  memset (fsh, 0, sizeof (*fsh));
  sh->opaque[0] = fsh;
  s->h = fsh;
  fsh->segment_name = format (0, "%s%c", a->segment_name, 0);
  preallocate_fifo_pairs (fsh, a);

  ssvm_pop_heap (oldheap);

  sh->ready = 1;
  vec_add1 (a->new_segment_indices, s - sm->segments);
  return (0);
}

/** Create an svm fifo segment in process-private memory */
int
svm_fifo_segment_create_process_private (svm_fifo_segment_create_args_t * a)
{
  svm_fifo_segment_private_t *s;
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;
  void *oldheap;
  u8 **heaps = 0;
  mheap_t *heap_header;
  int segment_count = 1;
  u32 rnd_size = 0;
  int i;

  if (a->private_segment_count && a->private_segment_size)
    {
      u8 *heap;
      u32 pagesize = clib_mem_get_page_size ();
      rnd_size = (a->private_segment_size + (pagesize - 1)) & ~pagesize;

      for (i = 0; i < a->private_segment_count; i++)
	{
	  heap = mheap_alloc (0, rnd_size);
	  if (heap == 0)
	    {
	      clib_unix_warning ("mheap alloc");
	      return -1;
	    }
	  heap_header = mheap_header (heap);
	  heap_header->flags |= MHEAP_FLAG_THREAD_SAFE;
	  vec_add1 (heaps, heap);
	}
      segment_count = a->private_segment_count;
    }

  /* Spread preallocated fifo pairs across segments */
  a->preallocated_fifo_pairs =
    (a->preallocated_fifo_pairs + segment_count - 1) / segment_count;

  /* Allocate segments */
  for (i = 0; i < segment_count; i++)
    {
      pool_get (sm->segments, s);
      memset (s, 0, sizeof (*s));

      s->ssvm.ssvm_size = rnd_size;
      s->ssvm.i_am_master = 1;
      s->ssvm.my_pid = getpid ();
      s->ssvm.name = format (0, "%s%c", a->segment_name, 0);
      s->ssvm.requested_va = ~0;

      /* Allocate a [sic] shared memory header, in process memory... */
      sh = clib_mem_alloc_aligned (sizeof (*sh), CLIB_CACHE_LINE_BYTES);
      s->ssvm.sh = sh;

      memset (sh, 0, sizeof (*sh));
      sh->heap = a->private_segment_count ? heaps[i] : clib_mem_get_heap ();

      /* Set up svm_fifo_segment shared header */
      fsh = clib_mem_alloc (sizeof (*fsh));
      memset (fsh, 0, sizeof (*fsh));
      sh->opaque[0] = fsh;
      s->h = fsh;
      fsh->flags = FIFO_SEGMENT_F_IS_PRIVATE;
      if (!a->private_segment_count)
	fsh->flags |= FIFO_SEGMENT_F_IS_MAIN_HEAP;
      fsh->segment_name = format (0, "%s%c", a->segment_name, 0);

      if (a->private_segment_count)
	{
	  oldheap = clib_mem_get_heap ();
	  clib_mem_set_heap (sh->heap);
	  preallocate_fifo_pairs (fsh, a);
	  clib_mem_set_heap (oldheap);
	}
      sh->ready = 1;
      vec_add1 (a->new_segment_indices, s - sm->segments);
    }
  vec_free (heaps);
  return (0);
}

/** (slave) attach to an svm fifo segment */
int
svm_fifo_segment_attach (svm_fifo_segment_create_args_t * a)
{
  int rv;
  svm_fifo_segment_private_t *s;
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;

  /* Allocate a fresh segment */
  pool_get (sm->segments, s);
  memset (s, 0, sizeof (*s));

  s->ssvm.ssvm_size = a->segment_size;
  s->ssvm.my_pid = getpid ();
  s->ssvm.name = format (0, "%s%c", a->segment_name, 0);
  s->ssvm.requested_va = sm->next_baseva;

  rv = ssvm_slave_init (&s->ssvm, sm->timeout_in_seconds);

  if (rv)
    {
      _vec_len (s) = vec_len (s) - 1;
      return (rv);
    }

  /* Fish the segment header */
  sh = s->ssvm.sh;
  fsh = (svm_fifo_segment_header_t *) sh->opaque[0];
  s->h = fsh;

  vec_add1 (a->new_segment_indices, s - sm->segments);
  return (0);
}

void
svm_fifo_segment_delete (svm_fifo_segment_private_t * s)
{
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
  if (s->h->flags & FIFO_SEGMENT_F_IS_PRIVATE)
    {
      /* Don't try to free vpp's heap! */
      if (!(s->h->flags & FIFO_SEGMENT_F_IS_MAIN_HEAP))
	mheap_free (s->ssvm.sh->heap);
      clib_mem_free (s->ssvm.sh);
      clib_mem_free (s->h);
      pool_put (sm->segments, s);
    }
  else
    {
      ssvm_delete (&s->ssvm);
      pool_put (sm->segments, s);
    }
}

svm_fifo_t *
svm_fifo_segment_alloc_fifo (svm_fifo_segment_private_t * s,
			     u32 data_size_in_bytes,
			     svm_fifo_segment_freelist_t list_index)
{
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;
  svm_fifo_t *f;
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

  sh = s->ssvm.sh;
  fsh = (svm_fifo_segment_header_t *) sh->opaque[0];

  ssvm_lock_non_recursive (sh, 1);
  oldheap = ssvm_push_heap (sh);

  switch (list_index)
    {
    case FIFO_SEGMENT_RX_FREELIST:
    case FIFO_SEGMENT_TX_FREELIST:
      vec_validate_init_empty (fsh->free_fifos, freelist_index, 0);

      f = fsh->free_fifos[freelist_index];
      if (PREDICT_FALSE (f == 0))
	{
	  allocate_new_fifo_chunk (fsh, data_size_in_bytes,
				   FIFO_SEGMENT_ALLOC_CHUNK_SIZE);
	  f = fsh->free_fifos[freelist_index];
	}
      if (PREDICT_TRUE (f != 0))
	{
	  fsh->free_fifos[freelist_index] = f->next;
	  /* (re)initialize the fifo, as in svm_fifo_create */
	  memset (f, 0, sizeof (*f));
	  f->nitems = data_size_in_bytes;
	  f->ooos_list_head = OOO_SEGMENT_INVALID_INDEX;
	  f->refcnt = 1;
	  f->freelist_index = freelist_index;
	  goto found;
	}
      /* FALLTHROUGH */
    case FIFO_SEGMENT_FREELIST_NONE:
      break;

    default:
      clib_warning ("ignore bogus freelist %d", list_index);
      break;
    }

  /* Note: this can fail, in which case: create another segment */
  f = svm_fifo_create (data_size_in_bytes);
  if (PREDICT_FALSE (f == 0))
    {
      ssvm_pop_heap (oldheap);
      ssvm_unlock_non_recursive (sh);
      return (0);
    }
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

  ssvm_pop_heap (oldheap);
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
svm_fifo_segment_init (u64 baseva, u32 timeout_in_seconds)
{
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;

  sm->next_baseva = baseva;
  sm->timeout_in_seconds = timeout_in_seconds;
}

u32
svm_fifo_segment_index (svm_fifo_segment_private_t * s)
{
  return s - svm_fifo_segment_main.segments;
}

/**
 * Retrieve svm segments pool. Used only for debug purposes.
 */
svm_fifo_segment_private_t *
svm_fifo_segment_segments_pool (void)
{
  svm_fifo_segment_main_t *sm = &svm_fifo_segment_main;
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

  if (freelist_index > vec_len (fsh->free_fifos))
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

/**
 * Segment format function
 */
u8 *
format_svm_fifo_segment (u8 * s, va_list * args)
{
  svm_fifo_segment_private_t *sp
    = va_arg (*args, svm_fifo_segment_private_t *);
  int verbose = va_arg (*args, int);
  ssvm_shared_header_t *sh;
  svm_fifo_segment_header_t *fsh;
  svm_fifo_t *f;
  int i;
  u32 count;
  uword indent = format_get_indent (s) + 2;

  sh = sp->ssvm.sh;
  fsh = (svm_fifo_segment_header_t *) sh->opaque[0];

  s = format (s, "%USegment Heap: %U\n", format_white_space, indent,
	      format_mheap, sh->heap, verbose);
  s = format (s, "%U segment has %u active fifos\n",
	      format_white_space, indent, svm_fifo_segment_num_fifos (sp));

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
