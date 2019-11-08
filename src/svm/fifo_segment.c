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
 * Fifo segment free space
 *
 * Queries the underlying memory manager, dlmalloc, for free space. Since this
 * ends up walking the internal data structures, it should not be called
 * indiscriminately.
 *
 * @param fs		fifo segment
 * @return		number of free bytes
 */
static u32
fs_free_space (fifo_segment_t * fs)
{
  struct dlmallinfo dlminfo;

  dlminfo = mspace_mallinfo (fs->ssvm.sh->heap);
  return dlminfo.fordblks;
}

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

  fsh->n_free_bytes = fs_free_space (fs);
  sh->ready = 1;
  return (0);
}

/**
 * Create a fifo segment and initialize as master
 */
int
fifo_segment_create (fifo_segment_main_t * sm, fifo_segment_create_args_t * a)
{
  fifo_segment_t *fs;
  uword baseva;
  int rv;

  /* Allocate a fresh segment */
  pool_get_zero (sm->segments, fs);

  baseva = a->segment_type == SSVM_SEGMENT_PRIVATE ? ~0ULL : sm->next_baseva;
  fs->ssvm.ssvm_size = a->segment_size;
  fs->ssvm.i_am_master = 1;
  fs->ssvm.my_pid = getpid ();
  fs->ssvm.name = format (0, "%s%c", a->segment_name, 0);
  fs->ssvm.requested_va = baseva;

  if ((rv = ssvm_master_init (&fs->ssvm, a->segment_type)))
    {
      pool_put (sm->segments, fs);
      return (rv);
    }

  /* Note: requested_va updated due to seg base addr randomization */
  sm->next_baseva = fs->ssvm.sh->ssvm_va + fs->ssvm.ssvm_size;

  fifo_segment_init (fs);
  vec_add1 (a->new_segment_indices, fs - sm->segments);
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
  *address = (char *) seg->ssvm.sh->ssvm_va;
  *size = seg->ssvm.ssvm_size;
}

void
fifo_segment_main_init (fifo_segment_main_t * sm, u64 baseva,
			u32 timeout_in_seconds)
{
  sm->next_baseva = baseva;
  sm->timeout_in_seconds = timeout_in_seconds;
}

static inline u32
fs_freelist_for_size (u32 size)
{
  return max_log2 (size) - max_log2 (FIFO_SEGMENT_MIN_FIFO_SIZE);
}

static inline u32
fs_freelist_index_to_size (u32 fl_index)
{
  return 1 << (fl_index + max_log2 (FIFO_SEGMENT_MIN_FIFO_SIZE));
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

static svm_fifo_t *
fs_try_alloc_fifo_freelist (fifo_segment_t * fs, u32 fl_index, u32 data_bytes)
{
  fifo_segment_header_t *fsh = fs->h;
  svm_fifo_chunk_t *c;
  svm_fifo_t *f;

  f = fsh->free_fifos;
  c = fsh->free_chunks[fl_index];

  if (!f || !c)
    return 0;

  fsh->free_fifos = f->next;
  fsh->free_chunks[fl_index] = c->next;
  c->next = c;
  c->start_byte = 0;
  c->length = data_bytes;
  memset (f, 0, sizeof (*f));
  f->start_chunk = c;
  f->end_chunk = c;

  fsh->n_fl_chunk_bytes -= fs_freelist_index_to_size (fl_index);
  return f;
}

static svm_fifo_t *
fs_try_alloc_fifo_freelist_multi_chunk (fifo_segment_t * fs, u32 data_bytes)
{
  svm_fifo_chunk_t *c, *first = 0, *last = 0;
  fifo_segment_header_t *fsh = fs->h;
  u32 fl_index, fl_size, n_alloc = 0;
  svm_fifo_t *f;

  f = fsh->free_fifos;
  if (!f)
    {
      void *oldheap = ssvm_push_heap (fs->ssvm.sh);
      f = clib_mem_alloc_aligned (sizeof (*f), CLIB_CACHE_LINE_BYTES);
      ssvm_pop_heap (oldheap);
      if (!f)
	return 0;
      memset (f, 0, sizeof (*f));
      fsh->n_free_bytes -= sizeof (*f);
    }
  else
    {
      fsh->free_fifos = f->next;
    }

  fl_index = fs_freelist_for_size (data_bytes) - 1;
  vec_validate_init_empty (fsh->free_chunks, fl_index, 0);
  fl_size = fs_freelist_index_to_size (fl_index);

  while (data_bytes)
    {
      c = fsh->free_chunks[fl_index];
      if (c)
	{
	  fsh->free_chunks[fl_index] = c->next;
	  if (!last)
	    last = c;
	  c->next = first;
	  first = c;
	  n_alloc += fl_size;
	  c->length = clib_min (fl_size, data_bytes);
	  data_bytes -= c->length;
	}
      else
	{
	  ASSERT (fl_index > 0);
	  fl_index -= 1;
	  fl_size = fl_size >> 1;
	}
    }
  f->start_chunk = first;
  f->end_chunk = last;
  last->next = first;
  fsh->n_fl_chunk_bytes -= n_alloc;
  return f;
}

static int
fs_try_alloc_fifo_batch (fifo_segment_t * fs, u32 fl_index, u32 batch_size)
{
  fifo_segment_header_t *fsh = fs->h;
  u32 size, hdrs, rounded_data_size;
  svm_fifo_chunk_t *c;
  svm_fifo_t *f;
  void *oldheap;
  u8 *fmem;
  int i;

  vec_validate_init_empty (fsh->free_chunks, fl_index, 0);
  rounded_data_size = fs_freelist_index_to_size (fl_index);
  hdrs = sizeof (*f) + sizeof (*c);
  size = (hdrs + rounded_data_size) * batch_size;

  oldheap = ssvm_push_heap (fs->ssvm.sh);
  fmem = clib_mem_alloc_aligned_at_offset (size, CLIB_CACHE_LINE_BYTES,
					   0 /* align_offset */ ,
					   0 /* os_out_of_memory */ );
  ssvm_pop_heap (oldheap);

  /* Out of space.. */
  if (fmem == 0)
    return -1;

  /* Carve fifo + chunk space */
  for (i = 0; i < batch_size; i++)
    {
      f = (svm_fifo_t *) fmem;
      memset (f, 0, sizeof (*f));
      f->next = fsh->free_fifos;
      fsh->free_fifos = f;
      c = (svm_fifo_chunk_t *) (fmem + sizeof (*f));
      c->start_byte = 0;
      c->length = rounded_data_size;
      c->next = fsh->free_chunks[fl_index];
      fsh->free_chunks[fl_index] = c;
      fmem += hdrs + rounded_data_size;
    }

  fsh->n_fl_chunk_bytes += batch_size * rounded_data_size;
  fsh->n_free_bytes -= size;

  return 0;
}

/**
 * Try to allocate new fifo
 *
 * Tries the following steps in order:
 * - grab fifo and chunk from freelists
 * - batch fifo and chunk allocation
 * - single fifo allocation
 * - grab multiple fifo chunks from freelists
 */
static svm_fifo_t *
fs_try_alloc_fifo (fifo_segment_t * fs, u32 data_bytes)
{
  fifo_segment_header_t *fsh = fs->h;
  u32 fifo_sz, fl_index;
  svm_fifo_t *f = 0;

  fl_index = fs_freelist_for_size (data_bytes);
  vec_validate_init_empty (fsh->free_chunks, fl_index, 0);
  fifo_sz = sizeof (svm_fifo_t) + sizeof (svm_fifo_chunk_t);
  fifo_sz += 1 << max_log2 (data_bytes);

  if (fsh->free_fifos && fsh->free_chunks[fl_index])
    {
      f = fs_try_alloc_fifo_freelist (fs, fl_index, data_bytes);
      if (f)
	goto done;
    }
  if (fifo_sz * FIFO_SEGMENT_ALLOC_BATCH_SIZE < fsh->n_free_bytes)
    {
      if (fs_try_alloc_fifo_batch (fs, fl_index,
				   FIFO_SEGMENT_ALLOC_BATCH_SIZE))
	goto done;

      f = fs_try_alloc_fifo_freelist (fs, fl_index, data_bytes);
      goto done;
    }
  if (fifo_sz <= fsh->n_free_bytes)
    {
      void *oldheap = ssvm_push_heap (fs->ssvm.sh);
      f = svm_fifo_create (data_bytes);
      ssvm_pop_heap (oldheap);
      if (f)
	{
	  fsh->n_free_bytes -= fifo_sz;
	  goto done;
	}
    }
  if (data_bytes <= fsh->n_fl_chunk_bytes)
    f = fs_try_alloc_fifo_freelist_multi_chunk (fs, data_bytes);

done:

  return f;
}

/**
 * Allocate fifo in fifo segment
 */
svm_fifo_t *
fifo_segment_alloc_fifo (fifo_segment_t * fs, u32 data_bytes,
			 fifo_segment_ftype_t ftype)
{
  fifo_segment_header_t *fsh;
  svm_fifo_t *f = 0;

  if (!fs_chunk_size_is_valid (data_bytes))
    {
      clib_warning ("fifo size out of range %d", data_bytes);
      return 0;
    }

  fsh = fs->h;
  ssvm_lock_non_recursive (fs->ssvm.sh, 1);

  f = fs_try_alloc_fifo (fs, data_bytes);
  if (!f)
    goto done;

  /* (re)initialize the fifo, as in svm_fifo_create */
  svm_fifo_init (f, data_bytes);

  /* Initialize chunks and rbtree for multi-chunk fifos */
  if (f->start_chunk->next != f->start_chunk)
    {
      void *oldheap = ssvm_push_heap (fs->ssvm.sh);
      svm_fifo_init_chunks (f);
      ssvm_pop_heap (oldheap);
    }

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
  ssvm_unlock_non_recursive (fs->ssvm.sh);
  return (f);
}

/**
 * Free fifo allocated in fifo segment
 */
void
fifo_segment_free_fifo (fifo_segment_t * fs, svm_fifo_t * f)
{
  svm_fifo_chunk_t *cur, *next;
  fifo_segment_header_t *fsh;
  ssvm_shared_header_t *sh;
  void *oldheap;
  int fl_index;

  ASSERT (f->refcnt > 0);

  if (--f->refcnt > 0)
    return;

  sh = fs->ssvm.sh;
  fsh = fs->h;

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
  f->next = fsh->free_fifos;
  f->prev = 0;
  fsh->free_fifos = f;

  /* Free fifo chunks */
  cur = f->start_chunk;
  do
    {
      next = cur->next;
      fl_index = fs_freelist_for_size (cur->length);
      ASSERT (fl_index < vec_len (fsh->free_chunks));
      cur->next = fsh->free_chunks[fl_index];
      fsh->free_chunks[fl_index] = cur;
      fsh->n_fl_chunk_bytes += fs_freelist_index_to_size (fl_index);
      cur = next;
    }
  while (cur != f->start_chunk);

  f->start_chunk = f->end_chunk = f->new_chunks = 0;
  f->head_chunk = f->tail_chunk = f->ooo_enq = f->ooo_deq = 0;

  oldheap = ssvm_push_heap (sh);
  svm_fifo_free_chunk_lookup (f);
  ssvm_pop_heap (oldheap);

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

int
fifo_segment_prealloc_fifo_hdrs (fifo_segment_t * fs, u32 batch_size)
{
  fifo_segment_header_t *fsh = fs->h;
  svm_fifo_t *f;
  void *oldheap;
  u32 size;
  u8 *fmem;
  int i;

  size = (sizeof (*f)) * batch_size;

  oldheap = ssvm_push_heap (fs->ssvm.sh);
  fmem = clib_mem_alloc_aligned_at_offset (size, CLIB_CACHE_LINE_BYTES,
					   0 /* align_offset */ ,
					   0 /* os_out_of_memory */ );
  ssvm_pop_heap (oldheap);

  /* Out of space.. */
  if (fmem == 0)
    return -1;

  /* Carve fifo + chunk space */
  for (i = 0; i < batch_size; i++)
    {
      f = (svm_fifo_t *) fmem;
      memset (f, 0, sizeof (*f));
      f->next = fsh->free_fifos;
      fsh->free_fifos = f;
      fmem += sizeof (*f);
    }

  fsh->n_free_bytes -= size;

  return 0;
}

int
fifo_segment_prealloc_fifo_chunks (fifo_segment_t * fs, u32 chunk_size,
				   u32 batch_size)
{
  fifo_segment_header_t *fsh = fs->h;
  u32 size, rounded_data_size, fl_index;
  svm_fifo_chunk_t *c;
  void *oldheap;
  u8 *cmem;
  int i;

  if (!fs_chunk_size_is_valid (chunk_size))
    {
      clib_warning ("chunk size out of range %d", chunk_size);
      return -1;
    }

  fl_index = fs_freelist_for_size (chunk_size);
  vec_validate_init_empty (fsh->free_chunks, fl_index, 0);
  rounded_data_size = fs_freelist_index_to_size (fl_index);
  size = (sizeof (*c) + rounded_data_size) * batch_size;

  oldheap = ssvm_push_heap (fs->ssvm.sh);
  cmem = clib_mem_alloc_aligned_at_offset (size, CLIB_CACHE_LINE_BYTES,
					   0 /* align_offset */ ,
					   0 /* os_out_of_memory */ );
  ssvm_pop_heap (oldheap);

  /* Out of space.. */
  if (cmem == 0)
    return -1;

  /* Carve fifo + chunk space */
  for (i = 0; i < batch_size; i++)
    {
      c = (svm_fifo_chunk_t *) cmem;
      c->start_byte = 0;
      c->length = rounded_data_size;
      c->next = fsh->free_chunks[fl_index];
      fsh->free_chunks[fl_index] = c;
      cmem += sizeof (*c) + rounded_data_size;
    }

  fsh->n_fl_chunk_bytes += batch_size * rounded_data_size;
  fsh->n_free_bytes -= size;

  return 0;
}

/**
 * Pre-allocates fifo pairs in fifo segment
 */
void
fifo_segment_preallocate_fifo_pairs (fifo_segment_t * fs,
				     u32 rx_fifo_size, u32 tx_fifo_size,
				     u32 * n_fifo_pairs)
{
  u32 rx_rounded_data_size, tx_rounded_data_size, pair_size, pairs_to_alloc;
  int rx_fl_index, tx_fl_index;
  uword space_available;
  u32 hdrs;

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
  rx_fl_index = fs_freelist_for_size (rx_fifo_size);
  tx_rounded_data_size = (1 << (max_log2 (tx_fifo_size)));
  tx_fl_index = fs_freelist_for_size (tx_fifo_size);

  hdrs = sizeof (svm_fifo_t) + sizeof (svm_fifo_chunk_t);

  /* Calculate space requirements */
  pair_size = 2 * hdrs + rx_rounded_data_size + tx_rounded_data_size;
  space_available = fs_free_space (fs);
  pairs_to_alloc = space_available / pair_size;
  pairs_to_alloc = clib_min (pairs_to_alloc, *n_fifo_pairs);

  if (!pairs_to_alloc)
    return;

  if (fs_try_alloc_fifo_batch (fs, rx_fl_index, pairs_to_alloc))
    clib_warning ("rx prealloc failed: pairs %u", pairs_to_alloc);
  if (fs_try_alloc_fifo_batch (fs, tx_fl_index, pairs_to_alloc))
    clib_warning ("tx prealloc failed: pairs %u", pairs_to_alloc);

  /* Account for the pairs allocated */
  *n_fifo_pairs -= pairs_to_alloc;
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
      return -1;
    }

  fl_index = fs_freelist_for_size (chunk_size);

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
	  ssvm_unlock_non_recursive (sh);
	  return -1;
	}
    }
  else
    {
      fs->h->free_chunks[fl_index] = c->next;
      c->next = 0;
      fs->h->n_fl_chunk_bytes -= fs_freelist_index_to_size (fl_index);
    }

  svm_fifo_add_chunk (f, c);

  ssvm_pop_heap (oldheap);
  ssvm_unlock_non_recursive (sh);
  return 0;
}

int
fifo_segment_collect_fifo_chunks (fifo_segment_t * fs, svm_fifo_t * f)
{
  svm_fifo_chunk_t *cur, *next;
  ssvm_shared_header_t *sh;
  void *oldheap;
  int fl_index;

  sh = fs->ssvm.sh;
  ssvm_lock_non_recursive (sh, 1);

  oldheap = ssvm_push_heap (sh);
  cur = svm_fifo_collect_chunks (f);

  while (cur)
    {
      next = cur->next;
      fl_index = fs_freelist_for_size (cur->length);
      cur->next = fs->h->free_chunks[fl_index];
      fs->h->free_chunks[fl_index] = cur;
      cur = next;
    }

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
fifo_segment_num_free_fifos (fifo_segment_t * fs)
{
  fifo_segment_header_t *fsh = fs->h;
  svm_fifo_t *f;
  u32 count = 0;

  f = fsh->free_fifos;
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
  fl_index = fs_freelist_for_size (rounded_size);

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

void
fifo_segment_update_free_bytes (fifo_segment_t * fs)
{
  fs->h->n_free_bytes = fs_free_space (fs);
}

u32
fifo_segment_free_bytes (fifo_segment_t * fs)
{
  return fs->h->n_free_bytes;
}

u32
fifo_segment_fl_chunk_bytes (fifo_segment_t * fs)
{
  return fs->h->n_fl_chunk_bytes;
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
  u32 count, indent, active_fifos, free_fifos, fifo_hdr = 0, chunk_size;
  fifo_segment_t *fs = va_arg (*args, fifo_segment_t *);
  int verbose __attribute__ ((unused)) = va_arg (*args, int);
  u32 est_chunk_bytes, est_free_seg_bytes;
  fifo_segment_header_t *fsh;
  svm_fifo_chunk_t *c;
  u64 chunk_bytes = 0;
  char *address;
  size_t size;
  int i;

  indent = format_get_indent (s) + 2;
#if USE_DLMALLOC == 0
  s = format (s, "%U segment heap: %U\n", format_white_space, indent,
	      format_mheap, svm_fifo_segment_heap (fs), verbose);
  s = format (s, "%U segment has %u active fifos\n",
	      format_white_space, indent, fifo_segment_num_fifos (fs));
#endif

  if (fs == 0)
    {
      s = format (s, "%-15s%15s%15s%15s%15s%15s", "Name", "Type",
		  "HeapSize (M)", "ActiveFifos", "FreeFifos", "Address");
      return s;
    }

  fsh = fs->h;
  fifo_segment_info (fs, &address, &size);
  active_fifos = fifo_segment_num_fifos (fs);
  free_fifos = fifo_segment_num_free_fifos (fs);

  s = format (s, "%-15v%15U%15llu%15u%15u%15llx", ssvm_name (&fs->ssvm),
	      format_fifo_segment_type, fs, size >> 20ULL, active_fifos,
	      free_fifos, address);

  if (!verbose)
    return s;

  if (fsh->free_chunks)
    s = format (s, "\n\n%UFree chunks by size:\n", format_white_space,
		indent + 2);
  else
    s = format (s, "\n");

  for (i = 0; i < vec_len (fsh->free_chunks); i++)
    {
      c = fsh->free_chunks[i];
      if (c == 0)
	continue;
      count = 0;
      while (c)
	{
	  c = c->next;
	  count++;
	}

      chunk_size = fs_freelist_index_to_size (i);
      s = format (s, "%U%-5u kB: %u\n", format_white_space, indent + 2,
		  chunk_size >> 10, count);

      chunk_bytes += count * chunk_size;
    }

  fifo_hdr = free_fifos * sizeof (svm_fifo_t);
  est_chunk_bytes = fifo_segment_fl_chunk_bytes (fs);
  est_free_seg_bytes = fsh->n_free_bytes;
  fifo_segment_update_free_bytes (fs);

  s = format (s, "\n%Useg free bytes: %U (%u) estimated: %U (%u)\n",
	      format_white_space, indent + 2, format_memory_size,
	      fsh->n_free_bytes, fsh->n_free_bytes, format_memory_size,
	      est_free_seg_bytes, est_free_seg_bytes);
  s = format (s, "%Uchunk free bytes: %U (%lu) estimated: %U (%u)\n",
	      format_white_space, indent + 2, format_memory_size, chunk_bytes,
	      chunk_bytes, format_memory_size, est_chunk_bytes,
	      est_chunk_bytes);
  s = format (s, "%Ufifo hdr free bytes: %U (%u)\n", format_white_space,
	      indent + 2, format_memory_size, fifo_hdr, fifo_hdr);
  s = format (s, "\n");

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
