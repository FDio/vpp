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

static inline fifo_segment_slice_t *
fsh_slice_get (fifo_segment_header_t * fsh, u32 slice_index)
{
  return &fsh->slices[slice_index];
}

static char *fifo_segment_mem_status_strings[] = {
#define _(sym,str) str,
  foreach_segment_mem_status
#undef _
};

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
static uword
fsh_free_space (fifo_segment_header_t * fsh)
{
  return clib_mem_get_heap_free_space (fsh->ssvm_sh->heap);
}

static inline void
fsh_free_bytes_sub (fifo_segment_header_t * fsh, int size)
{
  clib_atomic_fetch_sub_rel (&fsh->n_free_bytes, size);
}

static inline uword
fsh_n_free_bytes (fifo_segment_header_t * fsh)
{
  uword n_free = clib_atomic_load_relax_n (&fsh->n_free_bytes);
  return n_free > fsh->n_reserved_bytes ? n_free - fsh->n_reserved_bytes : 0;
}

static inline void
fsh_update_free_bytes (fifo_segment_header_t * fsh)
{
  clib_atomic_store_rel_n (&fsh->n_free_bytes, fsh_free_space (fsh));
}

static inline void
fsh_cached_bytes_add (fifo_segment_header_t * fsh, uword size)
{
  clib_atomic_fetch_add_rel (&fsh->n_cached_bytes, size);
}

static inline void
fsh_cached_bytes_sub (fifo_segment_header_t * fsh, uword size)
{
  clib_atomic_fetch_sub_rel (&fsh->n_cached_bytes, size);
}

static inline uword
fsh_n_cached_bytes (fifo_segment_header_t * fsh)
{
  uword n_cached = clib_atomic_load_relax_n (&fsh->n_cached_bytes);
  return n_cached;
}

static inline void
fsh_active_fifos_update (fifo_segment_header_t * fsh, int inc)
{
  clib_atomic_fetch_add_rel (&fsh->n_active_fifos, inc);
}

static inline u32
fsh_n_active_fifos (fifo_segment_header_t * fsh)
{
  return clib_atomic_load_relax_n (&fsh->n_active_fifos);
}

static inline uword
fsh_virtual_mem (fifo_segment_header_t * fsh)
{
  fifo_segment_slice_t *fss;
  uword total_vm = 0;
  int i;

  for (i = 0; i < fsh->n_slices; i++)
    {
      fss = fsh_slice_get (fsh, i);
      total_vm += clib_atomic_load_relax_n (&fss->virtual_mem);
    }
  return total_vm;
}

void
fsh_virtual_mem_update (fifo_segment_header_t * fsh, u32 slice_index,
			int n_bytes)
{
  fifo_segment_slice_t *fss = fsh_slice_get (fsh, slice_index);
  fss->virtual_mem += n_bytes;
}

static void
fsh_check_mem (fifo_segment_header_t * fsh)
{
  uword thresh;

  if (fsh->flags & FIFO_SEGMENT_F_MEM_LIMIT)
    return;

  thresh = clib_max (0.01 * fsh->ssvm_sh->ssvm_size,
		     2 * fsh->n_reserved_bytes);
  if (fsh->n_free_bytes > thresh)
    return;

  fsh->flags |= FIFO_SEGMENT_F_MEM_LIMIT;
  fsh_update_free_bytes (fsh);
}

static inline int
fss_chunk_fl_index_is_valid (fifo_segment_slice_t * fss, u32 fl_index)
{
  return (fl_index < vec_len (fss->free_chunks));
}

static void
fss_chunk_free_list_push (fifo_segment_slice_t * fss, u32 fl_index,
			  svm_fifo_chunk_t * c)
{
  clib_spinlock_lock (&fss->chunk_lock);
  c->next = fss->free_chunks[fl_index];
  fss->free_chunks[fl_index] = c;
  clib_spinlock_unlock (&fss->chunk_lock);
}

static void
fss_chunk_free_list_push_list (fifo_segment_slice_t * fss, u32 fl_index,
			       svm_fifo_chunk_t * head,
			       svm_fifo_chunk_t * tail)
{
  clib_spinlock_lock (&fss->chunk_lock);
  tail->next = fss->free_chunks[fl_index];
  fss->free_chunks[fl_index] = head;
  clib_spinlock_unlock (&fss->chunk_lock);
}

static svm_fifo_chunk_t *
fss_chunk_free_list_pop (fifo_segment_slice_t * fss, u32 fl_index)
{
  svm_fifo_chunk_t *c;

  ASSERT (fss_chunk_fl_index_is_valid (fss, fl_index));

  clib_spinlock_lock (&fss->chunk_lock);

  if (!fss->free_chunks[fl_index])
    {
      clib_spinlock_unlock (&fss->chunk_lock);
      return 0;
    }

  c = fss->free_chunks[fl_index];
  fss->free_chunks[fl_index] = c->next;

  clib_spinlock_unlock (&fss->chunk_lock);

  return c;
}

static inline void
fss_fifo_add_active_list (fifo_segment_slice_t * fss, svm_fifo_t * f)
{
  if (fss->fifos)
    {
      fss->fifos->prev = f;
      f->next = fss->fifos;
    }
  fss->fifos = f;
}

static inline void
fss_fifo_del_active_list (fifo_segment_slice_t * fss, svm_fifo_t * f)
{
  if (f->flags & SVM_FIFO_F_LL_TRACKED)
    {
      if (f->prev)
	f->prev->next = f->next;
      else
	fss->fifos = f->next;
      if (f->next)
	f->next->prev = f->prev;
    }
}

static inline uword
fss_fl_chunk_bytes (fifo_segment_slice_t * fss)
{
  return clib_atomic_load_relax_n (&fss->n_fl_chunk_bytes);
}

static inline void
fss_fl_chunk_bytes_add (fifo_segment_slice_t * fss, uword size)
{
  clib_atomic_fetch_add_relax (&fss->n_fl_chunk_bytes, size);
}

static inline void
fss_fl_chunk_bytes_sub (fifo_segment_slice_t * fss, uword size)
{
  clib_atomic_fetch_sub_relax (&fss->n_fl_chunk_bytes, size);
}

/**
 * Initialize fifo segment shared header
 */
int
fifo_segment_init (fifo_segment_t * fs)
{
  fifo_segment_header_t *fsh;
  fifo_segment_slice_t *fss;
  ssvm_shared_header_t *sh;
  u32 max_chunk_sz;
  uword max_fifo;
  void *oldheap;
  int i;

  sh = fs->ssvm.sh;
  oldheap = ssvm_push_heap (sh);

  /*
   * Manually align the fifo segment header to sizeof(uword) = 8 bytes.
   * Long story made short: the "process-private" fifo segment
   * is allocated from the main heap, not mmapped. dlmalloc
   * only guarantees 4-byte alignment, and on aarch64
   * the fsh can end up 4-byte but not 8-byte aligned.
   * That eventually causes the atomic op in fifo_segment_update_free_bytes
   * to backfire.
   */
  fsh = clib_mem_alloc_aligned (sizeof (*fsh), sizeof (uword));
  clib_memset (fsh, 0, sizeof (*fsh));
  fs->h = sh->opaque[0] = fsh;
  fs->n_slices = clib_max (fs->n_slices, 1);

  fsh->ssvm_sh = fs->ssvm.sh;
  fsh->n_slices = fs->n_slices;
  max_fifo = clib_min ((fsh_free_space (fsh) - 4096) / 2,
		       FIFO_SEGMENT_MAX_FIFO_SIZE);
  fsh->max_log2_chunk_size = max_log2 (max_fifo);

  fsh->slices = clib_mem_alloc (sizeof (*fss) * fs->n_slices);
  clib_memset (fsh->slices, 0, sizeof (*fss) * fs->n_slices);
  max_chunk_sz = fsh->max_log2_chunk_size - FIFO_SEGMENT_MIN_LOG2_FIFO_SIZE;

  for (i = 0; i < fs->n_slices; i++)
    {
      fss = fsh_slice_get (fsh, i);
      vec_validate_init_empty (fss->free_chunks, max_chunk_sz, 0);
      vec_validate_init_empty (fss->num_chunks, max_chunk_sz, 0);
      clib_spinlock_init (&fss->chunk_lock);
    }

  ssvm_pop_heap (oldheap);

  fsh->n_free_bytes = fsh_free_space (fsh);
  fsh->n_cached_bytes = 0;
  fsh->n_reserved_bytes = clib_min (0.01 * fsh->n_free_bytes, 256 << 10);
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
  fs->ssvm.is_server = 1;
  fs->ssvm.my_pid = getpid ();
  fs->ssvm.name = format (0, "%s%c", a->segment_name, 0);
  fs->ssvm.requested_va = baseva;

  if ((rv = ssvm_server_init (&fs->ssvm, a->segment_type)))
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
  fifo_segment_t *fs;
  int rv;

  pool_get_zero (sm->segments, fs);

  fs->ssvm.ssvm_size = a->segment_size;
  fs->ssvm.my_pid = getpid ();
  fs->ssvm.name = format (0, "%s%c", a->segment_name, 0);
  fs->ssvm.requested_va = sm->next_baseva;
  if (a->segment_type == SSVM_SEGMENT_MEMFD)
    fs->ssvm.fd = a->memfd_fd;
  else
    fs->ssvm.attach_timeout = sm->timeout_in_seconds;

  if ((rv = ssvm_client_init (&fs->ssvm, a->segment_type)))
    {
      _vec_len (fs) = vec_len (fs) - 1;
      return (rv);
    }

  /* Fish the segment header */
  fs->h = fs->ssvm.sh->opaque[0];

  vec_add1 (a->new_segment_indices, fs - sm->segments);
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
  if (PREDICT_FALSE (size < FIFO_SEGMENT_MIN_FIFO_SIZE))
    return 0;
  return max_log2 (size) - FIFO_SEGMENT_MIN_LOG2_FIFO_SIZE;
}

static inline u32
fs_freelist_index_to_size (u32 fl_index)
{
  return 1 << (fl_index + FIFO_SEGMENT_MIN_LOG2_FIFO_SIZE);
}

static inline int
fs_chunk_size_is_valid (fifo_segment_header_t * fsh, u32 size)
{
  /*
   * 4K minimum. It's not likely that anything good will happen
   * with a smaller FIFO.
   */
  return size >= FIFO_SEGMENT_MIN_FIFO_SIZE
    && size <= (1ULL << fsh->max_log2_chunk_size);
}

svm_fifo_chunk_t *
fs_try_alloc_multi_chunk (fifo_segment_header_t * fsh,
			  fifo_segment_slice_t * fss, u32 data_bytes)
{
  u32 fl_index, fl_size, n_alloc = 0, req_bytes = data_bytes;
  svm_fifo_chunk_t *c, *first = 0, *next;

  fl_index = fs_freelist_for_size (req_bytes);
  if (fl_index > 0)
    fl_index -= 1;

  fl_size = fs_freelist_index_to_size (fl_index);

  while (req_bytes)
    {
      c = fss_chunk_free_list_pop (fss, fl_index);
      if (c)
	{
	  c->next = first;
	  first = c;
	  n_alloc += fl_size;
	  req_bytes -= clib_min (fl_size, req_bytes);
	}
      else
	{
	  /* Failed to allocate with smaller chunks */
	  if (fl_index == 0)
	    {
	      /* Free all chunks if any allocated */
	      c = first;
	      while (c)
		{
		  fl_index = fs_freelist_for_size (c->length);
		  next = c->next;
		  fss_chunk_free_list_push (fss, fl_index, c);
		  c = next;
		}
	      n_alloc = 0;
	      first = 0;
	      /* As last attempt, try allocating a chunk larger than
	       * the requested size, if possible */
	      fl_index = fs_freelist_for_size (data_bytes) + 1;
	      if (!fss_chunk_fl_index_is_valid (fss, fl_index))
		return 0;
	      first = fss_chunk_free_list_pop (fss, fl_index);
	      if (first)
		{
		  first->next = 0;
		  n_alloc = fs_freelist_index_to_size (fl_index);
		  goto done;
		}
	      return 0;
	    }
	  fl_index -= 1;
	  fl_size = fl_size >> 1;
	}
    }

done:
  fss_fl_chunk_bytes_sub (fss, n_alloc);
  fsh_cached_bytes_sub (fsh, n_alloc);
  return first;
}

static int
fsh_try_alloc_fifo_hdr_batch (fifo_segment_header_t * fsh,
			      fifo_segment_slice_t * fss, u32 batch_size)
{
  svm_fifo_t *f;
  void *oldheap;
  uword size;
  u8 *fmem;
  int i;

  ASSERT (batch_size != 0);

  size = (uword) sizeof (*f) * batch_size;

  oldheap = ssvm_push_heap (fsh->ssvm_sh);
  fmem = clib_mem_alloc_aligned_at_offset (size, CLIB_CACHE_LINE_BYTES,
					   0 /* align_offset */ ,
					   0 /* os_out_of_memory */ );
  ssvm_pop_heap (oldheap);

  /* Out of space.. */
  if (fmem == 0)
    return -1;

  /* Carve fifo hdr space */
  for (i = 0; i < batch_size; i++)
    {
      f = (svm_fifo_t *) fmem;
      memset (f, 0, sizeof (*f));
      f->next = fss->free_fifos;
      fss->free_fifos = f;
      fmem += sizeof (*f);
    }

  return 0;
}

static int
fsh_try_alloc_chunk_batch (fifo_segment_header_t * fsh,
			   fifo_segment_slice_t * fss,
			   u32 fl_index, u32 batch_size)
{
  svm_fifo_chunk_t *c, *head = 0, *tail;
  uword size, total_chunk_bytes;
  u32 rounded_data_size;
  void *oldheap;
  u8 *cmem;
  int i;

  ASSERT (batch_size != 0);

  rounded_data_size = fs_freelist_index_to_size (fl_index);
  total_chunk_bytes = (uword) batch_size *rounded_data_size;
  size = (uword) (sizeof (*c) + rounded_data_size) * batch_size;

  oldheap = ssvm_push_heap (fsh->ssvm_sh);
  cmem = clib_mem_alloc_aligned_at_offset (size, CLIB_CACHE_LINE_BYTES,
					   0 /* align_offset */ ,
					   0 /* os_out_of_memory */ );
  ssvm_pop_heap (oldheap);

  /* Out of space.. */
  if (cmem == 0)
    return -1;

  /* Carve fifo + chunk space */
  tail = c = (svm_fifo_chunk_t *) cmem;
  for (i = 0; i < batch_size; i++)
    {
      c->start_byte = 0;
      c->length = rounded_data_size;
      c->next = head;
      head = c;
      cmem += sizeof (*c) + rounded_data_size;
      c = (svm_fifo_chunk_t *) cmem;
    }

  fss_chunk_free_list_push_list (fss, fl_index, head, tail);
  fss->num_chunks[fl_index] += batch_size;
  fss_fl_chunk_bytes_add (fss, total_chunk_bytes);
  fsh_cached_bytes_add (fsh, total_chunk_bytes);
  fsh_free_bytes_sub (fsh, size);

  return 0;
}

static int
fs_try_alloc_fifo_batch (fifo_segment_header_t * fsh,
			 fifo_segment_slice_t * fss,
			 u32 fl_index, u32 batch_size)
{
  if (fsh_try_alloc_fifo_hdr_batch (fsh, fss, batch_size))
    return 0;
  return fsh_try_alloc_chunk_batch (fsh, fss, fl_index, batch_size);
}

static svm_fifo_t *
fsh_try_alloc_fifo_hdr (fifo_segment_header_t * fsh,
			fifo_segment_slice_t * fss)
{
  svm_fifo_t *f;

  if (!fss->free_fifos)
    {
      if (fsh_try_alloc_fifo_hdr_batch (fsh, fss,
					FIFO_SEGMENT_ALLOC_BATCH_SIZE))
	return 0;
    }

  f = fss->free_fifos;
  fss->free_fifos = f->next;
  memset (f, 0, sizeof (*f));
  return f;
}

static svm_fifo_chunk_t *
fsh_try_alloc_chunk (fifo_segment_header_t * fsh,
		     fifo_segment_slice_t * fss, u32 data_bytes)
{
  svm_fifo_chunk_t *c;
  u32 fl_index;

  fl_index = fs_freelist_for_size (data_bytes);

free_list:
  c = fss_chunk_free_list_pop (fss, fl_index);
  if (c)
    {
      c->next = 0;
      fss_fl_chunk_bytes_sub (fss, fs_freelist_index_to_size (fl_index));
      fsh_cached_bytes_sub (fsh, fs_freelist_index_to_size (fl_index));
    }
  else
    {
      u32 chunk_size, batch = FIFO_SEGMENT_ALLOC_BATCH_SIZE;
      uword n_free;

      chunk_size = fs_freelist_index_to_size (fl_index);
      n_free = fsh_n_free_bytes (fsh);

      if (chunk_size <= n_free)
	{
	  batch = chunk_size * batch <= n_free ? batch : 1;
	  if (!fsh_try_alloc_chunk_batch (fsh, fss, fl_index, batch))
	    goto free_list;
	}
      /* Failed to allocate larger chunk, try to allocate multi-chunk
       * that is close to what was actually requested */
      if (data_bytes <= fss_fl_chunk_bytes (fss))
	{
	  c = fs_try_alloc_multi_chunk (fsh, fss, data_bytes);
	  if (c)
	    goto done;
	  batch = n_free / FIFO_SEGMENT_MIN_FIFO_SIZE;
	  if (!batch || fsh_try_alloc_chunk_batch (fsh, fss, 0, batch))
	    {
	      fsh_check_mem (fsh);
	      goto done;
	    }
	}
      if (data_bytes <= fss_fl_chunk_bytes (fss) + n_free)
	{
	  u32 min_size = FIFO_SEGMENT_MIN_FIFO_SIZE;

	  batch = (data_bytes - fss_fl_chunk_bytes (fss)) / min_size;
	  batch = clib_min (batch + 1, n_free / min_size);
	  if (fsh_try_alloc_chunk_batch (fsh, fss, 0, batch))
	    {
	      fsh_check_mem (fsh);
	      goto done;
	    }
	  c = fs_try_alloc_multi_chunk (fsh, fss, data_bytes);
	}
    }

done:

  return c;
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
fs_try_alloc_fifo (fifo_segment_header_t * fsh, fifo_segment_slice_t * fss,
		   u32 data_bytes)
{
  u32 fl_index, min_size;
  svm_fifo_chunk_t *c;
  svm_fifo_t *f = 0;

  min_size = clib_max ((fsh->pct_first_alloc * data_bytes) / 100, 4096);
  fl_index = fs_freelist_for_size (min_size);

  if (!fss_chunk_fl_index_is_valid (fss, fl_index))
    return 0;

  f = fsh_try_alloc_fifo_hdr (fsh, fss);
  if (!f)
    return 0;

  c = fsh_try_alloc_chunk (fsh, fss, min_size);
  if (!c)
    {
      f->next = fss->free_fifos;
      fss->free_fifos = f;
      return 0;
    }

  f->start_chunk = c;
  while (c->next)
    c = c->next;
  f->end_chunk = c;
  f->size = data_bytes;
  f->fs_hdr = fsh;

  return f;
}

svm_fifo_chunk_t *
fsh_alloc_chunk (fifo_segment_header_t * fsh, u32 slice_index, u32 chunk_size)
{
  fifo_segment_slice_t *fss;
  svm_fifo_chunk_t *c;

  fss = fsh_slice_get (fsh, slice_index);
  c = fsh_try_alloc_chunk (fsh, fss, chunk_size);

  return c;
}

static void
fsh_slice_collect_chunks (fifo_segment_header_t * fsh,
			  fifo_segment_slice_t * fss, svm_fifo_chunk_t * c)
{
  u32 n_collect = 0, fl_index;
  svm_fifo_chunk_t *next;

  while (c)
    {
      CLIB_MEM_UNPOISON (c, sizeof (*c));
      next = c->next;
      fl_index = fs_freelist_for_size (c->length);
      fss_chunk_free_list_push (fss, fl_index, c);
      n_collect += fs_freelist_index_to_size (fl_index);
      c = next;
    }

  fss_fl_chunk_bytes_add (fss, n_collect);
  fsh_cached_bytes_add (fsh, n_collect);
}

void
fsh_collect_chunks (fifo_segment_header_t * fsh, u32 slice_index,
		    svm_fifo_chunk_t * c)
{
  fifo_segment_slice_t *fss;
  fss = fsh_slice_get (fsh, slice_index);
  fsh_slice_collect_chunks (fsh, fss, c);
}

/**
 * Allocate fifo in fifo segment
 */
svm_fifo_t *
fifo_segment_alloc_fifo_w_slice (fifo_segment_t * fs, u32 slice_index,
				 u32 data_bytes, fifo_segment_ftype_t ftype)
{
  fifo_segment_header_t *fsh = fs->h;
  fifo_segment_slice_t *fss;
  svm_fifo_t *f = 0;

  ASSERT (slice_index < fs->n_slices);

  if (PREDICT_FALSE (data_bytes > 1 << fsh->max_log2_chunk_size))
    return 0;

  fss = fsh_slice_get (fsh, slice_index);
  f = fs_try_alloc_fifo (fsh, fss, data_bytes);
  if (!f)
    goto done;

  f->slice_index = slice_index;

  svm_fifo_init (f, data_bytes);

  /* If rx fifo type add to active fifos list. When cleaning up segment,
   * we need a list of active sessions that should be disconnected. Since
   * both rx and tx fifos keep pointers to the session, it's enough to track
   * only one. */
  if (ftype == FIFO_SEGMENT_RX_FIFO)
    {
      fss_fifo_add_active_list (fss, f);
      f->flags |= SVM_FIFO_F_LL_TRACKED;
    }

  fsh_active_fifos_update (fsh, 1);
  fss->virtual_mem += svm_fifo_size (f);

done:
  return (f);
}

/**
 * Free fifo allocated in fifo segment
 */
void
fifo_segment_free_fifo (fifo_segment_t * fs, svm_fifo_t * f)
{
  fifo_segment_header_t *fsh = fs->h;
  fifo_segment_slice_t *fss;

  ASSERT (f->refcnt > 0);

  if (--f->refcnt > 0)
    return;

  fss = fsh_slice_get (fsh, f->slice_index);

  /* Remove from active list. Only rx fifos are tracked */
  if (f->flags & SVM_FIFO_F_LL_TRACKED)
    {
      fss_fifo_del_active_list (fss, f);
      f->flags &= ~SVM_FIFO_F_LL_TRACKED;
    }

  /* Free fifo chunks */
  fsh_slice_collect_chunks (fsh, fss, f->start_chunk);

  f->start_chunk = f->end_chunk = 0;
  f->head_chunk = f->tail_chunk = f->ooo_enq = f->ooo_deq = 0;

  /* not allocated on segment heap */
  svm_fifo_free_chunk_lookup (f);
  svm_fifo_free_ooo_data (f);

  if (CLIB_DEBUG)
    {
      f->master_session_index = ~0;
      f->master_thread_index = ~0;
    }

  fss->virtual_mem -= svm_fifo_size (f);

  /* Add to free list */
  f->next = fss->free_fifos;
  f->prev = 0;
  fss->free_fifos = f;

  fsh_active_fifos_update (fsh, -1);
}

void
fifo_segment_detach_fifo (fifo_segment_t * fs, svm_fifo_t * f)
{
  fifo_segment_slice_t *fss;
  svm_fifo_chunk_t *c;
  u32 fl_index;

  ASSERT (f->refcnt == 1);

  fss = fsh_slice_get (fs->h, f->slice_index);
  fss->virtual_mem -= svm_fifo_size (f);
  if (f->flags & SVM_FIFO_F_LL_TRACKED)
    fss_fifo_del_active_list (fss, f);

  c = f->start_chunk;
  while (c)
    {
      fl_index = fs_freelist_for_size (c->length);
      clib_atomic_fetch_sub_rel (&fss->num_chunks[fl_index], 1);
      c = c->next;
    }
}

void
fifo_segment_attach_fifo (fifo_segment_t * fs, svm_fifo_t * f,
			  u32 slice_index)
{
  fifo_segment_slice_t *fss;
  svm_fifo_chunk_t *c;
  u32 fl_index;

  f->slice_index = slice_index;
  fss = fsh_slice_get (fs->h, f->slice_index);
  fss->virtual_mem += svm_fifo_size (f);
  if (f->flags & SVM_FIFO_F_LL_TRACKED)
    fss_fifo_add_active_list (fss, f);

  c = f->start_chunk;
  while (c)
    {
      fl_index = fs_freelist_for_size (c->length);
      clib_atomic_fetch_add_rel (&fss->num_chunks[fl_index], 1);
      c = c->next;
    }
}

int
fifo_segment_prealloc_fifo_hdrs (fifo_segment_t * fs, u32 slice_index,
				 u32 batch_size)
{
  fifo_segment_header_t *fsh = fs->h;
  fifo_segment_slice_t *fss;
  svm_fifo_t *f;
  void *oldheap;
  uword size;
  u8 *fmem;
  int i;

  fss = fsh_slice_get (fsh, slice_index);
  size = (uword) (sizeof (*f)) * batch_size;

  oldheap = ssvm_push_heap (fsh->ssvm_sh);
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
      f->next = fss->free_fifos;
      fss->free_fifos = f;
      fmem += sizeof (*f);
    }

  fsh_free_bytes_sub (fsh, size);

  return 0;
}

int
fifo_segment_prealloc_fifo_chunks (fifo_segment_t * fs, u32 slice_index,
				   u32 chunk_size, u32 batch_size)
{
  fifo_segment_header_t *fsh = fs->h;
  fifo_segment_slice_t *fss;
  u32 fl_index;

  if (!fs_chunk_size_is_valid (fsh, chunk_size))
    {
      clib_warning ("chunk size out of range %d", chunk_size);
      return -1;
    }

  fl_index = fs_freelist_for_size (chunk_size);
  fss = fsh_slice_get (fsh, slice_index);

  return fsh_try_alloc_chunk_batch (fsh, fss, fl_index, batch_size);
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
  u32 hdrs, pairs_per_slice, alloc_now;
  fifo_segment_header_t *fsh = fs->h;
  int rx_fl_index, tx_fl_index, i;
  fifo_segment_slice_t *fss;
  uword space_available;

  /* Parameter check */
  if (rx_fifo_size == 0 || tx_fifo_size == 0 || *n_fifo_pairs == 0)
    return;

  if (!fs_chunk_size_is_valid (fsh, rx_fifo_size))
    {
      clib_warning ("rx fifo_size out of range %d", rx_fifo_size);
      return;
    }

  if (!fs_chunk_size_is_valid (fsh, tx_fifo_size))
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
  space_available = fsh_free_space (fsh);
  pairs_to_alloc = space_available / pair_size;
  pairs_to_alloc = clib_min (pairs_to_alloc, *n_fifo_pairs);
  pairs_per_slice = pairs_to_alloc / fs->n_slices;
  pairs_per_slice += pairs_to_alloc % fs->n_slices ? 1 : 0;

  if (!pairs_per_slice)
    return;

  for (i = 0; i < fs->n_slices; i++)
    {
      alloc_now = clib_min (pairs_per_slice, *n_fifo_pairs);
      if (0 == alloc_now)
        break;

      fss = fsh_slice_get (fsh, i);
      if (fs_try_alloc_fifo_batch (fsh, fss, rx_fl_index, alloc_now))
	clib_warning ("rx prealloc failed: pairs %u", alloc_now);
      if (fs_try_alloc_fifo_batch (fsh, fss, tx_fl_index, alloc_now))
	clib_warning ("tx prealloc failed: pairs %u", alloc_now);

      /* Account for the pairs allocated */
      *n_fifo_pairs -= alloc_now;
    }
}

/**
 * Get number of active fifos
 */
u32
fifo_segment_num_fifos (fifo_segment_t * fs)
{
  return fsh_n_active_fifos (fs->h);
}

static u32
fs_slice_num_free_fifos (fifo_segment_slice_t * fss)
{
  svm_fifo_t *f;
  u32 count = 0;

  f = fss->free_fifos;
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
fifo_segment_num_free_fifos (fifo_segment_t * fs)
{
  fifo_segment_header_t *fsh = fs->h;
  fifo_segment_slice_t *fss;
  int slice_index;
  u32 count = 0;

  for (slice_index = 0; slice_index < fs->n_slices; slice_index++)
    {
      fss = fsh_slice_get (fsh, slice_index);
      count += fs_slice_num_free_fifos (fss);
    }
  return count;
}

static u32
fs_slice_num_free_chunks (fifo_segment_slice_t * fss, u32 size)
{
  u32 count = 0, rounded_size, fl_index;
  svm_fifo_chunk_t *c;
  int i;

  /* Count all free chunks? */
  if (size == ~0)
    {
      for (i = 0; i < vec_len (fss->free_chunks); i++)
	{
	  c = fss->free_chunks[i];
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

  if (fl_index >= vec_len (fss->free_chunks))
    return 0;

  c = fss->free_chunks[fl_index];
  if (c == 0)
    return 0;

  while (c)
    {
      c = c->next;
      count++;
    }
  return count;
}

u32
fifo_segment_num_free_chunks (fifo_segment_t * fs, u32 size)
{
  fifo_segment_header_t *fsh = fs->h;
  fifo_segment_slice_t *fss;
  int slice_index;
  u32 count = 0;

  for (slice_index = 0; slice_index < fs->n_slices; slice_index++)
    {
      fss = fsh_slice_get (fsh, slice_index);
      count += fs_slice_num_free_chunks (fss, size);
    }
  return count;
}

void
fifo_segment_update_free_bytes (fifo_segment_t * fs)
{
  fsh_update_free_bytes (fs->h);
}

uword
fifo_segment_size (fifo_segment_t * fs)
{
  return fs->ssvm.ssvm_size;
}

u8
fsh_has_reached_mem_limit (fifo_segment_header_t * fsh)
{
  return (fsh->flags & FIFO_SEGMENT_F_MEM_LIMIT) ? 1 : 0;
}

void
fsh_reset_mem_limit (fifo_segment_header_t * fsh)
{
  fsh->flags &= ~FIFO_SEGMENT_F_MEM_LIMIT;
}

uword
fifo_segment_free_bytes (fifo_segment_t * fs)
{
  return fsh_n_free_bytes (fs->h);
}

uword
fifo_segment_cached_bytes (fifo_segment_t * fs)
{
  return fsh_n_cached_bytes (fs->h);
}

uword
fifo_segment_available_bytes (fifo_segment_t * fs)
{
  return fsh_n_free_bytes (fs->h) + fsh_n_cached_bytes (fs->h);
}

uword
fifo_segment_fl_chunk_bytes (fifo_segment_t * fs)
{
  fifo_segment_header_t *fsh = fs->h;
  fifo_segment_slice_t *fss;
  uword n_bytes = 0;
  int slice_index;

  for (slice_index = 0; slice_index < fs->n_slices; slice_index++)
    {
      fss = fsh_slice_get (fsh, slice_index);
      n_bytes += fss_fl_chunk_bytes (fss);
    }

  return n_bytes;
}

u8
fifo_segment_has_fifos (fifo_segment_t * fs)
{
  return (fsh_n_active_fifos (fs->h) != 0);
}

svm_fifo_t *
fifo_segment_get_slice_fifo_list (fifo_segment_t * fs, u32 slice_index)
{
  fifo_segment_header_t *fsh = fs->h;
  fifo_segment_slice_t *fss;

  fss = fsh_slice_get (fsh, slice_index);
  return fss->fifos;
}

u8
fifo_segment_get_mem_usage (fifo_segment_t * fs)
{
  uword size, in_use;

  size = fifo_segment_size (fs);
  in_use =
    size - fifo_segment_free_bytes (fs) - fifo_segment_cached_bytes (fs);
  return (in_use * 100) / size;
}

fifo_segment_mem_status_t
fifo_segment_determine_status (fifo_segment_header_t * fsh, u8 usage)
{
  if (!fsh->high_watermark || !fsh->low_watermark)
    return MEMORY_PRESSURE_NO_PRESSURE;

  /* once the no-memory is detected, the status continues
   * until memory usage gets below the high watermark
   */
  if (fsh_has_reached_mem_limit (fsh))
    {
      if (usage >= fsh->high_watermark)
	return MEMORY_PRESSURE_NO_MEMORY;
      else
	fsh_reset_mem_limit (fsh);
    }

  if (usage >= fsh->high_watermark)
    return MEMORY_PRESSURE_HIGH_PRESSURE;

  else if (usage >= fsh->low_watermark)
    return MEMORY_PRESSURE_LOW_PRESSURE;

  return MEMORY_PRESSURE_NO_PRESSURE;
}

fifo_segment_mem_status_t
fifo_segment_get_mem_status (fifo_segment_t * fs)
{
  fifo_segment_header_t *fsh = fs->h;
  u8 usage = fifo_segment_get_mem_usage (fs);

  return fifo_segment_determine_status (fsh, usage);
}

u8 *
format_fifo_segment_type (u8 * s, va_list * args)
{
  fifo_segment_t *sp;
  sp = va_arg (*args, fifo_segment_t *);
  ssvm_segment_type_t st = ssvm_type (&sp->ssvm);

  if (st == SSVM_SEGMENT_PRIVATE)
    s = format (s, "%s", "private");
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
  u32 count, indent, active_fifos, free_fifos;
  fifo_segment_t *fs = va_arg (*args, fifo_segment_t *);
  int verbose __attribute__ ((unused)) = va_arg (*args, int);
  uword est_chunk_bytes, est_free_seg_bytes, free_chunks;
  uword chunk_bytes = 0, free_seg_bytes, chunk_size;
  uword tracked_cached_bytes;
  uword fifo_hdr = 0, reserved;
  fifo_segment_header_t *fsh;
  fifo_segment_slice_t *fss;
  svm_fifo_chunk_t *c;
  u32 slice_index;
  char *address;
  size_t size;
  int i;
  uword allocated, in_use, virt;
  f64 usage;
  fifo_segment_mem_status_t mem_st;

  indent = format_get_indent (s) + 2;

  if (fs == 0)
    {
      s = format (s, "%-20s%10s%15s%15s%15s%15s", "Name", "Type",
		  "HeapSize (M)", "ActiveFifos", "FreeFifos", "Address");
      return s;
    }

  fifo_segment_info (fs, &address, &size);
  active_fifos = fifo_segment_num_fifos (fs);
  free_fifos = fifo_segment_num_free_fifos (fs);

  s = format (s, "%-20v%10U%15llu%15u%15u%15llx", ssvm_name (&fs->ssvm),
	      format_fifo_segment_type, fs, size >> 20ULL, active_fifos,
	      free_fifos, address);

  if (!verbose)
    return s;

  fsh = fs->h;

  free_chunks = fifo_segment_num_free_chunks (fs, ~0);
  if (free_chunks)
    s =
      format (s, "\n\n%UFree/Allocated chunks by size:\n", format_white_space,
	      indent + 2);
  else
    s = format (s, "\n");

  for (slice_index = 0; slice_index < fs->n_slices; slice_index++)
    {
      fss = fsh_slice_get (fsh, slice_index);
      for (i = 0; i < vec_len (fss->free_chunks); i++)
	{
	  c = fss->free_chunks[i];
	  if (c == 0 && fss->num_chunks[i] == 0)
	    continue;
	  count = 0;
	  while (c)
	    {
	      c = c->next;
	      count++;
	    }

	  chunk_size = fs_freelist_index_to_size (i);
	  s = format (s, "%U%-5u kB: %u/%u\n", format_white_space, indent + 2,
		      chunk_size >> 10, count, fss->num_chunks[i]);

	  chunk_bytes += count * chunk_size;
	}
    }

  fifo_hdr = free_fifos * sizeof (svm_fifo_t);
  est_chunk_bytes = fifo_segment_fl_chunk_bytes (fs);
  est_free_seg_bytes = fifo_segment_free_bytes (fs);
  fifo_segment_update_free_bytes (fs);
  free_seg_bytes = fifo_segment_free_bytes (fs);
  tracked_cached_bytes = fifo_segment_cached_bytes (fs);
  allocated = fifo_segment_size (fs);
  in_use = fifo_segment_size (fs) - est_free_seg_bytes - tracked_cached_bytes;
  usage = (100.0 * in_use) / allocated;
  mem_st = fifo_segment_get_mem_status (fs);
  virt = fsh_virtual_mem (fsh);
  reserved = fsh->n_reserved_bytes;

  s = format (s, "\n%Useg free bytes: %U (%lu) estimated: %U (%lu) reserved:"
	      " %U (%lu)\n", format_white_space, indent + 2,
	      format_memory_size, free_seg_bytes, free_seg_bytes,
	      format_memory_size, est_free_seg_bytes, est_free_seg_bytes,
	      format_memory_size, reserved, reserved);
  s = format (s, "%Uchunk free bytes: %U (%lu) estimated: %U (%lu) tracked:"
	      " %U (%lu)\n", format_white_space, indent + 2,
	      format_memory_size, chunk_bytes, chunk_bytes,
	      format_memory_size, est_chunk_bytes, est_chunk_bytes,
	      format_memory_size, tracked_cached_bytes, tracked_cached_bytes);
  s = format (s, "%Ufifo active: %u hdr free bytes: %U (%u) \n",
	      format_white_space, indent + 2, fsh->n_active_fifos,
	      format_memory_size, fifo_hdr, fifo_hdr);
  s = format (s, "%Usegment usage: %.2f%% (%U / %U) virt: %U status: %s\n",
	      format_white_space, indent + 2, usage, format_memory_size,
	      in_use, format_memory_size, allocated, format_memory_size, virt,
	      fifo_segment_mem_status_strings[mem_st]);
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
