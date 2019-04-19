/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
 * Copyright (c) 2019 Arm Limited
 * Copyright (c) 2010-2017 Intel Corporation and/or its affiliates.
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * Inspired from DPDK rte_ring.h (SPSC only) (derived from freebsd bufring.h).
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

#include <svm/svm_fifo.h>

u8 *
format_ooo_segment (u8 * s, va_list * args)
{
  svm_fifo_t *f = va_arg (*args, svm_fifo_t *);
  ooo_segment_t *seg = va_arg (*args, ooo_segment_t *);
  u32 normalized_start = (seg->start + f->nitems - f->tail) % f->size;
  s = format (s, "[%u, %u], len %u, next %d, prev %d", normalized_start,
	      (normalized_start + seg->length) % f->size, seg->length,
	      seg->next, seg->prev);
  return s;
}

u8 *
svm_fifo_dump_trace (u8 * s, svm_fifo_t * f)
{
#if SVM_FIFO_TRACE
  svm_fifo_trace_elem_t *seg = 0;
  int i = 0;

  if (f->trace)
    {
      vec_foreach (seg, f->trace)
      {
	s = format (s, "{%u, %u, %u}, ", seg->offset, seg->len, seg->action);
	i++;
	if (i % 5 == 0)
	  s = format (s, "\n");
      }
      s = format (s, "\n");
    }
  return s;
#else
  return 0;
#endif
}

u8 *
svm_fifo_replay (u8 * s, svm_fifo_t * f, u8 no_read, u8 verbose)
{
  int i, trace_len;
  u8 *data = 0;
  svm_fifo_trace_elem_t *trace;
  u32 offset;
  svm_fifo_t *dummy_fifo;

  if (!f)
    return s;

#if SVM_FIFO_TRACE
  trace = f->trace;
  trace_len = vec_len (trace);
#else
  trace = 0;
  trace_len = 0;
#endif

  dummy_fifo = svm_fifo_create (f->size);
  clib_memset (f->head_chunk->data, 0xFF, f->nitems);
  vec_validate (data, f->nitems);
  for (i = 0; i < vec_len (data); i++)
    data[i] = i;

  for (i = 0; i < trace_len; i++)
    {
      offset = trace[i].offset;
      if (trace[i].action == 1)
	{
	  if (verbose)
	    s = format (s, "adding [%u, %u]:", trace[i].offset,
			(trace[i].offset + trace[i].len) % dummy_fifo->size);
	  svm_fifo_enqueue_with_offset (dummy_fifo, trace[i].offset,
					trace[i].len, &data[offset]);
	}
      else if (trace[i].action == 2)
	{
	  if (verbose)
	    s = format (s, "adding [%u, %u]:", 0, trace[i].len);
	  svm_fifo_enqueue_nowait (dummy_fifo, trace[i].len, &data[offset]);
	}
      else if (!no_read)
	{
	  if (verbose)
	    s = format (s, "read: %u", trace[i].len);
	  svm_fifo_dequeue_drop (dummy_fifo, trace[i].len);
	}
      if (verbose)
	s = format (s, "%U", format_svm_fifo, dummy_fifo, 1);
    }

  s = format (s, "result: %U", format_svm_fifo, dummy_fifo, 1);

  return s;
}

u8 *
format_ooo_list (u8 * s, va_list * args)
{
  svm_fifo_t *f = va_arg (*args, svm_fifo_t *);
  u32 indent = va_arg (*args, u32);
  u32 ooo_segment_index = f->ooos_list_head;
  ooo_segment_t *seg;

  while (ooo_segment_index != OOO_SEGMENT_INVALID_INDEX)
    {
      seg = pool_elt_at_index (f->ooo_segments, ooo_segment_index);
      s = format (s, "%U%U\n", format_white_space, indent, format_ooo_segment,
		  f, seg);
      ooo_segment_index = seg->next;
    }

  return s;
}

u8 *
format_svm_fifo (u8 * s, va_list * args)
{
  svm_fifo_t *f = va_arg (*args, svm_fifo_t *);
  int verbose = va_arg (*args, int);
  u32 indent;

  if (!s)
    return s;

  indent = format_get_indent (s);
  s = format (s, "cursize %u nitems %u has_event %d\n",
	      svm_fifo_max_dequeue (f), f->nitems, f->has_event);
  s = format (s, "%Uhead %u tail %u segment manager %u\n", format_white_space,
	      indent, (f->head % f->size), (f->tail % f->size),
	      f->segment_manager);

  if (verbose > 1)
    s = format (s, "%Uvpp session %d thread %d app session %d thread %d\n",
		format_white_space, indent, f->master_session_index,
		f->master_thread_index, f->client_session_index,
		f->client_thread_index);

  if (verbose)
    {
      s = format (s, "%Uooo pool %d active elts newest %u\n",
		  format_white_space, indent, pool_elts (f->ooo_segments),
		  f->ooos_newest);
      if (svm_fifo_has_ooo_data (f))
	s = format (s, " %U", format_ooo_list, f, indent, verbose);
    }
  return s;
}

void
svm_fifo_init (svm_fifo_t * f, u32 size)
{
  f->size = size;
  /*
   * usable size of the fifo set to rounded_data_size - 1
   * to differentiate between free fifo and empty fifo.
   */
  f->nitems = f->size - 1;
  f->ooos_list_head = OOO_SEGMENT_INVALID_INDEX;
  f->ct_session_index = SVM_FIFO_INVALID_SESSION_INDEX;
  f->segment_index = SVM_FIFO_INVALID_INDEX;
  f->refcnt = 1;
  f->default_chunk.start_byte = 0;
  f->default_chunk.length = f->size;
  f->default_chunk.next = f->start_chunk = &f->default_chunk;
  f->end_chunk = f->head_chunk = f->tail_chunk = f->start_chunk;
}

/** create an svm fifo, in the current heap. Fails vs blow up the process */
svm_fifo_t *
svm_fifo_create (u32 data_size_in_bytes)
{
  svm_fifo_t *f;
  u32 rounded_data_size;

  /* always round fifo data size to the next highest power-of-two */
  rounded_data_size = (1 << (max_log2 (data_size_in_bytes)));
  f = clib_mem_alloc_aligned_or_null (sizeof (*f) + rounded_data_size,
				      CLIB_CACHE_LINE_BYTES);
  if (f == 0)
    return 0;

  clib_memset (f, 0, sizeof (*f));
  svm_fifo_init (f, data_size_in_bytes);
  return f;
}

void
svm_fifo_free (svm_fifo_t * f)
{
  ASSERT (f->refcnt > 0);

  if (--f->refcnt == 0)
    {
      pool_free (f->ooo_segments);
      clib_mem_free (f);
    }
}

void
svm_fifo_overwrite_head (svm_fifo_t * f, u8 * data, u32 len)
{
  u32 n_chunk;
  u32 head, tail, head_idx;
  svm_fifo_chunk_t *c;

  ASSERT (len <= f->nitems);

  f_load_head_tail_cons (f, &head, &tail);
  c = f->head_chunk;
  head_idx = head % f->size;
  head_idx -= c->start_byte;
  n_chunk = c->length - head_idx;
  if (len <= n_chunk)
    clib_memcpy_fast (&c->data[head_idx], data, len);
  else
    {
      clib_memcpy_fast (&c->data[head_idx], data, n_chunk);
      clib_memcpy_fast (&c->next->data[0], data + n_chunk, len - n_chunk);
    }
}

int
svm_fifo_dequeue_drop (svm_fifo_t * f, u32 max_bytes)
{
  u32 total_drop_bytes;
  u32 tail, head, cursize;

  f_load_head_tail_cons (f, &head, &tail);

  /* number of bytes we're going to drop */
  cursize = f_cursize (f, head, tail);

  if (PREDICT_FALSE (cursize == 0))
    return -2;			/* nothing in the fifo */

  svm_fifo_trace_add (f, tail, total_drop_bytes, 3);

  /* number of bytes we're going to drop */
  total_drop_bytes = (cursize < max_bytes) ? cursize : max_bytes;

  /* move head */
  head += total_drop_bytes;

  ASSERT (cursize >= total_drop_bytes);
  /* store-rel: consumer owned index (paired with load-acq in producer) */
  clib_atomic_store_rel_n (&f->head, head);

  return total_drop_bytes;
}

void
svm_fifo_dequeue_drop_all (svm_fifo_t * f)
{
  /* consumer foreign index */
  u32 tail = clib_atomic_load_acq_n (&f->tail);
  /* store-rel: consumer owned index (paired with load-acq in producer) */
  clib_atomic_store_rel_n (&f->head, tail);
}

int
svm_fifo_segments (svm_fifo_t * f, svm_fifo_segment_t * fs)
{
  u32 cursize, head, tail, head_idx;

  f_load_head_tail_cons (f, &head, &tail);

  /* consumer function, cursize can only increase while we're working */
  cursize = f_cursize (f, head, tail);

  if (PREDICT_FALSE (cursize == 0))
    return -2;			/* nothing in the fifo */

  head_idx = head % f->size;

  if (tail < head)
    {
      fs[0].len = f->size - head_idx;
      fs[0].data = f->head_chunk->data + head_idx;
      fs[1].len = cursize - fs[0].len;
      fs[1].data = f->head_chunk->data;
    }
  else
    {
      fs[0].len = cursize;
      fs[0].data = f->head_chunk->data + head_idx;
      fs[1].len = 0;
      fs[1].data = 0;
    }
  return cursize;
}

void
svm_fifo_segments_free (svm_fifo_t * f, svm_fifo_segment_t * fs)
{
  u32 head, head_idx;

  /* consumer owned index */
  head = f->head;
  head_idx = head % f->size;

  ASSERT (fs[0].data == f->head_chunk->data + head_idx);
  head += fs[0].len + fs[1].len;
  /* store-rel: consumer owned index (paired with load-acq in producer) */
  clib_atomic_store_rel_n (&f->head, head);
}

/* Assumption: no prod and cons are accessing either dest or src fifo */
void
svm_fifo_clone (svm_fifo_t * df, svm_fifo_t * sf)
{
  u32 head, tail;
  clib_memcpy_fast (df->head_chunk->data, sf->head_chunk->data, sf->size);

  f_load_head_tail_all_acq (sf, &head, &tail);
  clib_atomic_store_rel_n (&df->head, head);
  clib_atomic_store_rel_n (&df->tail, tail);
}

u32
svm_fifo_number_ooo_segments (svm_fifo_t * f)
{
  return pool_elts (f->ooo_segments);
}

ooo_segment_t *
svm_fifo_first_ooo_segment (svm_fifo_t * f)
{
  return pool_elt_at_index (f->ooo_segments, f->ooos_list_head);
}

/**
 * Set fifo pointers to requested offset
 */
void
svm_fifo_init_pointers (svm_fifo_t * f, u32 pointer)
{
  clib_atomic_store_rel_n (&f->head, pointer);
  clib_atomic_store_rel_n (&f->tail, pointer);
}

void
svm_fifo_add_subscriber (svm_fifo_t * f, u8 subscriber)
{
  if (f->n_subscribers >= SVM_FIFO_MAX_EVT_SUBSCRIBERS)
    return;
  f->subscribers[f->n_subscribers++] = subscriber;
}

void
svm_fifo_del_subscriber (svm_fifo_t * f, u8 subscriber)
{
  int i;

  for (i = 0; i < f->n_subscribers; i++)
    {
      if (f->subscribers[i] != subscriber)
	continue;
      f->subscribers[i] = f->subscribers[f->n_subscribers - 1];
      f->n_subscribers--;
      break;
    }
}

static inline void
svm_fifo_size_update (svm_fifo_t * f, svm_fifo_chunk_t * c)
{
  svm_fifo_chunk_t *prev;
  u32 add_bytes = 0;

  prev = f->end_chunk;
  while (c)
    {
      c->start_byte = prev->start_byte + prev->length;
      add_bytes += c->length;
      prev->next = c;
      prev = c;
      c = c->next;
    }
  f->end_chunk = prev;
  prev->next = f->start_chunk;
  f->size += add_bytes;
  f->nitems = f->size - 1;
  f->new_chunks = 0;
}

void
svm_fifo_try_size_update (svm_fifo_t * f, u32 new_head)
{
  if (new_head % f->size > f->tail % f->size)
    return;

  svm_fifo_size_update (f, f->new_chunks);
  f->flags &= ~SVM_FIFO_F_SIZE_UPDATE;
}

void
svm_fifo_add_chunk (svm_fifo_t * f, svm_fifo_chunk_t * c)
{
  if (svm_fifo_is_wrapped (f))
    {
      if (f->new_chunks)
	{
	  svm_fifo_chunk_t *prev;

	  prev = f->new_chunks;
	  while (prev->next)
	    prev = prev->next;
	  prev->next = c;
	}
      else
	{
	  f->new_chunks = c;
	}
      f->flags |= SVM_FIFO_F_SIZE_UPDATE;
      return;
    }

  svm_fifo_size_update (f, c);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
