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

#include <svm/svm_fifo.h>
#include <vppinfra/cpu.h>

static inline u8
position_lt (svm_fifo_t * f, u32 a, u32 b)
{
  return (ooo_segment_distance_from_tail (f, a)
	  < ooo_segment_distance_from_tail (f, b));
}

static inline u8
position_leq (svm_fifo_t * f, u32 a, u32 b)
{
  return (ooo_segment_distance_from_tail (f, a)
	  <= ooo_segment_distance_from_tail (f, b));
}

static inline u8
position_gt (svm_fifo_t * f, u32 a, u32 b)
{
  return (ooo_segment_distance_from_tail (f, a)
	  > ooo_segment_distance_from_tail (f, b));
}

static inline u32
position_diff (svm_fifo_t * f, u32 posa, u32 posb)
{
  return ooo_segment_distance_from_tail (f, posa)
    - ooo_segment_distance_from_tail (f, posb);
}

static inline u32
ooo_segment_end_pos (svm_fifo_t * f, ooo_segment_t * s)
{
  return (s->start + s->length) % f->nitems;
}

#ifndef CLIB_MARCH_VARIANT

u8 *
format_ooo_segment (u8 * s, va_list * args)
{
  svm_fifo_t *f = va_arg (*args, svm_fifo_t *);
  ooo_segment_t *seg = va_arg (*args, ooo_segment_t *);
  u32 normalized_start = (seg->start + f->nitems - f->tail) % f->nitems;
  s = format (s, "[%u, %u], len %u, next %d, prev %d", normalized_start,
	      (normalized_start + seg->length) % f->nitems, seg->length,
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

  dummy_fifo = svm_fifo_create (f->nitems);
  clib_memset (f->data, 0xFF, f->nitems);

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
			(trace[i].offset +
			 trace[i].len) % dummy_fifo->nitems);
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
  u32 ooo_segment_index = f->ooos_list_head;
  ooo_segment_t *seg;

  while (ooo_segment_index != OOO_SEGMENT_INVALID_INDEX)
    {
      seg = pool_elt_at_index (f->ooo_segments, ooo_segment_index);
      s = format (s, "  %U\n", format_ooo_segment, f, seg);
      ooo_segment_index = seg->next;
    }

  return s;
}

u8 *
format_svm_fifo (u8 * s, va_list * args)
{
  svm_fifo_t *f = va_arg (*args, svm_fifo_t *);
  int verbose = va_arg (*args, int);

  if (!s)
    return s;

  s = format (s, "cursize %u nitems %u has_event %d\n",
	      f->cursize, f->nitems, f->has_event);
  s = format (s, " head %d tail %d segment manager %u\n", f->head, f->tail,
	      f->segment_manager);

  if (verbose > 1)
    s = format
      (s, " vpp session %d thread %d app session %d thread %d\n",
       f->master_session_index, f->master_thread_index,
       f->client_session_index, f->client_thread_index);

  if (verbose)
    {
      s = format (s, " ooo pool %d active elts newest %u\n",
		  pool_elts (f->ooo_segments), f->ooos_newest);
      if (svm_fifo_has_ooo_data (f))
	s = format (s, " %U", format_ooo_list, f, verbose);
    }
  return s;
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
  f->nitems = data_size_in_bytes;
  f->ooos_list_head = OOO_SEGMENT_INVALID_INDEX;
  f->ct_session_index = SVM_FIFO_INVALID_SESSION_INDEX;
  f->refcnt = 1;
  return (f);
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
#endif

always_inline ooo_segment_t *
ooo_segment_new (svm_fifo_t * f, u32 start, u32 length)
{
  ooo_segment_t *s;

  pool_get (f->ooo_segments, s);

  s->start = start;
  s->length = length;

  s->prev = s->next = OOO_SEGMENT_INVALID_INDEX;

  return s;
}

always_inline void
ooo_segment_del (svm_fifo_t * f, u32 index)
{
  ooo_segment_t *cur, *prev = 0, *next = 0;
  cur = pool_elt_at_index (f->ooo_segments, index);

  if (cur->next != OOO_SEGMENT_INVALID_INDEX)
    {
      next = pool_elt_at_index (f->ooo_segments, cur->next);
      next->prev = cur->prev;
    }

  if (cur->prev != OOO_SEGMENT_INVALID_INDEX)
    {
      prev = pool_elt_at_index (f->ooo_segments, cur->prev);
      prev->next = cur->next;
    }
  else
    {
      f->ooos_list_head = cur->next;
    }

  pool_put (f->ooo_segments, cur);
}

/**
 * Add segment to fifo's out-of-order segment list. Takes care of merging
 * adjacent segments and removing overlapping ones.
 */
static void
ooo_segment_add (svm_fifo_t * f, u32 offset, u32 length)
{
  ooo_segment_t *s, *new_s, *prev, *next, *it;
  u32 new_index, s_end_pos, s_index;
  u32 normalized_position, normalized_end_position;

  ASSERT (offset + length <= ooo_segment_distance_from_tail (f, f->head));
  normalized_position = (f->tail + offset) % f->nitems;
  normalized_end_position = (f->tail + offset + length) % f->nitems;

  f->ooos_newest = OOO_SEGMENT_INVALID_INDEX;

  if (f->ooos_list_head == OOO_SEGMENT_INVALID_INDEX)
    {
      s = ooo_segment_new (f, normalized_position, length);
      f->ooos_list_head = s - f->ooo_segments;
      f->ooos_newest = f->ooos_list_head;
      return;
    }

  /* Find first segment that starts after new segment */
  s = pool_elt_at_index (f->ooo_segments, f->ooos_list_head);
  while (s->next != OOO_SEGMENT_INVALID_INDEX
	 && position_lt (f, s->start, normalized_position))
    s = pool_elt_at_index (f->ooo_segments, s->next);

  /* If we have a previous and we overlap it, use it as starting point */
  prev = ooo_segment_get_prev (f, s);
  if (prev
      && position_leq (f, normalized_position, ooo_segment_end_pos (f, prev)))
    {
      s = prev;
      s_end_pos = ooo_segment_end_pos (f, s);

      /* Since we have previous, normalized start position cannot be smaller
       * than prev->start. Check tail */
      ASSERT (position_lt (f, s->start, normalized_position));
      goto check_tail;
    }

  s_index = s - f->ooo_segments;
  s_end_pos = ooo_segment_end_pos (f, s);

  /* No overlap, add before current segment */
  if (position_lt (f, normalized_end_position, s->start))
    {
      new_s = ooo_segment_new (f, normalized_position, length);
      new_index = new_s - f->ooo_segments;

      /* Pool might've moved, get segment again */
      s = pool_elt_at_index (f->ooo_segments, s_index);
      if (s->prev != OOO_SEGMENT_INVALID_INDEX)
	{
	  new_s->prev = s->prev;
	  prev = pool_elt_at_index (f->ooo_segments, new_s->prev);
	  prev->next = new_index;
	}
      else
	{
	  /* New head */
	  f->ooos_list_head = new_index;
	}

      new_s->next = s_index;
      s->prev = new_index;
      f->ooos_newest = new_index;
      return;
    }
  /* No overlap, add after current segment */
  else if (position_gt (f, normalized_position, s_end_pos))
    {
      new_s = ooo_segment_new (f, normalized_position, length);
      new_index = new_s - f->ooo_segments;

      /* Pool might've moved, get segment again */
      s = pool_elt_at_index (f->ooo_segments, s_index);

      /* Needs to be last */
      ASSERT (s->next == OOO_SEGMENT_INVALID_INDEX);

      new_s->prev = s_index;
      s->next = new_index;
      f->ooos_newest = new_index;

      return;
    }

  /*
   * Merge needed
   */

  /* Merge at head */
  if (position_lt (f, normalized_position, s->start))
    {
      s->start = normalized_position;
      s->length = position_diff (f, s_end_pos, s->start);
      f->ooos_newest = s - f->ooo_segments;
    }

check_tail:

  /* Overlapping tail */
  if (position_gt (f, normalized_end_position, s_end_pos))
    {
      s->length = position_diff (f, normalized_end_position, s->start);

      /* Remove the completely overlapped segments in the tail */
      it = ooo_segment_next (f, s);
      while (it && position_leq (f, ooo_segment_end_pos (f, it),
				 normalized_end_position))
	{
	  next = ooo_segment_next (f, it);
	  ooo_segment_del (f, it - f->ooo_segments);
	  it = next;
	}

      /* If partial overlap with last, merge */
      if (it && position_leq (f, it->start, normalized_end_position))
	{
	  s->length = position_diff (f, ooo_segment_end_pos (f, it),
				     s->start);
	  ooo_segment_del (f, it - f->ooo_segments);
	}
      f->ooos_newest = s - f->ooo_segments;
    }
}

/**
 * Removes segments that can now be enqueued because the fifo's tail has
 * advanced. Returns the number of bytes added to tail.
 */
static int
ooo_segment_try_collect (svm_fifo_t * f, u32 n_bytes_enqueued)
{
  ooo_segment_t *s;
  u32 index, bytes = 0;
  i32 diff;

  s = pool_elt_at_index (f->ooo_segments, f->ooos_list_head);
  diff = ooo_segment_distance_to_tail (f, s->start);

  ASSERT (diff != n_bytes_enqueued);

  if (diff > n_bytes_enqueued)
    return 0;

  /* If last tail update overlaps one/multiple ooo segments, remove them */
  while (0 <= diff && diff < n_bytes_enqueued)
    {
      index = s - f->ooo_segments;

      /* Segment end is beyond the tail. Advance tail and remove segment */
      if (s->length > diff)
	{
	  bytes = s->length - diff;
	  f->tail += bytes;
	  f->tail %= f->nitems;
	  ooo_segment_del (f, index);
	  break;
	}

      /* If we have next go on */
      if (s->next != OOO_SEGMENT_INVALID_INDEX)
	{
	  s = pool_elt_at_index (f->ooo_segments, s->next);
	  diff = ooo_segment_distance_to_tail (f, s->start);
	  ooo_segment_del (f, index);
	}
      /* End of search */
      else
	{
	  ooo_segment_del (f, index);
	  break;
	}
    }

  ASSERT (bytes <= f->nitems);
  return bytes;
}

CLIB_MARCH_FN (svm_fifo_enqueue_nowait, int, svm_fifo_t * f, u32 max_bytes,
	       const u8 * copy_from_here)
{
  u32 total_copy_bytes, first_copy_bytes, second_copy_bytes;
  u32 cursize, nitems;

  /* read cursize, which can only increase while we're working */
  cursize = svm_fifo_max_dequeue (f);
  f->ooos_newest = OOO_SEGMENT_INVALID_INDEX;

  if (PREDICT_FALSE (cursize == f->nitems))
    return SVM_FIFO_FULL;

  nitems = f->nitems;

  /* Number of bytes we're going to copy */
  total_copy_bytes = (nitems - cursize) < max_bytes ?
    (nitems - cursize) : max_bytes;

  if (PREDICT_TRUE (copy_from_here != 0))
    {
      /* Number of bytes in first copy segment */
      first_copy_bytes = ((nitems - f->tail) < total_copy_bytes)
	? (nitems - f->tail) : total_copy_bytes;

      _clib_memcpy (&f->data[f->tail], copy_from_here, first_copy_bytes);
      f->tail += first_copy_bytes;
      f->tail = (f->tail == nitems) ? 0 : f->tail;

      /* Number of bytes in second copy segment, if any */
      second_copy_bytes = total_copy_bytes - first_copy_bytes;
      if (second_copy_bytes)
	{
	  _clib_memcpy (&f->data[f->tail], copy_from_here + first_copy_bytes,
			second_copy_bytes);
	  f->tail += second_copy_bytes;
	  f->tail = (f->tail == nitems) ? 0 : f->tail;
	}
    }
  else
    {
      ASSERT (0);

      /* Account for a zero-copy enqueue done elsewhere */
      ASSERT (max_bytes <= (nitems - cursize));
      f->tail += max_bytes;
      f->tail = f->tail % nitems;
      total_copy_bytes = max_bytes;
    }

  svm_fifo_trace_add (f, f->head, total_copy_bytes, 2);

  /* Any out-of-order segments to collect? */
  if (PREDICT_FALSE (f->ooos_list_head != OOO_SEGMENT_INVALID_INDEX))
    total_copy_bytes += ooo_segment_try_collect (f, total_copy_bytes);

  /* Atomically increase the queue length */
  ASSERT (cursize + total_copy_bytes <= nitems);
  clib_atomic_fetch_add (&f->cursize, total_copy_bytes);

  return (total_copy_bytes);
}

#ifndef CLIB_MARCH_VARIANT
int
svm_fifo_enqueue_nowait (svm_fifo_t * f, u32 max_bytes,
			 const u8 * copy_from_here)
{
  return CLIB_MARCH_FN_SELECT (svm_fifo_enqueue_nowait) (f, max_bytes,
							 copy_from_here);
}
#endif

/**
 * Enqueue a future segment.
 *
 * Two choices: either copies the entire segment, or copies nothing
 * Returns 0 of the entire segment was copied
 * Returns -1 if none of the segment was copied due to lack of space
 */
CLIB_MARCH_FN (svm_fifo_enqueue_with_offset, int, svm_fifo_t * f,
	       u32 offset, u32 required_bytes, u8 * copy_from_here)
{
  u32 total_copy_bytes, first_copy_bytes, second_copy_bytes;
  u32 cursize, nitems, normalized_offset;

  f->ooos_newest = OOO_SEGMENT_INVALID_INDEX;

  /* read cursize, which can only increase while we're working */
  cursize = svm_fifo_max_dequeue (f);
  nitems = f->nitems;

  ASSERT (required_bytes < nitems);

  normalized_offset = (f->tail + offset) % nitems;

  /* Will this request fit? */
  if ((required_bytes + offset) > (nitems - cursize))
    return -1;

  svm_fifo_trace_add (f, offset, required_bytes, 1);

  ooo_segment_add (f, offset, required_bytes);

  /* Number of bytes we're going to copy */
  total_copy_bytes = required_bytes;

  /* Number of bytes in first copy segment */
  first_copy_bytes = ((nitems - normalized_offset) < total_copy_bytes)
    ? (nitems - normalized_offset) : total_copy_bytes;

  _clib_memcpy (&f->data[normalized_offset], copy_from_here,
		first_copy_bytes);

  /* Number of bytes in second copy segment, if any */
  second_copy_bytes = total_copy_bytes - first_copy_bytes;
  if (second_copy_bytes)
    {
      normalized_offset += first_copy_bytes;
      normalized_offset %= nitems;

      ASSERT (normalized_offset == 0);

      _clib_memcpy (&f->data[normalized_offset],
		    copy_from_here + first_copy_bytes, second_copy_bytes);
    }

  return (0);
}

#ifndef CLIB_MARCH_VARIANT

int
svm_fifo_enqueue_with_offset (svm_fifo_t * f, u32 offset, u32 required_bytes,
			      u8 * copy_from_here)
{
  return CLIB_MARCH_FN_SELECT (svm_fifo_enqueue_with_offset) (f, offset,
							      required_bytes,
							      copy_from_here);
}

void
svm_fifo_overwrite_head (svm_fifo_t * f, u8 * data, u32 len)
{
  u32 first_chunk;
  first_chunk = f->nitems - f->head;
  ASSERT (len <= f->nitems);
  if (len <= first_chunk)
    _clib_memcpy (&f->data[f->head], data, len);
  else
    {
      _clib_memcpy (&f->data[f->head], data, first_chunk);
      _clib_memcpy (&f->data[0], data + first_chunk, len - first_chunk);
    }
}
#endif

CLIB_MARCH_FN (svm_fifo_dequeue_nowait, int, svm_fifo_t * f, u32 max_bytes,
	       u8 * copy_here)
{
  u32 total_copy_bytes, first_copy_bytes, second_copy_bytes;
  u32 cursize, nitems;

  /* read cursize, which can only increase while we're working */
  cursize = svm_fifo_max_dequeue (f);
  if (PREDICT_FALSE (cursize == 0))
    return -2;			/* nothing in the fifo */

  nitems = f->nitems;

  /* Number of bytes we're going to copy */
  total_copy_bytes = (cursize < max_bytes) ? cursize : max_bytes;

  if (PREDICT_TRUE (copy_here != 0))
    {
      /* Number of bytes in first copy segment */
      first_copy_bytes = ((nitems - f->head) < total_copy_bytes)
	? (nitems - f->head) : total_copy_bytes;
      _clib_memcpy (copy_here, &f->data[f->head], first_copy_bytes);
      f->head += first_copy_bytes;
      f->head = (f->head == nitems) ? 0 : f->head;

      /* Number of bytes in second copy segment, if any */
      second_copy_bytes = total_copy_bytes - first_copy_bytes;
      if (second_copy_bytes)
	{
	  _clib_memcpy (copy_here + first_copy_bytes,
			&f->data[f->head], second_copy_bytes);
	  f->head += second_copy_bytes;
	  f->head = (f->head == nitems) ? 0 : f->head;
	}
    }
  else
    {
      ASSERT (0);
      /* Account for a zero-copy dequeue done elsewhere */
      ASSERT (max_bytes <= cursize);
      f->head += max_bytes;
      f->head = f->head % nitems;
      cursize -= max_bytes;
      total_copy_bytes = max_bytes;
    }

  ASSERT (f->head <= nitems);
  ASSERT (cursize >= total_copy_bytes);
  clib_atomic_fetch_sub (&f->cursize, total_copy_bytes);

  return (total_copy_bytes);
}

#ifndef CLIB_MARCH_VARIANT

int
svm_fifo_dequeue_nowait (svm_fifo_t * f, u32 max_bytes, u8 * copy_here)
{
  return CLIB_MARCH_FN_SELECT (svm_fifo_dequeue_nowait) (f, max_bytes,
							 copy_here);
}
#endif

CLIB_MARCH_FN (svm_fifo_peek, int, svm_fifo_t * f, u32 relative_offset,
	       u32 max_bytes, u8 * copy_here)
{
  u32 total_copy_bytes, first_copy_bytes, second_copy_bytes;
  u32 cursize, nitems, real_head;

  /* read cursize, which can only increase while we're working */
  cursize = svm_fifo_max_dequeue (f);
  if (PREDICT_FALSE (cursize < relative_offset))
    return -2;			/* nothing in the fifo */

  nitems = f->nitems;
  real_head = f->head + relative_offset;
  real_head = real_head >= nitems ? real_head - nitems : real_head;

  /* Number of bytes we're going to copy */
  total_copy_bytes = (cursize - relative_offset < max_bytes) ?
    cursize - relative_offset : max_bytes;

  if (PREDICT_TRUE (copy_here != 0))
    {
      /* Number of bytes in first copy segment */
      first_copy_bytes =
	((nitems - real_head) < total_copy_bytes) ?
	(nitems - real_head) : total_copy_bytes;
      _clib_memcpy (copy_here, &f->data[real_head], first_copy_bytes);

      /* Number of bytes in second copy segment, if any */
      second_copy_bytes = total_copy_bytes - first_copy_bytes;
      if (second_copy_bytes)
	{
	  _clib_memcpy (copy_here + first_copy_bytes, &f->data[0],
			second_copy_bytes);
	}
    }
  return total_copy_bytes;
}

#ifndef CLIB_MARCH_VARIANT

int
svm_fifo_peek (svm_fifo_t * f, u32 relative_offset, u32 max_bytes,
	       u8 * copy_here)
{
  return CLIB_MARCH_FN_SELECT (svm_fifo_peek) (f, relative_offset, max_bytes,
					       copy_here);
}

int
svm_fifo_dequeue_drop (svm_fifo_t * f, u32 max_bytes)
{
  u32 total_drop_bytes, first_drop_bytes, second_drop_bytes;
  u32 cursize, nitems;

  /* read cursize, which can only increase while we're working */
  cursize = svm_fifo_max_dequeue (f);
  if (PREDICT_FALSE (cursize == 0))
    return -2;			/* nothing in the fifo */

  nitems = f->nitems;

  /* Number of bytes we're going to drop */
  total_drop_bytes = (cursize < max_bytes) ? cursize : max_bytes;

  svm_fifo_trace_add (f, f->tail, total_drop_bytes, 3);

  /* Number of bytes in first copy segment */
  first_drop_bytes =
    ((nitems - f->head) < total_drop_bytes) ?
    (nitems - f->head) : total_drop_bytes;
  f->head += first_drop_bytes;
  f->head = (f->head == nitems) ? 0 : f->head;

  /* Number of bytes in second drop segment, if any */
  second_drop_bytes = total_drop_bytes - first_drop_bytes;
  if (second_drop_bytes)
    {
      f->head += second_drop_bytes;
      f->head = (f->head == nitems) ? 0 : f->head;
    }

  ASSERT (f->head <= nitems);
  ASSERT (cursize >= total_drop_bytes);
  clib_atomic_fetch_sub (&f->cursize, total_drop_bytes);

  return total_drop_bytes;
}

void
svm_fifo_dequeue_drop_all (svm_fifo_t * f)
{
  f->head = f->tail;
  clib_atomic_fetch_sub (&f->cursize, f->cursize);
}

int
svm_fifo_segments (svm_fifo_t * f, svm_fifo_segment_t * fs)
{
  u32 cursize, nitems;

  /* read cursize, which can only increase while we're working */
  cursize = svm_fifo_max_dequeue (f);
  if (PREDICT_FALSE (cursize == 0))
    return -2;

  nitems = f->nitems;

  fs[0].len = ((nitems - f->head) < cursize) ? (nitems - f->head) : cursize;
  fs[0].data = f->data + f->head;

  if (fs[0].len < cursize)
    {
      fs[1].len = cursize - fs[0].len;
      fs[1].data = f->data;
    }
  else
    {
      fs[1].len = 0;
      fs[1].data = 0;
    }
  return cursize;
}

void
svm_fifo_segments_free (svm_fifo_t * f, svm_fifo_segment_t * fs)
{
  u32 total_drop_bytes;

  ASSERT (fs[0].data == f->data + f->head);
  if (fs[1].len)
    {
      f->head = fs[1].len;
      total_drop_bytes = fs[0].len + fs[1].len;
    }
  else
    {
      f->head = (f->head + fs[0].len) % f->nitems;
      total_drop_bytes = fs[0].len;
    }
  clib_atomic_fetch_sub (&f->cursize, total_drop_bytes);
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
  f->head = f->tail = pointer % f->nitems;
}

#endif
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
