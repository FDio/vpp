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

#define offset_lt(_a, _b) ((i32)((_a)-(_b)) < 0)
#define offset_leq(_a, _b) ((i32)((_a)-(_b)) <= 0)
#define offset_gt(_a, _b) ((i32)((_a)-(_b)) > 0)
#define offset_geq(_a, _b) ((i32)((_a)-(_b)) >= 0)

u8 *
format_ooo_segment (u8 * s, va_list * args)
{
  ooo_segment_t *seg = va_arg (*args, ooo_segment_t *);

  s = format (s, "pos %u, len %u, next %d, prev %d",
	      seg->start, seg->length, seg->next, seg->prev);
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
      s = format (s, "  %U\n", format_ooo_segment, seg);
      ooo_segment_index = seg->next;
    }
  return s;
}

u8 *
format_svm_fifo (u8 * s, va_list * args)
{
  svm_fifo_t *f = va_arg (*args, svm_fifo_t *);
  int verbose = va_arg (*args, int);

  s = format (s, "cursize %u nitems %u has_event %d\n",
	      f->cursize, f->nitems, f->has_event);
  s = format (s, " head %d tail %d\n", f->head, f->tail);

  if (verbose > 1)
    s = format
      (s, " server session %d thread %d client session %d thread %d\n",
       f->master_session_index, f->master_thread_index,
       f->client_session_index, f->client_thread_index);

  if (verbose)
    {
      s = format (s, " ooo pool %d active elts\n",
		  pool_elts (f->ooo_segments));
      if (svm_fifo_has_ooo_data (f))
	s = format (s, " %U", format_ooo_list, f);
    }
  return s;
}

/** create an svm fifo, in the current heap. Fails vs blow up the process */
svm_fifo_t *
svm_fifo_create (u32 data_size_in_bytes)
{
  svm_fifo_t *f;

  f = clib_mem_alloc_aligned_or_null (sizeof (*f) + data_size_in_bytes,
				      CLIB_CACHE_LINE_BYTES);
  if (f == 0)
    return 0;

  memset (f, 0, sizeof (*f) + data_size_in_bytes);
  f->nitems = data_size_in_bytes;
  f->ooos_list_head = OOO_SEGMENT_INVALID_INDEX;

  return (f);
}

void
svm_fifo_free (svm_fifo_t * f)
{
  pool_free (f->ooo_segments);
  clib_mem_free (f);
}

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
  u32 new_index, end_offset, s_sof, s_eof, s_index;

  end_offset = offset + length;

  if (f->ooos_list_head == OOO_SEGMENT_INVALID_INDEX)
    {
      s = ooo_segment_new (f, offset, length);
      f->ooos_list_head = s - f->ooo_segments;
      f->ooos_newest = f->ooos_list_head;
      return;
    }

  /* Find first segment that starts after new segment */
  s = pool_elt_at_index (f->ooo_segments, f->ooos_list_head);
  while (s->next != OOO_SEGMENT_INVALID_INDEX
	 && offset_leq (ooo_segment_offset (f, s), offset))
    s = pool_elt_at_index (f->ooo_segments, s->next);

  /* If we have a previous and we overlap it, use it as starting point */
  prev = ooo_segment_get_prev (f, s);
  if (prev && offset_leq (offset, ooo_segment_end_offset (f, prev)))
    {
      s = prev;
      prev = ooo_segment_get_prev (f, s);
      s_sof = ooo_segment_offset (f, s);
      s_eof = ooo_segment_end_offset (f, s);
      goto merge;
    }

  s_index = s - f->ooo_segments;
  s_sof = ooo_segment_offset (f, s);
  s_eof = ooo_segment_end_offset (f, s);

  /* No overlap, add before current segment */
  if (offset_lt (end_offset, s_sof))
    {
      new_s = ooo_segment_new (f, offset, length);
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

      new_s->next = s - f->ooo_segments;
      s->prev = new_index;
      f->ooos_newest = new_index;
      return;
    }
  /* No overlap, add after current segment */
  else if (offset_gt (offset, s_eof))
    {
      new_s = ooo_segment_new (f, offset, length);
      new_index = new_s - f->ooo_segments;

      /* Pool might've moved, get segment again */
      s = pool_elt_at_index (f->ooo_segments, s_index);

      if (s->next != OOO_SEGMENT_INVALID_INDEX)
	{
	  new_s->next = s->next;
	  next = pool_elt_at_index (f->ooo_segments, new_s->next);
	  next->prev = new_index;
	}

      new_s->prev = s - f->ooo_segments;
      s->next = new_index;
      f->ooos_newest = new_index;

      return;
    }

  /*
   * Merge needed
   */

merge:

  /* Merge at head */
  if (offset_lt (offset, s_sof))
    {
      s->start = offset;
      s->length = s_eof - ooo_segment_offset (f, s);
    }
  /* Last but overlapping previous */
  else if (offset_gt (end_offset, s_eof))
    {
      s->length = end_offset - ooo_segment_offset (f, s);
    }
  /* New segment completely covered by current one */
  else
    {
      /* Do Nothing */
      goto done;
    }

  /* The new segment's tail may cover multiple smaller ones */
  if (offset_geq (end_offset, s_eof))
    {
      /* Remove the completely overlapped segments */
      it = (s->next != OOO_SEGMENT_INVALID_INDEX) ?
	pool_elt_at_index (f->ooo_segments, s->next) : 0;
      while (it && offset_leq (ooo_segment_end_offset (f, it), end_offset))
	{
	  next = (it->next != OOO_SEGMENT_INVALID_INDEX) ?
	    pool_elt_at_index (f->ooo_segments, it->next) : 0;
	  ooo_segment_del (f, it - f->ooo_segments);
	  it = next;
	}

      /* If partial overlap with last, merge */
      if (it && offset_leq (ooo_segment_offset (f, it), end_offset))
	{
	  s->length = ooo_segment_end_offset (f, it) -
	    ooo_segment_offset (f, s);
	  ooo_segment_del (f, it - f->ooo_segments);
	}
    }

done:
  /* Most recently updated segment */
  f->ooos_newest = s - f->ooo_segments;
}

/**
 * Removes segments that can now be enqueued because the fifo's tail has
 * advanced. Returns the number of bytes added to tail.
 */
static int
ooo_segment_try_collect (svm_fifo_t * f, u32 n_bytes_enqueued)
{
  ooo_segment_t *s;
  u32 index, bytes = 0, diff;
  u32 cursize, norm_start, nitems;

  /* current size has not yet been updated */
  cursize = svm_fifo_max_dequeue (f) + n_bytes_enqueued;
  nitems = f->nitems;

  s = pool_elt_at_index (f->ooo_segments, f->ooos_list_head);

  norm_start = s->start % nitems;
  diff = (f->nitems + (i32) (f->tail - norm_start)) % nitems;

  if (diff > cursize)
    return 0;

  /* If last tail update overlaps one/multiple ooo segments, remove them */
  while (0 < diff && diff < cursize)
    {
      index = s - f->ooo_segments;

      /* Segment end is beyond the tail. Advance tail and remove segment */
      if (diff < s->length)
	{
	  f->tail += s->length - diff;
	  f->tail %= f->nitems;
	  bytes = s->length - diff;
	  ooo_segment_del (f, index);
	  break;
	}

      /* If we have next go on */
      if (s->next != OOO_SEGMENT_INVALID_INDEX)
	{
	  s = pool_elt_at_index (f->ooo_segments, s->next);
	  norm_start = s->start % nitems;
	  diff = (f->nitems + (i32) (f->tail - norm_start)) % nitems;
	  ooo_segment_del (f, index);
	}
      /* End of search */
      else
	{
	  ooo_segment_del (f, index);
	  break;
	}
    }

  /* If tail is adjacent to an ooo segment, 'consume' it */
  if (diff == 0)
    {
      bytes = ((nitems - cursize) >= s->length) ? s->length :
	nitems - cursize;

      f->tail += bytes;
      f->tail %= nitems;

      ooo_segment_del (f, s - f->ooo_segments);
    }

  return bytes;
}

static int
svm_fifo_enqueue_internal (svm_fifo_t * f, u32 max_bytes, u8 * copy_from_here)
{
  u32 total_copy_bytes, first_copy_bytes, second_copy_bytes;
  u32 cursize, nitems;

  /* read cursize, which can only increase while we're working */
  cursize = svm_fifo_max_dequeue (f);

  if (PREDICT_FALSE (cursize == f->nitems))
    return -2;			/* fifo stuffed */

  nitems = f->nitems;

  /* Number of bytes we're going to copy */
  total_copy_bytes = (nitems - cursize) < max_bytes ?
    (nitems - cursize) : max_bytes;

  if (PREDICT_TRUE (copy_from_here != 0))
    {
      /* Number of bytes in first copy segment */
      first_copy_bytes = ((nitems - f->tail) < total_copy_bytes)
	? (nitems - f->tail) : total_copy_bytes;

      clib_memcpy (&f->data[f->tail], copy_from_here, first_copy_bytes);
      f->tail += first_copy_bytes;
      f->tail = (f->tail == nitems) ? 0 : f->tail;

      /* Number of bytes in second copy segment, if any */
      second_copy_bytes = total_copy_bytes - first_copy_bytes;
      if (second_copy_bytes)
	{
	  clib_memcpy (&f->data[f->tail], copy_from_here + first_copy_bytes,
		       second_copy_bytes);
	  f->tail += second_copy_bytes;
	  f->tail = (f->tail == nitems) ? 0 : f->tail;
	}
    }
  else
    {
      /* Account for a zero-copy enqueue done elsewhere */
      ASSERT (max_bytes <= (nitems - cursize));
      f->tail += max_bytes;
      f->tail = f->tail % nitems;
      total_copy_bytes = max_bytes;
    }

  /* Any out-of-order segments to collect? */
  if (PREDICT_FALSE (f->ooos_list_head != OOO_SEGMENT_INVALID_INDEX))
    total_copy_bytes += ooo_segment_try_collect (f, total_copy_bytes);

  /* Atomically increase the queue length */
  __sync_fetch_and_add (&f->cursize, total_copy_bytes);

  return (total_copy_bytes);
}

int
svm_fifo_enqueue_nowait (svm_fifo_t * f, u32 max_bytes, u8 * copy_from_here)
{
  return svm_fifo_enqueue_internal (f, max_bytes, copy_from_here);
}

/**
 * Enqueue a future segment.
 *
 * Two choices: either copies the entire segment, or copies nothing
 * Returns 0 of the entire segment was copied
 * Returns -1 if none of the segment was copied due to lack of space
 */
static int
svm_fifo_enqueue_with_offset_internal (svm_fifo_t * f,
				       u32 offset,
				       u32 required_bytes,
				       u8 * copy_from_here)
{
  u32 total_copy_bytes, first_copy_bytes, second_copy_bytes;
  u32 cursize, nitems;
  u32 normalized_offset, offset_from_tail;

  /* read cursize, which can only increase while we're working */
  cursize = svm_fifo_max_dequeue (f);
  nitems = f->nitems;
  normalized_offset = offset % nitems;

  /* Will this request fit? */
  offset_from_tail = (nitems + normalized_offset - f->tail) % nitems;
  if ((required_bytes + offset_from_tail) > (nitems - cursize))
    return -1;

  ooo_segment_add (f, offset, required_bytes);

  /* Number of bytes we're going to copy */
  total_copy_bytes = required_bytes;

  /* Number of bytes in first copy segment */
  first_copy_bytes = ((nitems - normalized_offset) < total_copy_bytes)
    ? (nitems - normalized_offset) : total_copy_bytes;

  clib_memcpy (&f->data[normalized_offset], copy_from_here, first_copy_bytes);

  /* Number of bytes in second copy segment, if any */
  second_copy_bytes = total_copy_bytes - first_copy_bytes;
  if (second_copy_bytes)
    {
      normalized_offset += first_copy_bytes;
      normalized_offset %= nitems;

      ASSERT (normalized_offset == 0);

      clib_memcpy (&f->data[normalized_offset],
		   copy_from_here + first_copy_bytes, second_copy_bytes);
    }

  return (0);
}


int
svm_fifo_enqueue_with_offset (svm_fifo_t * f,
			      u32 offset,
			      u32 required_bytes, u8 * copy_from_here)
{
  return svm_fifo_enqueue_with_offset_internal (f, offset, required_bytes,
						copy_from_here);
}


static int
svm_fifo_dequeue_internal (svm_fifo_t * f, u32 max_bytes, u8 * copy_here)
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
      clib_memcpy (copy_here, &f->data[f->head], first_copy_bytes);
      f->head += first_copy_bytes;
      f->head = (f->head == nitems) ? 0 : f->head;

      /* Number of bytes in second copy segment, if any */
      second_copy_bytes = total_copy_bytes - first_copy_bytes;
      if (second_copy_bytes)
	{
	  clib_memcpy (copy_here + first_copy_bytes,
		       &f->data[f->head], second_copy_bytes);
	  f->head += second_copy_bytes;
	  f->head = (f->head == nitems) ? 0 : f->head;
	}
    }
  else
    {
      /* Account for a zero-copy dequeue done elsewhere */
      ASSERT (max_bytes <= cursize);
      f->head += max_bytes;
      f->head = f->head % nitems;
      cursize -= max_bytes;
      total_copy_bytes = max_bytes;
    }

  __sync_fetch_and_sub (&f->cursize, total_copy_bytes);

  return (total_copy_bytes);
}

int
svm_fifo_dequeue_nowait (svm_fifo_t * f, u32 max_bytes, u8 * copy_here)
{
  return svm_fifo_dequeue_internal (f, max_bytes, copy_here);
}

int
svm_fifo_peek (svm_fifo_t * f, u32 relative_offset, u32 max_bytes,
	       u8 * copy_here)
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
      clib_memcpy (copy_here, &f->data[real_head], first_copy_bytes);

      /* Number of bytes in second copy segment, if any */
      second_copy_bytes = total_copy_bytes - first_copy_bytes;
      if (second_copy_bytes)
	{
	  clib_memcpy (copy_here + first_copy_bytes, &f->data[0],
		       second_copy_bytes);
	}
    }
  return total_copy_bytes;
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

  __sync_fetch_and_sub (&f->cursize, total_drop_bytes);

  return total_drop_bytes;
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
