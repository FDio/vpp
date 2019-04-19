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
#include <vppinfra/cpu.h>

static inline u8
position_lt (svm_fifo_t * f, u32 a, u32 b, u32 tail)
{
  return (ooo_segment_distance_from_tail (f, a, tail)
	  < ooo_segment_distance_from_tail (f, b, tail));
}

static inline u8
position_leq (svm_fifo_t * f, u32 a, u32 b, u32 tail)
{
  return (ooo_segment_distance_from_tail (f, a, tail)
	  <= ooo_segment_distance_from_tail (f, b, tail));
}

static inline u8
position_gt (svm_fifo_t * f, u32 a, u32 b, u32 tail)
{
  return (ooo_segment_distance_from_tail (f, a, tail)
	  > ooo_segment_distance_from_tail (f, b, tail));
}

static inline u32
position_diff (svm_fifo_t * f, u32 posa, u32 posb, u32 tail)
{
  return ooo_segment_distance_from_tail (f, posa, tail)
    - ooo_segment_distance_from_tail (f, posb, tail);
}

static inline u32
ooo_segment_end_pos (svm_fifo_t * f, ooo_segment_t * s)
{
  return s->start + s->length;
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
ooo_segment_add (svm_fifo_t * f, u32 offset, u32 head, u32 tail, u32 length)
{
  ooo_segment_t *s, *new_s, *prev, *next, *it;
  u32 new_index, s_end_pos, s_index;
  u32 offset_pos, offset_end_pos;

  ASSERT (offset + length <= ooo_segment_distance_from_tail (f, head, tail)
	  || head == tail);

  offset_pos = tail + offset;
  offset_end_pos = tail + offset + length;

  f->ooos_newest = OOO_SEGMENT_INVALID_INDEX;

  if (f->ooos_list_head == OOO_SEGMENT_INVALID_INDEX)
    {
      s = ooo_segment_new (f, offset_pos, length);
      f->ooos_list_head = s - f->ooo_segments;
      f->ooos_newest = f->ooos_list_head;
      return;
    }

  /* Find first segment that starts after new segment */
  s = pool_elt_at_index (f->ooo_segments, f->ooos_list_head);
  while (s->next != OOO_SEGMENT_INVALID_INDEX
	 && position_lt (f, s->start, offset_pos, tail))
    s = pool_elt_at_index (f->ooo_segments, s->next);

  /* If we have a previous and we overlap it, use it as starting point */
  prev = ooo_segment_get_prev (f, s);
  if (prev
      && position_leq (f, offset_pos, ooo_segment_end_pos (f, prev), tail))
    {
      s = prev;
      s_end_pos = ooo_segment_end_pos (f, s);

      /* Since we have previous, offset start position cannot be smaller
       * than prev->start. Check tail */
      ASSERT (position_lt (f, s->start, offset_pos, tail));
      goto check_tail;
    }

  s_index = s - f->ooo_segments;
  s_end_pos = ooo_segment_end_pos (f, s);

  /* No overlap, add before current segment */
  if (position_lt (f, offset_end_pos, s->start, tail))
    {
      new_s = ooo_segment_new (f, offset_pos, length);
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
  else if (position_gt (f, offset_pos, s_end_pos, tail))
    {
      new_s = ooo_segment_new (f, offset_pos, length);
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
  if (position_lt (f, offset_pos, s->start, tail))
    {
      s->start = offset_pos;
      s->length = position_diff (f, s_end_pos, s->start, tail);
      f->ooos_newest = s - f->ooo_segments;
    }

check_tail:

  /* Overlapping tail */
  if (position_gt (f, offset_end_pos, s_end_pos, tail))
    {
      s->length = position_diff (f, offset_end_pos, s->start, tail);

      /* Remove the completely overlapped segments in the tail */
      it = ooo_segment_next (f, s);
      while (it && position_leq (f, ooo_segment_end_pos (f, it),
				 offset_end_pos, tail))
	{
	  next = ooo_segment_next (f, it);
	  ooo_segment_del (f, it - f->ooo_segments);
	  it = next;
	}

      /* If partial overlap with last, merge */
      if (it && position_leq (f, it->start, offset_end_pos, tail))
	{
	  s->length = position_diff (f, ooo_segment_end_pos (f, it),
				     s->start, tail);
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
ooo_segment_try_collect (svm_fifo_t * f, u32 n_bytes_enqueued, u32 * tail)
{
  ooo_segment_t *s;
  u32 index, bytes = 0;
  i32 diff;

  s = pool_elt_at_index (f->ooo_segments, f->ooos_list_head);
  diff = ooo_segment_distance_to_tail (f, s->start, *tail);

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
	  *tail = *tail + bytes;
	  ooo_segment_del (f, index);
	  break;
	}

      /* If we have next go on */
      if (s->next != OOO_SEGMENT_INVALID_INDEX)
	{
	  s = pool_elt_at_index (f->ooo_segments, s->next);
	  diff = ooo_segment_distance_to_tail (f, s->start, *tail);
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

CLIB_MARCH_FN (svm_fifo_enqueue_nowait, int, svm_fifo_t * f, u32 len,
	       const u8 * src)
{
  u32 n_chunk, to_copy, tail, head, free_count, tail_idx;
  svm_fifo_chunk_t *c;

  f_load_head_tail_prod (f, &head, &tail);

  /* free space in fifo can only increase during enqueue: SPSC */
  free_count = f_free_count (f, head, tail);

  f->ooos_newest = OOO_SEGMENT_INVALID_INDEX;

  if (PREDICT_FALSE (free_count == 0))
    return SVM_FIFO_FULL;

  /* number of bytes we're going to copy */
  to_copy = len = clib_min (free_count, len);

  c = f->tail_chunk;
  tail_idx = tail % f->size;
  ASSERT (tail_idx >= c->start_byte);
  tail_idx -= c->start_byte;
  n_chunk = c->length - tail_idx;

  if (n_chunk < to_copy)
    {
      clib_memcpy_fast (&c->data[tail_idx], src, n_chunk);
      while ((to_copy -= n_chunk))
	{
	  c = c->next;
	  n_chunk = clib_min (c->length, to_copy);
	  clib_memcpy_fast (&c->data[0], src + (len - to_copy), n_chunk);
	}
      f->tail_chunk = c;
    }
  else
    {
      clib_memcpy_fast (&c->data[tail_idx], src, to_copy);
    }
  tail += len;

  svm_fifo_trace_add (f, head, n_total, 2);

  /* collect out-of-order segments */
  if (PREDICT_FALSE (f->ooos_list_head != OOO_SEGMENT_INVALID_INDEX))
    len += ooo_segment_try_collect (f, len, &tail);

  ASSERT (len <= free_count);

  /* store-rel: producer owned index (paired with load-acq in consumer) */
  clib_atomic_store_rel_n (&f->tail, tail);

  return len;
}

/**
 * Enqueue a future segment.
 *
 * Two choices: either copies the entire segment, or copies nothing
 * Returns 0 of the entire segment was copied
 * Returns -1 if none of the segment was copied due to lack of space
 */
CLIB_MARCH_FN (svm_fifo_enqueue_with_offset, int, svm_fifo_t * f,
	       u32 offset, u32 len, u8 * src)
{
  u32 to_copy, n_chunk, tail, head, free_count, tail_offset_idx;
  svm_fifo_chunk_t *c;

  f_load_head_tail_prod (f, &head, &tail);

  /* free space in fifo can only increase during enqueue: SPSC */
  free_count = f_free_count (f, head, tail);

  /* will this request fit? */
  if ((len + offset) > free_count)
    return -1;

  f->ooos_newest = OOO_SEGMENT_INVALID_INDEX;

  ASSERT (len < f->nitems);
  svm_fifo_trace_add (f, offset, len, 1);

  ooo_segment_add (f, offset, head, tail, len);

  c = f->tail_chunk;
  tail_offset_idx = (tail + offset) % f->size;
  tail_offset_idx -= c->start_byte;
  n_chunk = c->length - tail_offset_idx;
  to_copy = len;

  if (n_chunk < to_copy)
    {
      clib_memcpy_fast (&c->data[tail_offset_idx], src, n_chunk);
      while ((to_copy -= n_chunk))
	{
	  c = c->next;
	  n_chunk = clib_min (c->length, to_copy);
	  clib_memcpy_fast (&c->data[0], src + (len - to_copy), n_chunk);
	}
    }
  else
    {
      clib_memcpy_fast (&c->data[tail_offset_idx], src, len);
    }

  return 0;
}

CLIB_MARCH_FN (svm_fifo_dequeue_nowait, int, svm_fifo_t * f, u32 len,
	       u8 * dst)
{
  u32 to_copy, n_chunk, tail, head, cursize, head_idx;
  svm_fifo_chunk_t *c;

  f_load_head_tail_cons (f, &head, &tail);

  /* current size of fifo can only increase during dequeue: SPSC */
  cursize = f_cursize (f, head, tail);

  if (PREDICT_FALSE (cursize == 0))
    return -2;			/* nothing in the fifo */

  to_copy = len = clib_min (cursize, len);
  ASSERT (cursize >= to_copy);

  c = f->head_chunk;
  head_idx = head % f->size;
  head_idx -= c->start_byte;
  n_chunk = c->length - head_idx;

  if (n_chunk < to_copy)
    {
      clib_memcpy_fast (dst, &c->data[head_idx], n_chunk);
      while ((to_copy -= n_chunk))
	{
	  c = c->next;
	  n_chunk = clib_min (c->length, to_copy);
	  clib_memcpy_fast (dst + (len - to_copy), &c->data[0], n_chunk);
	}
      f->head_chunk = c;
    }
  else
    {
      clib_memcpy_fast (dst, &c->data[head_idx], to_copy);
    }
  head += len;

  if (PREDICT_FALSE (f->flags & SVM_FIFO_F_SIZE_UPDATE))
    svm_fifo_try_size_update (f, head);

  /* store-rel: consumer owned index (paired with load-acq in producer) */
  clib_atomic_store_rel_n (&f->head, head);

  return len;
}

CLIB_MARCH_FN (svm_fifo_peek, int, svm_fifo_t * f, u32 relative_offset,
	       u32 len, u8 * dst)
{
  u32 to_copy, n_chunk, tail, head, cursize, head_idx;
  svm_fifo_chunk_t *c;

  f_load_head_tail_cons (f, &head, &tail);

  /* current size of fifo can only increase during peek: SPSC */
  cursize = f_cursize (f, head, tail);

  if (PREDICT_FALSE (cursize < relative_offset))
    return -2;			/* nothing in the fifo */

  to_copy = len = clib_min (cursize - relative_offset, len);

  c = f->head_chunk;
  head_idx = (head + relative_offset) % f->size;
  head_idx -= c->start_byte;
  n_chunk = c->length - head_idx;

  if (n_chunk < to_copy)
    {
      clib_memcpy_fast (dst, &c->data[head_idx], n_chunk);
      while ((to_copy -= n_chunk))
	{
	  c = c->next;
	  n_chunk = clib_min (c->length, to_copy);
	  clib_memcpy_fast (dst + (len - to_copy), &c->data[0], n_chunk);
	}
      f->head_chunk = c;
    }
  else
    {
      clib_memcpy_fast (dst, &c->data[head_idx], to_copy);
    }
  return len;
}

#ifndef CLIB_MARCH_VARIANT
int
svm_fifo_enqueue_nowait (svm_fifo_t * f, u32 max_bytes,
			 const u8 * copy_from_here)
{
  return CLIB_MARCH_FN_SELECT (svm_fifo_enqueue_nowait) (f, max_bytes,
							 copy_from_here);
}

int
svm_fifo_enqueue_with_offset (svm_fifo_t * f, u32 offset, u32 required_bytes,
			      u8 * copy_from_here)
{
  return CLIB_MARCH_FN_SELECT (svm_fifo_enqueue_with_offset) (f, offset,
							      required_bytes,
							      copy_from_here);
}

int
svm_fifo_dequeue_nowait (svm_fifo_t * f, u32 max_bytes, u8 * copy_here)
{
  return CLIB_MARCH_FN_SELECT (svm_fifo_dequeue_nowait) (f, max_bytes,
							 copy_here);
}

int
svm_fifo_peek (svm_fifo_t * f, u32 relative_offset, u32 max_bytes,
	       u8 * copy_here)
{
  return CLIB_MARCH_FN_SELECT (svm_fifo_peek) (f, relative_offset, max_bytes,
					       copy_here);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
