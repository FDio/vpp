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
#include <svm/fifo_segment.h>
#include <vppinfra/cpu.h>

CLIB_MARCH_FN (svm_fifo_copy_to_chunk, void, svm_fifo_t * f,
	       svm_fifo_chunk_t * c, u32 tail_idx, const u8 * src, u32 len,
	       svm_fifo_chunk_t ** last)
{
  u32 n_chunk;

  ASSERT (f_pos_geq (tail_idx, c->start_byte)
	  && f_pos_lt (tail_idx, c->start_byte + c->length));

  tail_idx -= c->start_byte;
  n_chunk = c->length - tail_idx;
  if (n_chunk <= len)
    {
      u32 to_copy = len;
      clib_memcpy_fast (&c->data[tail_idx], src, n_chunk);
      c = c->next;
      while ((to_copy -= n_chunk))
	{
	  n_chunk = clib_min (c->length, to_copy);
	  clib_memcpy_fast (&c->data[0], src + (len - to_copy), n_chunk);
	  c = c->length <= to_copy ? c->next : c;
	}
      if (*last)
	*last = c;
    }
  else
    {
      clib_memcpy_fast (&c->data[tail_idx], src, len);
    }
}

CLIB_MARCH_FN (svm_fifo_copy_from_chunk, void, svm_fifo_t * f,
	       svm_fifo_chunk_t * c, u32 head_idx, u8 * dst, u32 len,
	       svm_fifo_chunk_t ** last)
{
  u32 n_chunk;

  ASSERT (f_pos_geq (head_idx, c->start_byte)
	  && f_pos_lt (head_idx, c->start_byte + c->length));

  head_idx -= c->start_byte;
  n_chunk = c->length - head_idx;
  if (n_chunk <= len)
    {
      u32 to_copy = len;
      clib_memcpy_fast (dst, &c->data[head_idx], n_chunk);
      c = c->next;
      while ((to_copy -= n_chunk))
	{
	  n_chunk = clib_min (c->length, to_copy);
	  clib_memcpy_fast (dst + (len - to_copy), &c->data[0], n_chunk);
	  c = c->length <= to_copy ? c->next : c;
	}
      if (*last)
	*last = c;
    }
  else
    {
      clib_memcpy_fast (dst, &c->data[head_idx], len);
    }
}

#ifndef CLIB_MARCH_VARIANT

static inline void
svm_fifo_copy_to_chunk (svm_fifo_t * f, svm_fifo_chunk_t * c, u32 tail_idx,
			const u8 * src, u32 len, svm_fifo_chunk_t ** last)
{
  CLIB_MARCH_FN_SELECT (svm_fifo_copy_to_chunk) (f, c, tail_idx, src, len,
						 last);
}

static inline void
svm_fifo_copy_from_chunk (svm_fifo_t * f, svm_fifo_chunk_t * c, u32 head_idx,
			  u8 * dst, u32 len, svm_fifo_chunk_t ** last)
{
  CLIB_MARCH_FN_SELECT (svm_fifo_copy_from_chunk) (f, c, head_idx, dst, len,
						   last);
}

static inline u32
ooo_segment_end_pos (ooo_segment_t * s)
{
  return (s->start + s->length);
}

void
svm_fifo_free_ooo_data (svm_fifo_t * f)
{
  pool_free (f->ooo_segments);
}

static inline ooo_segment_t *
ooo_segment_prev (svm_fifo_t * f, ooo_segment_t * s)
{
  if (s->prev == OOO_SEGMENT_INVALID_INDEX)
    return 0;
  return pool_elt_at_index (f->ooo_segments, s->prev);
}

static inline ooo_segment_t *
ooo_segment_next (svm_fifo_t * f, ooo_segment_t * s)
{
  if (s->next == OOO_SEGMENT_INVALID_INDEX)
    return 0;
  return pool_elt_at_index (f->ooo_segments, s->next);
}

static inline ooo_segment_t *
ooo_segment_alloc (svm_fifo_t * f, u32 start, u32 length)
{
  ooo_segment_t *s;

  pool_get (f->ooo_segments, s);

  s->start = start;
  s->length = length;
  s->prev = s->next = OOO_SEGMENT_INVALID_INDEX;

  return s;
}

static inline void
ooo_segment_free (svm_fifo_t * f, u32 index)
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

  ASSERT (offset + length <= f_free_count (f, head, tail));

  offset_pos = tail + offset;
  offset_end_pos = tail + offset + length;

  f->ooos_newest = OOO_SEGMENT_INVALID_INDEX;

  if (f->ooos_list_head == OOO_SEGMENT_INVALID_INDEX)
    {
      s = ooo_segment_alloc (f, offset_pos, length);
      f->ooos_list_head = s - f->ooo_segments;
      f->ooos_newest = f->ooos_list_head;
      return;
    }

  /* Find first segment that starts after new segment */
  s = pool_elt_at_index (f->ooo_segments, f->ooos_list_head);
  while (s->next != OOO_SEGMENT_INVALID_INDEX
	 && f_pos_lt (s->start, offset_pos))
    s = pool_elt_at_index (f->ooo_segments, s->next);

  /* If we have a previous and we overlap it, use it as starting point */
  prev = ooo_segment_prev (f, s);
  if (prev && f_pos_leq (offset_pos, ooo_segment_end_pos (prev)))
    {
      s = prev;
      s_end_pos = ooo_segment_end_pos (s);

      /* Since we have previous, offset start position cannot be smaller
       * than prev->start. Check tail */
      ASSERT (f_pos_lt (s->start, offset_pos));
      goto check_tail;
    }

  s_index = s - f->ooo_segments;
  s_end_pos = ooo_segment_end_pos (s);

  /* No overlap, add before current segment */
  if (f_pos_lt (offset_end_pos, s->start))
    {
      new_s = ooo_segment_alloc (f, offset_pos, length);
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
  else if (f_pos_gt (offset_pos, s_end_pos))
    {
      new_s = ooo_segment_alloc (f, offset_pos, length);
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
  if (f_pos_lt (offset_pos, s->start))
    {
      s->start = offset_pos;
      s->length = s_end_pos - s->start;
      f->ooos_newest = s - f->ooo_segments;
    }

check_tail:

  /* Overlapping tail */
  if (f_pos_gt (offset_end_pos, s_end_pos))
    {
      s->length = offset_end_pos - s->start;

      /* Remove the completely overlapped segments in the tail */
      it = ooo_segment_next (f, s);
      while (it && f_pos_leq (ooo_segment_end_pos (it), offset_end_pos))
	{
	  next = ooo_segment_next (f, it);
	  ooo_segment_free (f, it - f->ooo_segments);
	  it = next;
	}

      /* If partial overlap with last, merge */
      if (it && f_pos_leq (it->start, offset_end_pos))
	{
	  s->length = ooo_segment_end_pos (it) - s->start;
	  ooo_segment_free (f, it - f->ooo_segments);
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
  u32 s_index, bytes = 0;
  ooo_segment_t *s;
  i32 diff;

  s = pool_elt_at_index (f->ooo_segments, f->ooos_list_head);
  diff = *tail - s->start;

  ASSERT (diff != n_bytes_enqueued);

  if (diff > n_bytes_enqueued)
    return 0;

  /* If last tail update overlaps one/multiple ooo segments, remove them */
  while (0 <= diff && diff < n_bytes_enqueued)
    {
      s_index = s - f->ooo_segments;

      /* Segment end is beyond the tail. Advance tail and remove segment */
      if (s->length > diff)
	{
	  bytes = s->length - diff;
	  *tail = *tail + bytes;
	  ooo_segment_free (f, s_index);
	  break;
	}

      /* If we have next go on */
      if (s->next != OOO_SEGMENT_INVALID_INDEX)
	{
	  s = pool_elt_at_index (f->ooo_segments, s->next);
	  diff = *tail - s->start;
	  ooo_segment_free (f, s_index);
	}
      /* End of search */
      else
	{
	  ooo_segment_free (f, s_index);
	  break;
	}
    }

  ASSERT (bytes <= f->size);
  return bytes;
}

__clib_unused static ooo_segment_t *
ooo_segment_last (svm_fifo_t * f)
{
  ooo_segment_t *s;

  if (f->ooos_list_head == OOO_SEGMENT_INVALID_INDEX)
    return 0;

  s = svm_fifo_first_ooo_segment (f);
  while (s->next != OOO_SEGMENT_INVALID_INDEX)
    s = pool_elt_at_index (f->ooo_segments, s->next);
  return s;
}

void
svm_fifo_init (svm_fifo_t * f, u32 size)
{
  svm_fifo_chunk_t *c, *prev;
  u32 min_alloc;

  f->size = size;
  f->ooos_list_head = OOO_SEGMENT_INVALID_INDEX;
  f->segment_index = SVM_FIFO_INVALID_INDEX;
  f->refcnt = 1;
  f->head = f->tail = f->flags = 0;
  f->head_chunk = f->tail_chunk = f->start_chunk;
  f->ooo_deq = f->ooo_enq = 0;

  min_alloc = size > 32 << 10 ? size >> 3 : 4096;
  min_alloc = clib_min (min_alloc, 64 << 10);
  f->min_alloc = min_alloc;

  /*
   * Initialize chunks
   */
  f->start_chunk->start_byte = 0;
  prev = f->start_chunk;
  c = prev->next;

  while (c)
    {
      c->start_byte = prev->start_byte + prev->length;
      prev = c;
      c = c->next;
    }
}

void
svm_fifo_init_ooo_lookup (svm_fifo_t * f, u8 ooo_type)
{
  if (ooo_type == 0)
    {
      ASSERT (!rb_tree_is_init (&f->ooo_enq_lookup));
      rb_tree_init (&f->ooo_enq_lookup);
    }
  else
    {
      ASSERT (!rb_tree_is_init (&f->ooo_deq_lookup));
      rb_tree_init (&f->ooo_deq_lookup);
    }
}

/**
 * Creates a fifo in the current heap. Fails vs blow up the process
 */
svm_fifo_t *
svm_fifo_alloc (u32 data_size_in_bytes)
{
  u32 rounded_data_size;
  svm_fifo_chunk_t *c;
  svm_fifo_t *f;

  f = clib_mem_alloc_aligned_or_null (sizeof (*f), CLIB_CACHE_LINE_BYTES);
  if (f == 0)
    return 0;

  clib_memset (f, 0, sizeof (*f));

  /* always round fifo data size to the next highest power-of-two */
  rounded_data_size = (1 << (max_log2 (data_size_in_bytes)));
  c = clib_mem_alloc_aligned_or_null (sizeof (*c) + rounded_data_size,
				      CLIB_CACHE_LINE_BYTES);
  if (!c)
    {
      clib_mem_free (f);
      return 0;
    }

  clib_memset (c, 0, sizeof (*c));
  c->start_byte = 0;
  c->length = data_size_in_bytes;
  c->enq_rb_index = RBTREE_TNIL_INDEX;
  c->deq_rb_index = RBTREE_TNIL_INDEX;
  f->start_chunk = f->end_chunk = c;

  return f;
}

/**
 * Creates a fifo chunk in the current heap
 */
svm_fifo_chunk_t *
svm_fifo_chunk_alloc (u32 size)
{
  svm_fifo_chunk_t *c;
  u32 rounded_size;

  /* round chunk size to the next highest power-of-two */
  rounded_size = (1 << (max_log2 (size)));
  c = clib_mem_alloc_aligned_or_null (sizeof (*c) + rounded_size,
				      CLIB_CACHE_LINE_BYTES);
  if (c == 0)
    return 0;

  clib_memset (c, 0, sizeof (*c));
  c->length = rounded_size;
  return c;
}

/**
 * Find chunk for given byte position
 *
 * @param f	fifo
 * @param pos	normalized position in fifo
 *
 * @return chunk that includes given position or 0
 */
static svm_fifo_chunk_t *
svm_fifo_find_chunk (svm_fifo_t * f, u32 pos)
{
  svm_fifo_chunk_t *c;

  c = f->start_chunk;
  while (c && !f_chunk_includes_pos (c, pos))
    c = c->next;

  return c;
}

static svm_fifo_chunk_t *
svm_fifo_find_next_chunk (svm_fifo_t * f, svm_fifo_chunk_t * start, u32 pos)
{
  svm_fifo_chunk_t *c;

  ASSERT (start != 0);

  c = start;
  while (c && !f_chunk_includes_pos (c, pos))
    c = c->next;

  return c;
}

u32
svm_fifo_max_read_chunk (svm_fifo_t * f)
{
  u32 head, tail, end_chunk;

  f_load_head_tail_cons (f, &head, &tail);
  ASSERT (!f->head_chunk || f_chunk_includes_pos (f->head_chunk, head));

  if (!f->head_chunk)
    {
      f->head_chunk = svm_fifo_find_chunk (f, head);
      if (PREDICT_FALSE (!f->head_chunk))
	return 0;
    }

  end_chunk = f_chunk_end (f->head_chunk);

  return f_pos_lt (end_chunk, tail) ? end_chunk - head : tail - head;
}

u32
svm_fifo_max_write_chunk (svm_fifo_t * f)
{
  u32 head, tail;

  f_load_head_tail_prod (f, &head, &tail);
  ASSERT (!f->tail_chunk || f_chunk_includes_pos (f->tail_chunk, tail));

  return f->tail_chunk ? f_chunk_end (f->tail_chunk) - tail : 0;
}

static rb_node_t *
f_find_node_rbtree (rb_tree_t * rt, u32 pos)
{
  rb_node_t *cur, *prev;

  cur = rb_node (rt, rt->root);
  if (PREDICT_FALSE (rb_node_is_tnil (rt, cur)))
    return 0;

  while (pos != cur->key)
    {
      prev = cur;
      if (f_pos_lt (pos, cur->key))
	{
	  cur = rb_node_left (rt, cur);
	  if (rb_node_is_tnil (rt, cur))
	    {
	      cur = rb_tree_predecessor (rt, prev);
	      break;
	    }
	}
      else
	{
	  cur = rb_node_right (rt, cur);
	  if (rb_node_is_tnil (rt, cur))
	    {
	      cur = prev;
	      break;
	    }
	}
    }

  if (rb_node_is_tnil (rt, cur))
    return 0;

  return cur;
}

static svm_fifo_chunk_t *
f_find_chunk_rbtree (rb_tree_t * rt, u32 pos)
{
  svm_fifo_chunk_t *c;
  rb_node_t *n;

  if (!rb_tree_is_init (rt))
    return 0;

  n = f_find_node_rbtree (rt, pos);
  if (!n)
    return 0;
  c = uword_to_pointer (n->opaque, svm_fifo_chunk_t *);
  if (f_chunk_includes_pos (c, pos))
    return c;

  return 0;
}

static void
f_update_ooo_enq (svm_fifo_t * f, u32 start_pos, u32 end_pos)
{
  rb_tree_t *rt = &f->ooo_enq_lookup;
  svm_fifo_chunk_t *c;
  rb_node_t *cur;

  /* Use linear search if rbtree is not initialized */
  if (PREDICT_FALSE (!rb_tree_is_init (rt)))
    {
      f->ooo_enq = svm_fifo_find_next_chunk (f, f->tail_chunk, start_pos);
      return;
    }

  if (rt->root == RBTREE_TNIL_INDEX)
    {
      c = f->tail_chunk;
      ASSERT (c->enq_rb_index == RBTREE_TNIL_INDEX);
      c->enq_rb_index = rb_tree_add_custom (rt, c->start_byte,
					    pointer_to_uword (c), f_pos_lt);
    }
  else
    {
      cur = f_find_node_rbtree (rt, start_pos);
      c = uword_to_pointer (cur->opaque, svm_fifo_chunk_t *);
      ASSERT (f_pos_leq (c->start_byte, start_pos));
    }

  if (f_chunk_includes_pos (c, start_pos))
    f->ooo_enq = c;

  if (f_chunk_includes_pos (c, end_pos))
    return;

  do
    {
      c = c->next;
      if (!c || c->enq_rb_index != RBTREE_TNIL_INDEX)
	break;

      c->enq_rb_index = rb_tree_add_custom (rt, c->start_byte,
					    pointer_to_uword (c), f_pos_lt);

      if (f_chunk_includes_pos (c, start_pos))
	f->ooo_enq = c;
    }
  while (!f_chunk_includes_pos (c, end_pos));
}

static void
f_update_ooo_deq (svm_fifo_t * f, u32 start_pos, u32 end_pos)
{
  rb_tree_t *rt = &f->ooo_deq_lookup;
  rb_node_t *cur;
  svm_fifo_chunk_t *c;

  /* Use linear search if rbtree is not initialized  */
  if (PREDICT_FALSE (!rb_tree_is_init (rt)))
    {
      f->ooo_deq = svm_fifo_find_chunk (f, start_pos);
      return;
    }

  if (rt->root == RBTREE_TNIL_INDEX)
    {
      c = f->start_chunk;
      ASSERT (c->deq_rb_index == RBTREE_TNIL_INDEX);
      c->deq_rb_index = rb_tree_add_custom (rt, c->start_byte,
					    pointer_to_uword (c), f_pos_lt);
    }
  else
    {
      cur = f_find_node_rbtree (rt, start_pos);
      c = uword_to_pointer (cur->opaque, svm_fifo_chunk_t *);
      ASSERT (f_pos_leq (c->start_byte, start_pos));
    }

  if (f_chunk_includes_pos (c, start_pos))
    f->ooo_deq = c;

  if (f_chunk_includes_pos (c, end_pos))
    return;

  do
    {
      c = c->next;
      if (!c || c->deq_rb_index != RBTREE_TNIL_INDEX)
	break;

      c->deq_rb_index = rb_tree_add_custom (rt, c->start_byte,
					    pointer_to_uword (c), f_pos_lt);

      if (f_chunk_includes_pos (c, start_pos))
	f->ooo_deq = c;
    }
  while (!f_chunk_includes_pos (c, end_pos));
}

static svm_fifo_chunk_t *
f_lookup_clear_enq_chunks (svm_fifo_t * f, svm_fifo_chunk_t * start,
			   u32 end_pos)
{
  rb_tree_t *rt = &f->ooo_enq_lookup;
  svm_fifo_chunk_t *c;
  rb_node_t *n;

  c = start;
  while (c && !f_chunk_includes_pos (c, end_pos))
    {
      if (c->enq_rb_index != RBTREE_TNIL_INDEX)
	{
	  n = rb_node (rt, c->enq_rb_index);
	  rb_tree_del_node (rt, n);
	  c->enq_rb_index = RBTREE_TNIL_INDEX;
	}

      c = c->next;
    }

  /* No ooo segments left, so make sure the current chunk
   * is not tracked in the enq rbtree */
  if (f->ooos_list_head == OOO_SEGMENT_INVALID_INDEX
      && c && c->enq_rb_index != RBTREE_TNIL_INDEX)
    {
      n = rb_node (rt, c->enq_rb_index);
      rb_tree_del_node (rt, n);
      c->enq_rb_index = RBTREE_TNIL_INDEX;
    }

  return c;
}

static svm_fifo_chunk_t *
f_lookup_clear_deq_chunks (svm_fifo_t * f, svm_fifo_chunk_t * start,
			   u32 end_pos)
{
  rb_tree_t *rt = &f->ooo_deq_lookup;
  svm_fifo_chunk_t *c;
  rb_node_t *n;

  c = start;
  while (c && !f_chunk_includes_pos (c, end_pos))
    {
      if (c->deq_rb_index != RBTREE_TNIL_INDEX)
	{
	  n = rb_node (rt, c->deq_rb_index);
	  rb_tree_del_node (rt, n);
	  c->deq_rb_index = RBTREE_TNIL_INDEX;
	}

      c = c->next;
    }

  return c;
}

void
svm_fifo_free_chunk_lookup (svm_fifo_t * f)
{
  rb_tree_free_nodes (&f->ooo_enq_lookup);
  rb_tree_free_nodes (&f->ooo_deq_lookup);
}

void
svm_fifo_free (svm_fifo_t * f)
{
  ASSERT (f->refcnt > 0);

  if (--f->refcnt == 0)
    {
      /* ooo data is not allocated on segment heap */
      svm_fifo_free_chunk_lookup (f);
      clib_mem_free (f);
    }
}

void
svm_fifo_overwrite_head (svm_fifo_t * f, u8 * src, u32 len)
{
  u32 n_chunk;
  u32 head, tail, head_idx;
  svm_fifo_chunk_t *c;

  ASSERT (len <= f->size);

  f_load_head_tail_cons (f, &head, &tail);

  if (!f->head_chunk)
    f->head_chunk = svm_fifo_find_chunk (f, head);

  c = f->head_chunk;
  head_idx = head - c->start_byte;
  n_chunk = c->length - head_idx;
  if (len <= n_chunk)
    clib_memcpy_fast (&c->data[head_idx], src, len);
  else
    {
      ASSERT (len - n_chunk <= c->next->length);
      clib_memcpy_fast (&c->data[head_idx], src, n_chunk);
      clib_memcpy_fast (&c->next->data[0], src + n_chunk, len - n_chunk);
    }
}

static int
f_try_chunk_alloc (svm_fifo_t * f, u32 head, u32 tail, u32 len)
{
  svm_fifo_chunk_t *c, *cur, *prev;
  u32 alloc_size, free_alloced;

  free_alloced = f_chunk_end (f->end_chunk) - tail;

  alloc_size = clib_min (f->min_alloc, f->size - (tail - head));
  alloc_size = clib_max (alloc_size, len - free_alloced);

  c = fsh_alloc_chunk (f->fs_hdr, f->slice_index, alloc_size);
  if (PREDICT_FALSE (!c))
    return -1;

  cur = c;
  prev = f->end_chunk;

  while (cur)
    {
      cur->start_byte = prev->start_byte + prev->length;
      cur->enq_rb_index = RBTREE_TNIL_INDEX;
      cur->deq_rb_index = RBTREE_TNIL_INDEX;

      prev = cur;
      cur = cur->next;
    }

  prev->next = 0;
  f->end_chunk->next = c;
  f->end_chunk = prev;

  if (!f->tail_chunk)
    f->tail_chunk = c;

  return 0;
}

int
svm_fifo_enqueue (svm_fifo_t * f, u32 len, const u8 * src)
{
  u32 tail, head, free_count;
  svm_fifo_chunk_t *old_tail_c;

  f->ooos_newest = OOO_SEGMENT_INVALID_INDEX;

  f_load_head_tail_prod (f, &head, &tail);

  /* free space in fifo can only increase during enqueue: SPSC */
  free_count = f_free_count (f, head, tail);

  if (PREDICT_FALSE (free_count == 0))
    return SVM_FIFO_EFULL;

  /* number of bytes we're going to copy */
  len = clib_min (free_count, len);

  if (f_pos_gt (tail + len, f_chunk_end (f->end_chunk)))
    {
      if (PREDICT_FALSE (f_try_chunk_alloc (f, head, tail, len)))
	{
	  len = f_chunk_end (f->end_chunk) - tail;
	  if (!len)
	    return SVM_FIFO_EGROW;
	}
    }

  old_tail_c = f->tail_chunk;

  svm_fifo_copy_to_chunk (f, f->tail_chunk, tail, src, len, &f->tail_chunk);
  tail = tail + len;

  svm_fifo_trace_add (f, head, len, 2);

  /* collect out-of-order segments */
  if (PREDICT_FALSE (f->ooos_list_head != OOO_SEGMENT_INVALID_INDEX))
    {
      len += ooo_segment_try_collect (f, len, &tail);
      /* Tail chunk might've changed even if nothing was collected */
      f->tail_chunk = f_lookup_clear_enq_chunks (f, old_tail_c, tail);
      f->ooo_enq = 0;
    }

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
int
svm_fifo_enqueue_with_offset (svm_fifo_t * f, u32 offset, u32 len, u8 * src)
{
  u32 tail, head, free_count, enq_pos;

  f_load_head_tail_prod (f, &head, &tail);

  /* free space in fifo can only increase during enqueue: SPSC */
  free_count = f_free_count (f, head, tail);
  f->ooos_newest = OOO_SEGMENT_INVALID_INDEX;

  /* will this request fit? */
  if ((len + offset) > free_count)
    return SVM_FIFO_EFULL;

  enq_pos = tail + offset;

  if (f_pos_gt (enq_pos + len, f_chunk_end (f->end_chunk)))
    {
      if (PREDICT_FALSE (f_try_chunk_alloc (f, head, tail, offset + len)))
	return SVM_FIFO_EGROW;
    }

  svm_fifo_trace_add (f, offset, len, 1);
  ooo_segment_add (f, offset, head, tail, len);

  if (!f->ooo_enq || !f_chunk_includes_pos (f->ooo_enq, enq_pos))
    f_update_ooo_enq (f, enq_pos, enq_pos + len);

  svm_fifo_copy_to_chunk (f, f->ooo_enq, enq_pos, src, len, &f->ooo_enq);

  return 0;
}

/**
 * Advance tail
 */
void
svm_fifo_enqueue_nocopy (svm_fifo_t * f, u32 len)
{
  u32 tail;

  ASSERT (len <= svm_fifo_max_enqueue_prod (f));
  /* load-relaxed: producer owned index */
  tail = f->tail;
  tail = tail + len;

  if (rb_tree_is_init (&f->ooo_enq_lookup))
    {
      f->tail_chunk = f_lookup_clear_enq_chunks (f, f->tail_chunk, tail);
      f->ooo_enq = 0;
    }
  else
    {
      f->tail_chunk = svm_fifo_find_next_chunk (f, f->tail_chunk, tail);
    }

  /* store-rel: producer owned index (paired with load-acq in consumer) */
  clib_atomic_store_rel_n (&f->tail, tail);
}

always_inline svm_fifo_chunk_t *
f_unlink_chunks (svm_fifo_t * f, u32 end_pos, u8 maybe_ooo)
{
  svm_fifo_chunk_t *start, *prev = 0, *c;
  rb_tree_t *rt;
  rb_node_t *n;

  ASSERT (!f_chunk_includes_pos (f->start_chunk, end_pos));

  if (maybe_ooo)
    rt = &f->ooo_deq_lookup;

  c = f->start_chunk;

  do
    {
      if (maybe_ooo && c->deq_rb_index != RBTREE_TNIL_INDEX)
	{
	  n = rb_node (rt, c->deq_rb_index);
	  ASSERT (n == f_find_node_rbtree (rt, c->start_byte));
	  rb_tree_del_node (rt, n);
	  c->deq_rb_index = RBTREE_TNIL_INDEX;
	}
      if (!c->next)
	break;
      prev = c;
      c = c->next;
    }
  while (!f_chunk_includes_pos (c, end_pos));

  if (maybe_ooo)
    {
      if (f->ooo_deq && f_pos_lt (f->ooo_deq->start_byte, f_chunk_end (c)))
	f->ooo_deq = 0;
    }
  else
    {
      if (PREDICT_FALSE (f->ooo_deq != 0))
	f->ooo_deq = 0;
    }

  /* Avoid unlinking the last chunk */
  if (!prev)
    return 0;

  prev->next = 0;
  start = f->start_chunk;
  f->start_chunk = c;

  return start;
}

int
svm_fifo_dequeue (svm_fifo_t * f, u32 len, u8 * dst)
{
  u32 tail, head, cursize;

  f_load_head_tail_cons (f, &head, &tail);

  /* current size of fifo can only increase during dequeue: SPSC */
  cursize = f_cursize (f, head, tail);

  if (PREDICT_FALSE (cursize == 0))
    return SVM_FIFO_EEMPTY;

  len = clib_min (cursize, len);

  if (!f->head_chunk)
    f->head_chunk = svm_fifo_find_chunk (f, head);

  svm_fifo_copy_from_chunk (f, f->head_chunk, head, dst, len, &f->head_chunk);
  head = head + len;

  /* In order dequeues are not supported in combination with ooo peeking.
   * Use svm_fifo_dequeue_drop instead. */
  ASSERT (rb_tree_n_nodes (&f->ooo_deq_lookup) <= 1);

  if (f_pos_geq (head, f_chunk_end (f->start_chunk)))
    fsh_collect_chunks (f->fs_hdr, f->slice_index,
			f_unlink_chunks (f, head, 0));

  /* store-rel: consumer owned index (paired with load-acq in producer) */
  clib_atomic_store_rel_n (&f->head, head);

  return len;
}

int
svm_fifo_peek (svm_fifo_t * f, u32 offset, u32 len, u8 * dst)
{
  u32 tail, head, cursize, head_idx;

  f_load_head_tail_cons (f, &head, &tail);

  /* current size of fifo can only increase during peek: SPSC */
  cursize = f_cursize (f, head, tail);

  if (PREDICT_FALSE (cursize < offset))
    return SVM_FIFO_EEMPTY;

  len = clib_min (cursize - offset, len);
  head_idx = head + offset;

  if (!f->ooo_deq || !f_chunk_includes_pos (f->ooo_deq, head_idx))
    f_update_ooo_deq (f, head_idx, head_idx + len);

  svm_fifo_copy_from_chunk (f, f->ooo_deq, head_idx, dst, len, &f->ooo_deq);
  return len;
}

int
svm_fifo_dequeue_drop (svm_fifo_t * f, u32 len)
{
  u32 total_drop_bytes, tail, head, cursize;

  f_load_head_tail_cons (f, &head, &tail);

  /* number of bytes available */
  cursize = f_cursize (f, head, tail);
  if (PREDICT_FALSE (cursize == 0))
    return SVM_FIFO_EEMPTY;

  /* number of bytes we're going to drop */
  total_drop_bytes = clib_min (cursize, len);

  svm_fifo_trace_add (f, tail, total_drop_bytes, 3);

  /* move head */
  head = head + total_drop_bytes;

  if (f_pos_geq (head, f_chunk_end (f->start_chunk)))
    {
      fsh_collect_chunks (f->fs_hdr, f->slice_index,
			  f_unlink_chunks (f, head, 1));
      f->head_chunk =
	f_chunk_includes_pos (f->start_chunk, head) ? f->start_chunk : 0;
    }

  /* store-rel: consumer owned index (paired with load-acq in producer) */
  clib_atomic_store_rel_n (&f->head, head);

  return total_drop_bytes;
}

/**
 * Drop all data from fifo
 *
 */
void
svm_fifo_dequeue_drop_all (svm_fifo_t * f)
{
  u32 head, tail;

  f_load_head_tail_all_acq (f, &head, &tail);

  if (!f->head_chunk || !f_chunk_includes_pos (f->head_chunk, head))
    f->head_chunk = svm_fifo_find_chunk (f, head);

  f->head_chunk = f_lookup_clear_deq_chunks (f, f->head_chunk, tail);

  if (f_pos_geq (tail, f_chunk_end (f->start_chunk)))
    fsh_collect_chunks (f->fs_hdr, f->slice_index,
			f_unlink_chunks (f, tail, 0));

  /* store-rel: consumer owned index (paired with load-acq in producer) */
  clib_atomic_store_rel_n (&f->head, tail);
}

int
svm_fifo_fill_chunk_list (svm_fifo_t * f)
{
  u32 head, tail;

  f_load_head_tail_prod (f, &head, &tail);

  if (f_chunk_end (f->end_chunk) - head >= f->size)
    return 0;

  if (f_try_chunk_alloc (f, head, tail, f->size - (tail - head)))
    return SVM_FIFO_EGROW;

  return 0;
}

int
svm_fifo_segments (svm_fifo_t * f, svm_fifo_seg_t * fs, u32 n_segs,
		   u32 max_bytes)
{
  u32 cursize, to_read, head, tail, fs_index = 1, n_bytes, head_pos, len;
  svm_fifo_chunk_t *c = f->head_chunk;

  f_load_head_tail_cons (f, &head, &tail);

  /* consumer function, cursize can only increase while we're working */
  cursize = f_cursize (f, head, tail);

  if (PREDICT_FALSE (cursize == 0))
    return SVM_FIFO_EEMPTY;

  to_read = clib_min (cursize, max_bytes);

  head_pos = head - c->start_byte;
  fs[0].data = c->data + head_pos;
  fs[0].len = c->length - head_pos;
  n_bytes = fs[0].len;
  c = c->next;

  while (n_bytes < to_read && fs_index < n_segs)
    {
      len = clib_min (c->length, to_read - n_bytes);
      fs[fs_index].data = c->data;
      fs[fs_index].len = len;
      n_bytes += len;
      c = c->next;
      fs_index += 1;
    }

  return n_bytes;
}

//void
//svm_fifo_segments_free (svm_fifo_t * f, svm_fifo_seg_t * fs)
//{
//  u32 head;
//
//  /* consumer owned index */
//  head = f->head;
//
//  ASSERT (fs[0].data == f->head_chunk->data + head);
//  head = (head + fs[0].len + fs[1].len);
//  /* store-rel: consumer owned index (paired with load-acq in producer) */
//  clib_atomic_store_rel_n (&f->head, head);
//}

/**
 * Clones fifo
 *
 * Assumptions:
 * - no prod and cons are accessing either dest or src fifo
 * - fifo is not multi chunk
 */
void
svm_fifo_clone (svm_fifo_t * df, svm_fifo_t * sf)
{
  u32 head, tail;

  /* Support only single chunk clones for now */
  ASSERT (svm_fifo_n_chunks (sf) == 1);

  clib_memcpy_fast (df->head_chunk->data, sf->head_chunk->data, sf->size);

  f_load_head_tail_all_acq (sf, &head, &tail);
  clib_atomic_store_rel_n (&df->head, head);
  clib_atomic_store_rel_n (&df->tail, tail);
}

u32
svm_fifo_n_ooo_segments (svm_fifo_t * f)
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
svm_fifo_init_pointers (svm_fifo_t * f, u32 head, u32 tail)
{
  svm_fifo_chunk_t *c;

  clib_atomic_store_rel_n (&f->head, head);
  clib_atomic_store_rel_n (&f->tail, tail);

  c = svm_fifo_find_chunk (f, head);
  ASSERT (c != 0);
  f->head_chunk = f->ooo_deq = c;
  c = svm_fifo_find_chunk (f, tail);
  ASSERT (c != 0);
  f->tail_chunk = f->ooo_enq = c;
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

u8
svm_fifo_is_sane (svm_fifo_t * f)
{
  svm_fifo_chunk_t *tmp;

  if (f->head_chunk && !f_chunk_includes_pos (f->head_chunk, f->head))
    return 0;
  if (f->tail_chunk && !f_chunk_includes_pos (f->tail_chunk, f->tail))
    return 0;
  if (f->ooo_deq)
    {
      if (rb_tree_is_init (&f->ooo_deq_lookup))
	{
	  if (f_pos_lt (f->ooo_deq->start_byte, f->start_chunk->start_byte)
	      || f_pos_gt (f->ooo_deq->start_byte,
			   f_chunk_end (f->end_chunk)))
	    return 0;

	  tmp = f_find_chunk_rbtree (&f->ooo_deq_lookup,
				     f->ooo_deq->start_byte);
	}
      else
	tmp = svm_fifo_find_chunk (f, f->ooo_deq->start_byte);
      if (tmp != f->ooo_deq)
	return 0;
    }
  if (f->ooo_enq)
    {
      if (rb_tree_is_init (&f->ooo_enq_lookup))
	{
	  if (f_pos_lt (f->ooo_enq->start_byte, f->start_chunk->start_byte)
	      || f_pos_gt (f->ooo_enq->start_byte,
			   f_chunk_end (f->end_chunk)))
	    return 0;

	  tmp = f_find_chunk_rbtree (&f->ooo_enq_lookup,
				     f->ooo_enq->start_byte);
	}
      else
	{
	  tmp = svm_fifo_find_next_chunk (f, f->tail_chunk,
					  f->ooo_enq->start_byte);
	}
      if (tmp != f->ooo_enq)
	return 0;
    }

  if (f->start_chunk->next)
    {
      svm_fifo_chunk_t *c, *prev = 0, *tmp;
      u32 chunks_bytes = 0;

      c = f->start_chunk;
      do
	{
	  tmp = svm_fifo_find_chunk (f, c->start_byte);
	  if (tmp != c)
	    return 0;
	  if (prev && (prev->start_byte + prev->length != c->start_byte))
	    return 0;

	  if (c->enq_rb_index != RBTREE_TNIL_INDEX)
	    {
	      tmp = f_find_chunk_rbtree (&f->ooo_enq_lookup, c->start_byte);
	      if (tmp)
		{
		  if (tmp != c)
		    return 0;
		}
	    }
	  if (c->deq_rb_index != RBTREE_TNIL_INDEX)
	    {
	      tmp = f_find_chunk_rbtree (&f->ooo_deq_lookup, c->start_byte);
	      if (tmp)
		{
		  if (tmp != c)
		    return 0;
		}
	    }

	  chunks_bytes += c->length;
	  prev = c;
	  c = c->next;
	}
      while (c);

      if (chunks_bytes < f->tail - f->head)
	return 0;
    }

  return 1;
}

u32
svm_fifo_n_chunks (svm_fifo_t * f)
{
  svm_fifo_chunk_t *c;
  int n_chunks = 0;

  c = f->start_chunk;
  while (c)
    {
      n_chunks++;
      c = c->next;
    }

  return n_chunks;
}

u8 *
format_ooo_segment (u8 * s, va_list * args)
{
  svm_fifo_t __clib_unused *f = va_arg (*args, svm_fifo_t *);
  ooo_segment_t *seg = va_arg (*args, ooo_segment_t *);
  s = format (s, "[%u, %u], len %u, next %d, prev %d", seg->start,
	      seg->start + seg->length, seg->length, seg->next, seg->prev);
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
  svm_fifo_t *placeholder_fifo;

  if (!f)
    return s;

#if SVM_FIFO_TRACE
  trace = f->trace;
  trace_len = vec_len (trace);
#else
  trace = 0;
  trace_len = 0;
#endif

  placeholder_fifo = svm_fifo_alloc (f->size);
  svm_fifo_init (f, f->size);
  clib_memset (f->head_chunk->data, 0xFF, f->size);
  vec_validate (data, f->size);
  for (i = 0; i < vec_len (data); i++)
    data[i] = i;

  for (i = 0; i < trace_len; i++)
    {
      offset = trace[i].offset;
      if (trace[i].action == 1)
	{
	  if (verbose)
	    s = format (s, "adding [%u, %u]:", trace[i].offset,
			(trace[i].offset + trace[i].len));
	  svm_fifo_enqueue_with_offset (placeholder_fifo, trace[i].offset,
					trace[i].len, &data[offset]);
	}
      else if (trace[i].action == 2)
	{
	  if (verbose)
	    s = format (s, "adding [%u, %u]:", 0, trace[i].len);
	  svm_fifo_enqueue (placeholder_fifo, trace[i].len, &data[offset]);
	}
      else if (!no_read)
	{
	  if (verbose)
	    s = format (s, "read: %u", trace[i].len);
	  svm_fifo_dequeue_drop (placeholder_fifo, trace[i].len);
	}
      if (verbose)
	s = format (s, "%U", format_svm_fifo, placeholder_fifo, 1);
    }

  s = format (s, "result: %U", format_svm_fifo, placeholder_fifo, 1);

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
  s = format (s, "cursize %u nitems %u has_event %d min_alloc %u\n",
	      svm_fifo_max_dequeue (f), f->size, f->has_event, f->min_alloc);
  s = format (s, "%Uhead %u tail %u segment manager %u\n", format_white_space,
	      indent, f->head, f->tail, f->segment_manager);

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

#endif
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
