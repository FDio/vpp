/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/*
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <vppinfra/cache.h>	/* for CLIB_CACHE_LINE_BYTES */
#include <vppinfra/mem.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>
#include <vppinfra/heap.h>
#include <vppinfra/error.h>

always_inline heap_elt_t *
elt_at (heap_header_t * h, uword i)
{
  ASSERT (i < vec_len (h->elts));
  return h->elts + i;
}

always_inline heap_elt_t *
last (heap_header_t * h)
{
  return elt_at (h, h->tail);
}

always_inline heap_elt_t *
first (heap_header_t * h)
{
  return elt_at (h, h->head);
}

/* Objects sizes are binned into N_BINS bins.
   Objects with size <= SMALL_BINS have their own bins.
   Larger objects are grouped together in power or 2 sized
   bins.

   Sizes are in units of elt_bytes bytes. */

/* Convert size to bin. */
always_inline uword
size_to_bin (uword size)
{
  uword bin;

  ASSERT (size > 0);

  if (size <= HEAP_SMALL_BINS)
    {
      bin = size - 1;
      if (size == 0)
	bin = 0;
    }
  else
    {
      bin = HEAP_SMALL_BINS + max_log2 (size) - (HEAP_LOG2_SMALL_BINS + 1);
      if (bin >= HEAP_N_BINS)
	bin = HEAP_N_BINS - 1;
    }

  return bin;
}

/* Convert bin to size. */
always_inline __attribute__ ((unused))
     uword bin_to_size (uword bin)
{
  uword size;

  if (bin <= HEAP_SMALL_BINS - 1)
    size = bin + 1;
  else
    size = (uword) 1 << ((bin - HEAP_SMALL_BINS) + HEAP_LOG2_SMALL_BINS + 1);

  return size;
}

static void
elt_delete (heap_header_t * h, heap_elt_t * e)
{
  heap_elt_t *l = vec_end (h->elts) - 1;

  ASSERT (e >= h->elts && e <= l);

  /* Update doubly linked pointers. */
  {
    heap_elt_t *p = heap_prev (e);
    heap_elt_t *n = heap_next (e);

    if (p == e)
      {
	n->prev = 0;
	h->head = n - h->elts;
      }
    else if (n == e)
      {
	p->next = 0;
	h->tail = p - h->elts;
      }
    else
      {
	p->next = n - p;
	n->prev = p - n;
      }
  }

  /* Add to index free list or delete from end. */
  if (e < l)
    vec_add1 (h->free_elts, e - h->elts);
  else
    _vec_len (h->elts)--;
}

/*
  Before: P ... E
  After : P ... NEW ... E
*/
always_inline void
elt_insert_before (heap_header_t * h, heap_elt_t * e, heap_elt_t * new)
{
  heap_elt_t *p = heap_prev (e);

  if (p == e)
    {
      new->prev = 0;
      new->next = e - new;
      p->prev = new - p;
      h->head = new - h->elts;
    }
  else
    {
      new->prev = p - new;
      new->next = e - new;
      e->prev = new - e;
      p->next = new - p;
    }
}

/*
  Before: E ... N
  After : E ... NEW ... N
*/
always_inline void
elt_insert_after (heap_header_t * h, heap_elt_t * e, heap_elt_t * new)
{
  heap_elt_t *n = heap_next (e);

  if (n == e)
    {
      new->next = 0;
      new->prev = e - new;
      e->next = new - e;
      h->tail = new - h->elts;
    }
  else
    {
      new->prev = e - new;
      new->next = n - new;
      e->next = new - e;
      n->prev = new - n;
    }
}

always_inline heap_elt_t *
elt_new (heap_header_t * h)
{
  heap_elt_t *e;
  uword l;
  if ((l = vec_len (h->free_elts)) > 0)
    {
      e = elt_at (h, h->free_elts[l - 1]);
      _vec_len (h->free_elts) -= 1;
    }
  else
    vec_add2 (h->elts, e, 1);
  return e;
}

/* Return pointer to object at given offset.
   Used to write free list index of free objects. */
always_inline u32 *
elt_data (void *v, heap_elt_t * e)
{
  heap_header_t *h = heap_header (v);
  return v + heap_offset (e) * h->elt_bytes;
}

always_inline void
set_free_elt (void *v, heap_elt_t * e, uword fi)
{
  heap_header_t *h = heap_header (v);

  e->offset |= HEAP_ELT_FREE_BIT;
  if (h->elt_bytes >= sizeof (u32))
    {
      *elt_data (v, e) = fi;
    }
  else
    {
      /* For elt_bytes < 4 we must store free index in separate
         vector. */
      uword elt_index = e - h->elts;
      vec_validate (h->small_free_elt_free_index, elt_index);
      h->small_free_elt_free_index[elt_index] = fi;
    }
}

always_inline uword
get_free_elt (void *v, heap_elt_t * e, uword * bin_result)
{
  heap_header_t *h = heap_header (v);
  uword fb, fi;

  ASSERT (heap_is_free (e));
  fb = size_to_bin (heap_elt_size (v, e));

  if (h->elt_bytes >= sizeof (u32))
    {
      fi = *elt_data (v, e);
    }
  else
    {
      uword elt_index = e - h->elts;
      fi = vec_elt (h->small_free_elt_free_index, elt_index);
    }

  *bin_result = fb;
  return fi;
}

always_inline void
remove_free_block (void *v, uword b, uword i)
{
  heap_header_t *h = heap_header (v);
  uword l;

  ASSERT (b < vec_len (h->free_lists));
  ASSERT (i < vec_len (h->free_lists[b]));

  l = vec_len (h->free_lists[b]);

  if (i < l - 1)
    {
      uword t = h->free_lists[b][l - 1];
      h->free_lists[b][i] = t;
      set_free_elt (v, elt_at (h, t), i);
    }
  _vec_len (h->free_lists[b]) = l - 1;
}

static heap_elt_t *
search_free_list (void *v, uword size)
{
  heap_header_t *h;
  heap_elt_t *f, *u;
  uword b, fb, f_size, f_index;
  word s, l;

  if (!v)
    return 0;

  h = heap_header (v);
  /* Search free lists for bins >= given size. */
  for (b = size_to_bin (size); b < vec_len (h->free_lists); b++)
    if ((l = vec_len (h->free_lists[b])) > 0)
      {
	/* Find an object that is large enough.
	   Search list in reverse so that more recently freed objects will be
	   allocated again sooner. */
	u8 found = 0;
	do
	  {
	    l--;
	    f_index = h->free_lists[b][l];
	    f = elt_at (h, f_index);
	    f_size = heap_elt_size (v, f);
	    if ((s = f_size - size) >= 0)
	      {
		found = 1;
		break;
	      }
	  }
	while (l > 0);

	/* If we fail to find a large enough object, try the next larger size. */
	if (found == 0)
	  continue;

	ASSERT (heap_is_free (f));

	/* Link in used object (u) after free object (f). */
	if (s == 0)
	  {
	    u = f;
	    fb = HEAP_N_BINS;
	  }
	else
	  {
	    u = elt_new (h);
	    f = elt_at (h, f_index);
	    elt_insert_after (h, f, u);
	    fb = size_to_bin (s);
	  }

	u->offset = heap_offset (f) + s;

	if (fb != b)
	  {
	    if (fb < HEAP_N_BINS)
	      {
		uword i;
		vec_validate (h->free_lists, fb);
		i = vec_len (h->free_lists[fb]);
		vec_add1 (h->free_lists[fb], f - h->elts);
		set_free_elt (v, f, i);
	      }

	    remove_free_block (v, b, l);
	  }

	return u;
      }

  return 0;
}

static void combine_free_blocks (void *v, heap_elt_t * e0, heap_elt_t * e1);

static inline void
dealloc_elt (void *v, heap_elt_t * e)
{
  heap_header_t *h = heap_header (v);
  uword b, l;
  heap_elt_t *n, *p;

  b = size_to_bin (heap_elt_size (v, e));
  vec_validate (h->free_lists, b);
  l = vec_len (h->free_lists[b]);
  vec_add1 (h->free_lists[b], e - h->elts);
  set_free_elt (v, e, l);

  /* See if we can combine the block we just freed with neighboring free blocks. */
  p = heap_prev (e);
  if (!heap_is_free (p))
    p = e;

  n = heap_next (e);
  if (!heap_is_free (n))
    n = e;

  if (p != n)
    combine_free_blocks (v, p, n);
}

__clib_export void *
_heap_alloc (void *v,
	     uword size,
	     uword align,
	     uword elt_bytes, uword * offset_return, uword * handle_return)
{
  uword offset = 0, align_size;
  heap_header_t *h;
  heap_elt_t *e;

  if (size == 0)
    goto error;

  /* Round up alignment to power of 2. */
  if (align <= 1)
    {
      align = 0;
      align_size = size;
    }
  else
    {
      align = max_pow2 (align);
      align_size = size + align - 1;
    }

  e = search_free_list (v, align_size);

  /* If nothing found on free list, allocate object from end of vector. */
  if (!e)
    {
      uword max_len;

      offset = vec_len (v);
      max_len = heap_get_max_len (v);

      if (max_len && offset + align_size > max_len)
	goto error;

      if (!v || !(heap_header (v)->flags & HEAP_IS_STATIC))
	v = _vec_resize (v,
			 align_size,
			 (offset + align_size) * elt_bytes,
			 sizeof (h[0]), HEAP_DATA_ALIGN);
      else
	_vec_len (v) += align_size;

      if (offset == 0)
	{
	  h = heap_header (v);
	  h->elt_bytes = elt_bytes;
	}
    }

  h = heap_header (v);

  /* Add new element to doubly linked chain of elements. */
  if (!e)
    {
      e = elt_new (h);
      e->offset = offset;
      elt_insert_after (h, last (h), e);
    }

  if (align > 0)
    {
      uword e_index;
      uword new_offset, old_offset;

      old_offset = e->offset;
      new_offset = (old_offset + align - 1) & ~(align - 1);
      e->offset = new_offset;
      e_index = e - h->elts;

      /* Free fragments before and after aligned object. */
      if (new_offset > old_offset)
	{
	  heap_elt_t *before_e = elt_new (h);
	  before_e->offset = old_offset;
	  elt_insert_before (h, h->elts + e_index, before_e);
	  dealloc_elt (v, before_e);
	}

      if (new_offset + size < old_offset + align_size)
	{
	  heap_elt_t *after_e = elt_new (h);
	  after_e->offset = new_offset + size;
	  elt_insert_after (h, h->elts + e_index, after_e);
	  dealloc_elt (v, after_e);
	}

      e = h->elts + e_index;
    }

  h->used_count++;

  /* Keep track of used elements when debugging.
     This allows deallocation to check that passed objects are valid. */
  if (CLIB_DEBUG > 0)
    {
      uword handle = e - h->elts;
      ASSERT (!clib_bitmap_get (h->used_elt_bitmap, handle));
      h->used_elt_bitmap = clib_bitmap_ori (h->used_elt_bitmap, handle);
    }

  *offset_return = e->offset;
  *handle_return = e - h->elts;
  return v;

error:
  *offset_return = *handle_return = ~0;
  return v;
}

__clib_export void
heap_dealloc (void *v, uword handle)
{
  heap_header_t *h = heap_header (v);
  heap_elt_t *e;

  ASSERT (handle < vec_len (h->elts));

  /* For debugging we keep track of indices for valid objects.
     We make sure user is not trying to free object with an invalid index. */
  if (CLIB_DEBUG > 0)
    {
      ASSERT (clib_bitmap_get (h->used_elt_bitmap, handle));
      h->used_elt_bitmap = clib_bitmap_andnoti (h->used_elt_bitmap, handle);
    }

  h->used_count--;

  e = h->elts + handle;
  ASSERT (!heap_is_free (e));

  dealloc_elt (v, e);
}

/* While freeing objects at INDEX we noticed free blocks i0 <= index and
   i1 >= index.  We combine these two or three blocks into one big free block. */
static void
combine_free_blocks (void *v, heap_elt_t * e0, heap_elt_t * e1)
{
  heap_header_t *h = heap_header (v);
  uword total_size, i, b, tb, ti, i_last, g_offset;
  heap_elt_t *e;

  struct
  {
    u32 index;
    u32 bin;
    u32 bin_index;
  } f[3], g;

  /* Compute total size of free objects i0 through i1. */
  total_size = 0;
  for (i = 0, e = e0; 1; e = heap_next (e), i++)
    {
      ASSERT (i < ARRAY_LEN (f));

      ti = get_free_elt (v, e, &tb);

      ASSERT (tb < vec_len (h->free_lists));
      ASSERT (ti < vec_len (h->free_lists[tb]));

      f[i].index = h->free_lists[tb][ti];
      f[i].bin = tb;
      f[i].bin_index = ti;

      total_size += heap_elt_size (v, elt_at (h, f[i].index));

      if (e == e1)
	{
	  i_last = i;
	  break;
	}
    }

  /* Compute combined bin.  See if all objects can be
     combined into existing bin. */
  b = size_to_bin (total_size);
  g.index = g.bin_index = 0;
  for (i = 0; i <= i_last; i++)
    if (b == f[i].bin)
      {
	g = f[i];
	break;
      }

  /* Make sure we found a bin. */
  if (i > i_last)
    {
      g.index = elt_new (h) - h->elts;
      vec_validate (h->free_lists, b);
      g.bin_index = vec_len (h->free_lists[b]);
      vec_add1 (h->free_lists[b], g.index);
      elt_insert_before (h, elt_at (h, f[0].index), elt_at (h, g.index));
    }

  g_offset = elt_at (h, f[0].index)->offset;

  /* Delete unused bins. */
  for (i = 0; i <= i_last; i++)
    if (g.index != f[i].index)
      {
	ti = get_free_elt (v, elt_at (h, f[i].index), &tb);
	remove_free_block (v, tb, ti);
	elt_delete (h, elt_at (h, f[i].index));
      }

  /* Initialize new element. */
  elt_at (h, g.index)->offset = g_offset;
  set_free_elt (v, elt_at (h, g.index), g.bin_index);
}

__clib_export uword
heap_len (void *v, word handle)
{
  heap_header_t *h = heap_header (v);

  if (CLIB_DEBUG > 0)
    ASSERT (clib_bitmap_get (h->used_elt_bitmap, handle));
  return heap_elt_size (v, elt_at (h, handle));
}

__clib_export void *
_heap_free (void *v)
{
  heap_header_t *h;
  uword b;

  if (!v)
    return v;

  h = heap_header (v);
  clib_bitmap_free (h->used_elt_bitmap);
  for (b = 0; b < vec_len (h->free_lists); b++)
    vec_free (h->free_lists[b]);
  vec_free (h->free_lists);
  vec_free (h->elts);
  vec_free (h->free_elts);
  vec_free (h->small_free_elt_free_index);
  if (!(h->flags & HEAP_IS_STATIC))
    vec_free_h (v, sizeof (h[0]));
  return v;
}

uword
heap_bytes (void *v)
{
  heap_header_t *h;
  uword bytes, b;

  if (!v)
    return 0;

  h = heap_header (v);
  bytes = sizeof (h[0]);
  bytes += vec_len (v) * sizeof (h->elt_bytes);
  for (b = 0; b < vec_len (h->free_lists); b++)
    bytes += vec_capacity (h->free_lists[b], 0);
  bytes += vec_bytes (h->free_lists);
  bytes += vec_capacity (h->elts, 0);
  bytes += vec_capacity (h->free_elts, 0);
  bytes += vec_bytes (h->used_elt_bitmap);

  return bytes;
}

static u8 *
debug_elt (u8 * s, void *v, word i, word n)
{
  heap_elt_t *e, *e0, *e1;
  heap_header_t *h = heap_header (v);
  word j;

  if (vec_len (h->elts) == 0)
    return s;

  if (i < 0)
    e0 = first (h);
  else
    {
      e0 = h->elts + i;
      for (j = 0; j < n / 2; j++)
	e0 = heap_prev (e0);
    }

  if (n < 0)
    e1 = h->elts + h->tail;
  else
    {
      e1 = h->elts + i;
      for (j = 0; j < n / 2; j++)
	e1 = heap_next (e1);
    }

  i = -n / 2;
  for (e = e0; 1; e = heap_next (e))
    {
      if (heap_is_free (e))
	s = format (s, "index %4d, free\n", e - h->elts);
      else if (h->format_elt)
	s = format (s, "%U", h->format_elt, v, elt_data (v, e));
      else
	s = format (s, "index %4d, used\n", e - h->elts);
      i++;
      if (e == e1)
	break;
    }

  return s;
}

__clib_export u8 *
format_heap (u8 *s, va_list *va)
{
  void *v = va_arg (*va, void *);
  uword verbose = va_arg (*va, uword);
  heap_header_t *h = heap_header (v);
  heap_header_t zero;

  clib_memset (&zero, 0, sizeof (zero));

  if (!v)
    h = &zero;

  {
    f64 elt_bytes = vec_len (v) * h->elt_bytes;
    f64 overhead_bytes = heap_bytes (v);

    s = format (s, "heap %p, %6d objects, size %.1fk + overhead %.1fk\n",
		v, h->used_count, elt_bytes / 1024,
		(overhead_bytes - elt_bytes) / 1024);
  }

  if (v && verbose)
    s = debug_elt (s, v, -1, -1);

  return s;
}

__clib_export void
heap_validate (void *v)
{
  heap_header_t *h = heap_header (v);
  uword i, o, s;
  u8 *free_map;
  heap_elt_t *e, *n;

  uword used_count, total_size;
  uword free_count, free_size;

  ASSERT (h->used_count == clib_bitmap_count_set_bits (h->used_elt_bitmap));

  ASSERT (first (h)->prev == 0);
  ASSERT (last (h)->next == 0);

  /* Validate number of elements and size. */
  free_size = free_count = 0;
  for (i = 0; i < vec_len (h->free_lists); i++)
    {
      free_count += vec_len (h->free_lists[i]);
      for (o = 0; o < vec_len (h->free_lists[i]); o++)
	{
	  e = h->elts + h->free_lists[i][o];
	  s = heap_elt_size (v, e);
	  ASSERT (size_to_bin (s) == i);
	  ASSERT (heap_is_free (e));
	  free_size += s;
	}
    }

  {
    uword elt_free_size, elt_free_count;

    used_count = total_size = elt_free_size = elt_free_count = 0;
    for (e = first (h); 1; e = n)
      {
	int is_free = heap_is_free (e);
	used_count++;
	s = heap_elt_size (v, e);
	total_size += s;
	ASSERT (is_free ==
		!clib_bitmap_get (h->used_elt_bitmap, e - h->elts));
	if (is_free)
	  {
	    elt_free_count++;
	    elt_free_size += s;
	  }
	n = heap_next (e);
	if (e == n)
	  {
	    ASSERT (last (h) == n);
	    break;
	  }

	/* We should never have two free adjacent elements. */
	ASSERT (!(heap_is_free (e) && heap_is_free (n)));
      }

    ASSERT (free_count == elt_free_count);
    ASSERT (free_size == elt_free_size);
    ASSERT (used_count == h->used_count + free_count);
    ASSERT (total_size == vec_len (v));
  }

  free_map = vec_new (u8, used_count);

  e = first (h);
  for (i = o = 0; 1; i++)
    {
      ASSERT (heap_offset (e) == o);
      s = heap_elt_size (v, e);

      if (heap_is_free (e))
	{
	  uword fb, fi;

	  fi = get_free_elt (v, e, &fb);

	  ASSERT (fb < vec_len (h->free_lists));
	  ASSERT (fi < vec_len (h->free_lists[fb]));
	  ASSERT (h->free_lists[fb][fi] == e - h->elts);

	  ASSERT (!free_map[i]);
	  free_map[i] = 1;
	}

      n = heap_next (e);

      if (e == n)
	break;

      ASSERT (heap_prev (n) == e);

      o += s;
      e = n;
    }

  vec_free (free_map);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
