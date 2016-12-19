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

/* Heaps of objects of type T (e.g. int, struct foo, ...).

   Usage.  To declare a null heap:

     T * heap = 0;

   To allocate:

     offset = heap_alloc (heap, size, handle);

   New object is heap[offset] ... heap[offset + size]
   Handle is used to free/query object.

   To free object:

     heap_dealloc (heap, handle);

   To query the size of an object:

     heap_size (heap, handle)

*/

#ifndef included_heap_h
#define included_heap_h

#include <vppinfra/clib.h>
#include <vppinfra/cache.h>
#include <vppinfra/hash.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>

/* Doubly linked list of elements. */
typedef struct
{
  /* Offset of this element (plus free bit).
     If element is free, data at offset contains pointer to free list. */
  u32 offset;

  /* Index of next and previous elements relative to current element. */
  i32 next, prev;
} heap_elt_t;

/* Use high bit of offset as free bit. */
#define HEAP_ELT_FREE_BIT	(1 << 31)

always_inline uword
heap_is_free (heap_elt_t * e)
{
  return (e->offset & HEAP_ELT_FREE_BIT) != 0;
}

always_inline uword
heap_offset (heap_elt_t * e)
{
  return e->offset & ~HEAP_ELT_FREE_BIT;
}

always_inline heap_elt_t *
heap_next (heap_elt_t * e)
{
  return e + e->next;
}

always_inline heap_elt_t *
heap_prev (heap_elt_t * e)
{
  return e + e->prev;
}

always_inline uword
heap_elt_size (void *v, heap_elt_t * e)
{
  heap_elt_t *n = heap_next (e);
  uword next_offset = n != e ? heap_offset (n) : vec_len (v);
  return next_offset - heap_offset (e);
}

/* Sizes are binned.  Sizes 1 to 2^log2_small_bins have their
   own free lists.  Larger sizes are grouped in powers of two. */
#define HEAP_LOG2_SMALL_BINS	(5)
#define HEAP_SMALL_BINS		(1 << HEAP_LOG2_SMALL_BINS)
#define HEAP_N_BINS		(2 * HEAP_SMALL_BINS)

/* Header for heaps. */
typedef struct
{
  /* Vector of used and free elements. */
  heap_elt_t *elts;

  /* For elt_bytes < sizeof (u32) we need some extra space
     per elt to store free list index. */
  u32 *small_free_elt_free_index;

  /* Vector of free indices of elts array. */
  u32 *free_elts;

  /* Indices of free elts indexed by size bin. */
  u32 **free_lists;

  format_function_t *format_elt;

  /* Used for validattion/debugging. */
  uword *used_elt_bitmap;

  /* First and last element of doubly linked chain of elements. */
  u32 head, tail;

  u32 used_count, max_len;

  /* Number of bytes in a help element. */
  u32 elt_bytes;

  u32 flags;
  /* Static heaps are made from external memory given to
     us by user and are not re-sizeable vectors. */
#define HEAP_IS_STATIC (1)
} heap_header_t;

/* Start of heap elements is always cache aligned. */
#define HEAP_DATA_ALIGN (CLIB_CACHE_LINE_BYTES)

always_inline heap_header_t *
heap_header (void *v)
{
  return vec_header (v, sizeof (heap_header_t));
}

always_inline uword
heap_header_bytes ()
{
  return vec_header_bytes (sizeof (heap_header_t));
}

always_inline void
heap_dup_header (heap_header_t * old, heap_header_t * new)
{
  uword i;

  new[0] = old[0];
  new->elts = vec_dup (new->elts);
  new->free_elts = vec_dup (new->free_elts);
  new->free_lists = vec_dup (new->free_lists);
  for (i = 0; i < vec_len (new->free_lists); i++)
    new->free_lists[i] = vec_dup (new->free_lists[i]);
  new->used_elt_bitmap = clib_bitmap_dup (new->used_elt_bitmap);
  new->small_free_elt_free_index = vec_dup (new->small_free_elt_free_index);
}

/* Make a duplicate copy of a heap. */
#define heap_dup(v) _heap_dup(v, vec_len (v) * sizeof (v[0]))

always_inline void *
_heap_dup (void *v_old, uword v_bytes)
{
  heap_header_t *h_old, *h_new;
  void *v_new;

  h_old = heap_header (v_old);

  if (!v_old)
    return v_old;

  v_new = 0;
  v_new =
    _vec_resize (v_new, _vec_len (v_old), v_bytes, sizeof (heap_header_t),
		 HEAP_DATA_ALIGN);
  h_new = heap_header (v_new);
  heap_dup_header (h_old, h_new);
  clib_memcpy (v_new, v_old, v_bytes);
  return v_new;
}

always_inline uword
heap_elts (void *v)
{
  heap_header_t *h = heap_header (v);
  return h->used_count;
}

uword heap_bytes (void *v);

always_inline void *
_heap_new (u32 len, u32 n_elt_bytes)
{
  void *v = _vec_resize (0, len, (uword) len * n_elt_bytes,
			 sizeof (heap_header_t),
			 HEAP_DATA_ALIGN);
  heap_header (v)->elt_bytes = n_elt_bytes;
  return v;
}

#define heap_new(v) (v) = _heap_new (0, sizeof ((v)[0]))

always_inline void
heap_set_format (void *v, format_function_t * format_elt)
{
  ASSERT (v);
  heap_header (v)->format_elt = format_elt;
}

always_inline void
heap_set_max_len (void *v, uword max_len)
{
  ASSERT (v);
  heap_header (v)->max_len = max_len;
}

always_inline uword
heap_get_max_len (void *v)
{
  return v ? heap_header (v)->max_len : 0;
}

/* Create fixed size heap with given block of memory. */
always_inline void *
heap_create_from_memory (void *memory, uword max_len, uword elt_bytes)
{
  heap_header_t *h;
  void *v;

  if (max_len * elt_bytes < sizeof (h[0]))
    return 0;

  h = memory;
  memset (h, 0, sizeof (h[0]));
  h->max_len = max_len;
  h->elt_bytes = elt_bytes;
  h->flags = HEAP_IS_STATIC;

  v = (void *) (memory + heap_header_bytes ());
  _vec_len (v) = 0;
  return v;
}

/* Execute BODY for each allocated heap element. */
#define heap_foreach(var,len,heap,body)			\
do {							\
  if (vec_len (heap) > 0)				\
    {							\
      heap_header_t * _h = heap_header (heap);		\
      heap_elt_t * _e   = _h->elts + _h->head;		\
      heap_elt_t * _end = _h->elts + _h->tail;		\
      while (1)						\
	{						\
	  if (! heap_is_free (_e))			\
	    {						\
	      (var) = (heap) + heap_offset (_e);	\
	      (len) = heap_elt_size ((heap), _e);	\
	      do { body; } while (0);			\
	    }						\
	  if (_e == _end)				\
	    break;					\
	  _e = heap_next (_e);				\
	}						\
    }							\
} while (0)

#define heap_elt_at_index(v,index) vec_elt_at_index(v,index)

always_inline heap_elt_t *
heap_get_elt (void *v, uword handle)
{
  heap_header_t *h = heap_header (v);
  heap_elt_t *e = vec_elt_at_index (h->elts, handle);
  ASSERT (!heap_is_free (e));
  return e;
}

#define heap_elt_with_handle(v,handle)			\
({							\
  heap_elt_t * _e = heap_get_elt ((v), (handle));	\
  (v) + heap_offset (_e);				\
})

always_inline uword
heap_is_free_handle (void *v, uword heap_handle)
{
  heap_header_t *h = heap_header (v);
  heap_elt_t *e = vec_elt_at_index (h->elts, heap_handle);
  return heap_is_free (e);
}

extern uword heap_len (void *v, word handle);

/* Low level allocation call. */
extern void *_heap_alloc (void *v, uword size, uword alignment,
			  uword elt_bytes, uword * offset, uword * handle);

#define heap_alloc_aligned(v,size,align,handle)			\
({								\
  uword _o, _h;							\
  uword _a = (align);						\
  uword _s = (size);						\
  (v) = _heap_alloc ((v), _s, _a, sizeof ((v)[0]), &_o, &_h);	\
  (handle) = _h;						\
  _o;								\
})

#define heap_alloc(v,size,handle) heap_alloc_aligned((v),(size),0,(handle))

extern void heap_dealloc (void *v, uword handle);
extern void heap_validate (void *v);

/* Format heap internal data structures as string. */
extern u8 *format_heap (u8 * s, va_list * va);

void *_heap_free (void *v);

#define heap_free(v) (v)=_heap_free(v)

#endif /* included_heap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
