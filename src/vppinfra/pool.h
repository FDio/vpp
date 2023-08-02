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
  Copyright (c) 2001, 2002, 2003, 2004 Eliot Dresselhaus

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
/** @file
 * @brief Fixed length block allocator.
   Pools are built from clib vectors and bitmaps. Use pools when
   repeatedly allocating and freeing fixed-size data. Pools are
   fast, and avoid memory fragmentation.
 */

#ifndef included_pool_h
#define included_pool_h

#include <vppinfra/bitmap.h>
#include <vppinfra/error.h>


typedef struct
{
  /** Bitmap of indices of free objects. */
  uword *free_bitmap;

  /** Vector of free indices.  One element for each set bit in bitmap. */
  u32 *free_indices;

  /* The following fields are set for fixed-size, preallocated pools */

  /** Maximum size of the pool, in elements */
  u32 max_elts;

} pool_header_t;

/** Get pool header from user pool pointer */
always_inline pool_header_t *
pool_header (void *v)
{
  return vec_header (v);
}

void _pool_init_fixed (void **pool_ptr, uword elt_sz, uword max_elts,
		       uword align);

/** initialize a fixed-size, preallocated pool */
#define pool_init_fixed(P, E)                                                 \
  _pool_init_fixed ((void **) &(P), _vec_elt_sz (P), E, _vec_align (P, 0));

/** Validate a pool */
always_inline void
pool_validate (void *v)
{
  pool_header_t *p = pool_header (v);
  uword i, n_free_bitmap;

  if (!v)
    return;

  n_free_bitmap = clib_bitmap_count_set_bits (p->free_bitmap);
  ASSERT (n_free_bitmap == vec_len (p->free_indices));
  for (i = 0; i < vec_len (p->free_indices); i++)
    ASSERT (clib_bitmap_get (p->free_bitmap, p->free_indices[i]) == 1);
}

/** Number of active elements in a pool.
 * @return Number of active elements in a pool
 */
always_inline uword
pool_elts (void *v)
{
  uword ret = vec_len (v);
  if (v)
    ret -= vec_len (pool_header (v)->free_indices);
  return ret;
}

/** Number of elements in pool vector.

    @note You probably want to call pool_elts() instead.
*/
#define pool_len(p)	vec_len(p)

/** Number of elements in pool vector (usable as an lvalue)

    @note You probably don't want to use this macro.
*/
#define _pool_len(p)	_vec_len(p)

/** Memory usage of pool header. */
always_inline uword
pool_header_bytes (void *v)
{
  pool_header_t *p = pool_header (v);

  if (!v)
    return 0;

  return vec_bytes (p->free_bitmap) + vec_bytes (p->free_indices);
}

/** Memory usage of pool. */
#define pool_bytes(P) (vec_bytes (P) + pool_header_bytes (P))

/** Local variable naming macro. */
#define _pool_var(v) _pool_##v

/** Number of elements that can fit into pool with current allocation */
#define pool_max_len(P) vec_max_len (P)

/** Number of free elements in pool */
static_always_inline uword
_pool_free_elts (void *p, uword elt_sz)
{
  pool_header_t *ph;
  uword n_free;

  if (p == 0)
    return 0;

  ph = pool_header (p);

  n_free = vec_len (ph->free_indices);

  /* Fixed-size pools have max_elts set non-zero */
  if (ph->max_elts == 0)
    n_free += _vec_max_len (p, elt_sz) - vec_len (p);

  return n_free;
}

#define pool_free_elts(P) _pool_free_elts ((void *) (P), _vec_elt_sz (P))

/** Allocate an object E from a pool P (general version).

   First search free list.  If nothing is free extend vector of objects.
*/

static_always_inline void
_pool_get (void **pp, void **ep, uword align, int zero, uword elt_sz)
{
  uword len = 0;
  void *p = pp[0];
  void *e;
  vec_attr_t va = { .hdr_sz = sizeof (pool_header_t),
		    .elt_sz = elt_sz,
		    .align = align };

  if (p)
    {
      pool_header_t *ph = pool_header (p);
      uword n_free = vec_len (ph->free_indices);

      if (n_free)
	{
	  uword index = ph->free_indices[n_free - 1];
	  e = p + index * elt_sz;
	  ph->free_bitmap =
	    clib_bitmap_andnoti_notrim (ph->free_bitmap, index);
	  vec_set_len (ph->free_indices, n_free - 1);
	  clib_mem_unpoison (e, elt_sz);
	  goto done;
	}

      if (ph->max_elts)
	{
	  clib_warning ("can't expand fixed-size pool");
	  os_out_of_memory ();
	}
    }

  len = vec_len (p);

  /* Nothing on free list, make a new element and return it. */
  p = _vec_realloc_internal (p, len + 1, &va);
  e = p + len * elt_sz;

  _vec_update_pointer (pp, p);

done:
  ep[0] = e;
  if (zero)
    clib_memset_u8 (e, 0, elt_sz);
}

#define _pool_get_aligned_internal(P, E, A, Z)                                \
  _pool_get ((void **) &(P), (void **) &(E), _vec_align (P, A), Z,            \
	     _vec_elt_sz (P))

/** Allocate an object E from a pool P with alignment A */
#define pool_get_aligned(P,E,A) _pool_get_aligned_internal(P,E,A,0)

/** Allocate an object E from a pool P with alignment A and zero it */
#define pool_get_aligned_zero(P,E,A) _pool_get_aligned_internal(P,E,A,1)

/** Allocate an object E from a pool P (unspecified alignment). */
#define pool_get(P,E) pool_get_aligned(P,E,0)

/** Allocate an object E from a pool P and zero it */
#define pool_get_zero(P,E) pool_get_aligned_zero(P,E,0)

always_inline int
_pool_get_will_expand (void *p, uword elt_sz)
{
  pool_header_t *ph;
  uword len;

  if (p == 0)
    return 1;

  ph = pool_header (p);

  if (ph->max_elts)
    len = ph->max_elts;
  else
    len = vec_len (ph->free_indices);

  /* Free elements, certainly won't expand */
  if (len > 0)
    return 0;

  return _vec_resize_will_expand (p, 1, elt_sz);
}

#define pool_get_will_expand(P) _pool_get_will_expand (P, sizeof ((P)[0]))

always_inline int
_pool_put_will_expand (void *p, uword index, uword elt_sz)
{
  pool_header_t *ph = pool_header (p);

  if (clib_bitmap_will_expand (ph->free_bitmap, index))
    return 1;

  if (vec_resize_will_expand (ph->free_indices, 1))
    return 1;

  return 0;
}

#define pool_put_will_expand(P, E) _pool_put_will_expand (P, (E) - (P), sizeof ((P)[0])

/** Use free bitmap to query whether given element is free. */
static_always_inline int
pool_is_free_index (void *p, uword index)
{
  pool_header_t *ph = pool_header (p);
  return index < vec_len (p) ? clib_bitmap_get (ph->free_bitmap, index) : 1;
}

#define pool_is_free(P, E) pool_is_free_index ((void *) (P), (E) - (P))

/** Free an object E in pool P. */
static_always_inline void
_pool_put_index (void *p, uword index, uword elt_sz)
{
  pool_header_t *ph = pool_header (p);

  ASSERT (index < ph->max_elts ? ph->max_elts : vec_len (p));
  ASSERT (!pool_is_free_index (p, index));

  /* Add element to free bitmap and to free list. */
  ph->free_bitmap = clib_bitmap_ori_notrim (ph->free_bitmap, index);

  /* Preallocated pool? */
  if (ph->max_elts)
    {
      u32 len = _vec_len (ph->free_indices);
      vec_set_len (ph->free_indices, len + 1);
      ph->free_indices[len] = index;
    }
  else
    vec_add1 (ph->free_indices, index);

  clib_mem_poison (p + index * elt_sz, elt_sz);
}

#define pool_put_index(P, I) _pool_put_index ((void *) (P), I, _vec_elt_sz (P))
#define pool_put(P, E)	     pool_put_index (P, (E) - (P))

/** Allocate N more free elements to pool (general version). */

static_always_inline void
_pool_alloc (void **pp, uword n_elts, uword align, void *heap, uword elt_sz)
{
  pool_header_t *ph = pool_header (pp[0]);
  uword len = vec_len (pp[0]);
  const vec_attr_t va = { .hdr_sz = sizeof (pool_header_t),
			  .elt_sz = elt_sz,
			  .align = align,
			  .heap = heap };

  if (ph && ph->max_elts)
    {
      clib_warning ("Can't expand fixed-size pool");
      os_out_of_memory ();
    }

  pp[0] = _vec_resize_internal (pp[0], len + n_elts, &va);
  _vec_set_len (pp[0], len, elt_sz);
  clib_mem_poison (pp[0] + len * elt_sz, n_elts * elt_sz);

  ph = pool_header (pp[0]);
  vec_resize (ph->free_indices, n_elts);
  vec_dec_len (ph->free_indices, n_elts);
  clib_bitmap_validate (ph->free_bitmap, (len + n_elts) ?: 1);
}

#define pool_alloc_aligned_heap(P, N, A, H)                                   \
  _pool_alloc ((void **) &(P), N, _vec_align (P, A), H, _vec_elt_sz (P))

#define pool_alloc_heap(P, N, H)    pool_alloc_aligned_heap (P, N, 0, H)
#define pool_alloc_aligned(P, N, A) pool_alloc_aligned_heap (P, N, A, 0)
#define pool_alloc(P, N)	    pool_alloc_aligned_heap (P, N, 0, 0)

static_always_inline void *
_pool_dup (void *p, uword align, uword elt_sz)
{
  pool_header_t *nph, *ph = pool_header (p);
  uword len = vec_len (p);
  const vec_attr_t va = { .hdr_sz = sizeof (pool_header_t),
			  .elt_sz = elt_sz,
			  .align = align };
  void *n;

  if (ph && ph->max_elts)
    {
      clib_warning ("Can't expand fixed-size pool");
      os_out_of_memory ();
    }

  n = _vec_alloc_internal (len, &va);
  nph = pool_header (n);
  clib_memset_u8 (nph, 0, sizeof (vec_header_t));

  if (len)
    {
      u32 *fi;
      vec_foreach (fi, ph->free_indices)
	clib_mem_unpoison (p + elt_sz * fi[0], elt_sz);

      clib_memcpy_fast (n, p, len * elt_sz);

      nph->free_bitmap = clib_bitmap_dup (ph->free_bitmap);
      nph->free_indices = vec_dup (ph->free_indices);

      vec_foreach (fi, ph->free_indices)
	{
	  uword offset = elt_sz * fi[0];
	  clib_mem_poison (p + offset, elt_sz);
	  clib_mem_poison (n + offset, elt_sz);
	}
    }

  return n;
}

/**
 * Return copy of pool with alignment
 *
 * @param P pool to copy
 * @param A alignment (may be zero)
 * @return copy of pool
 */

#define pool_dup_aligned(P, A)                                                \
  _pool_dup (P, _vec_align (P, A), _vec_elt_sz (P))

/**
 * Return copy of pool without alignment
 *
 * @param P pool to copy
 * @return copy of pool
 */
#define pool_dup(P) pool_dup_aligned(P,0)

/** Low-level free pool operator (do not call directly). */
always_inline void
_pool_free (void **v)
{
  pool_header_t *p = pool_header (v[0]);
  if (!p)
    return;

  clib_bitmap_free (p->free_bitmap);

  vec_free (p->free_indices);
  _vec_free (v);
}
#define pool_free(p) _pool_free ((void **) &(p))

static_always_inline uword
pool_get_first_index (void *pool)
{
  pool_header_t *h = pool_header (pool);
  return clib_bitmap_first_clear (h->free_bitmap);
}

static_always_inline uword
pool_get_next_index (void *pool, uword last)
{
  pool_header_t *h = pool_header (pool);
  return clib_bitmap_next_clear (h->free_bitmap, last + 1);
}

/** Optimized iteration through pool.

    @param LO pointer to first element in chunk
    @param HI pointer to last element in chunk
    @param POOL pool to iterate across
    @param BODY operation to perform

    Optimized version which assumes that BODY is smart enough to
    process multiple (LOW,HI) chunks. See also pool_foreach().
 */
#define pool_foreach_region(LO,HI,POOL,BODY)				\
do {									\
  uword _pool_var (i), _pool_var (lo), _pool_var (hi), _pool_var (len);	\
  uword _pool_var (bl), * _pool_var (b);				\
  pool_header_t * _pool_var (p);					\
									\
  _pool_var (p) = pool_header (POOL);					\
  _pool_var (b) = (POOL) ? _pool_var (p)->free_bitmap : 0;		\
  _pool_var (bl) = vec_len (_pool_var (b));				\
  _pool_var (len) = vec_len (POOL);					\
  _pool_var (lo) = 0;							\
									\
  for (_pool_var (i) = 0;						\
       _pool_var (i) <= _pool_var (bl);					\
       _pool_var (i)++)							\
    {									\
      uword _pool_var (m), _pool_var (f);				\
      _pool_var (m) = (_pool_var (i) < _pool_var (bl)			\
		       ? _pool_var (b) [_pool_var (i)]			\
		       : 1);						\
      while (_pool_var (m) != 0)					\
	{								\
	  _pool_var (f) = first_set (_pool_var (m));			\
	  _pool_var (hi) = (_pool_var (i) * BITS (_pool_var (b)[0])	\
			    + min_log2 (_pool_var (f)));		\
	  _pool_var (hi) = (_pool_var (i) < _pool_var (bl)		\
			    ? _pool_var (hi) : _pool_var (len));	\
	  _pool_var (m) ^= _pool_var (f);				\
	  if (_pool_var (hi) > _pool_var (lo))				\
	    {								\
	      (LO) = _pool_var (lo);					\
	      (HI) = _pool_var (hi);					\
	      do { BODY; } while (0);					\
	    }								\
	  _pool_var (lo) = _pool_var (hi) + 1;				\
	}								\
    }									\
} while (0)

/** Iterate through pool.

    @param VAR A variable of same type as pool vector to be used as an
               iterator.
    @param POOL The pool to iterate across.
    @param BODY The operation to perform, typically a code block. See
                the example below.

    This macro will call @c BODY with each active pool element.

    It is a bad idea to allocate or free pool element from within
    @c pool_foreach. Build a vector of indices and dispose of them later.
    Or call pool_flush.


    @par Example
    @code{.c}
    proc_t *procs;   // a pool of processes.
    proc_t *proc;    // pointer to one process; used as the iterator.

    pool_foreach (proc, procs, ({
        if (proc->state != PROC_STATE_RUNNING)
            continue;

        // check a running proc in some way
        ...
    }));
    @endcode

    @warning Because @c pool_foreach is a macro, syntax errors can be
    difficult to find inside @c BODY, let alone actual code bugs. One
    can temporarily split a complex @c pool_foreach into a trivial
    @c pool_foreach which builds a vector of active indices, and a
    vec_foreach() (or plain for-loop) to walk the active index vector.
 */

#define pool_foreach(VAR,POOL)						\
  if (POOL)								\
    for (VAR = POOL + pool_get_first_index (POOL);			\
	 VAR < vec_end (POOL);						\
	 VAR = POOL + pool_get_next_index (POOL, VAR - POOL))

/** Returns pointer to element at given index.

    ASSERTs that the supplied index is valid.
    Even though one can write correct code of the form
    @code
        p = pool_base + index;
    @endcode
    use of @c pool_elt_at_index is strongly suggested.
 */
#define pool_elt_at_index(p,i)			\
({						\
  typeof (p) _e = (p) + (i);			\
  ASSERT (! pool_is_free (p, _e));		\
  _e;						\
})

/** Return next occupied pool index after @c i, useful for safe iteration. */
#define pool_next_index(P,I)                                            \
({                                                                      \
  pool_header_t * _pool_var (p) = pool_header (P);                      \
  uword _pool_var (rv) = (I) + 1;                                       \
                                                                        \
  _pool_var(rv) =                                                       \
    (_pool_var (rv) < vec_len (P) ?                                     \
     clib_bitmap_next_clear (_pool_var (p)->free_bitmap, _pool_var(rv)) \
     : ~0);                                                             \
  _pool_var(rv) =                                                       \
    (_pool_var (rv) < vec_len (P) ?                                     \
     _pool_var (rv) : ~0);						\
  _pool_var(rv);                                                        \
})

#define pool_foreach_index(i, v)                                              \
  if (v)                                                                      \
    for (i = pool_get_first_index (v); i < vec_len (v);                       \
	 i = pool_get_next_index (v, i))

/* Iterate pool by index from s to e */
#define pool_foreach_stepping_index(i, s, e, v)                               \
  for ((i) =                                                                  \
	 (pool_is_free_index ((v), (s)) ? pool_get_next_index ((v), (s)) :    \
						(s));                               \
       (i) < (e); (i) = pool_get_next_index ((v), (i)))

/* works only for pool of pointers, e is declared inside macro */
#define pool_foreach_pointer(e, p)                                            \
  if (p)                                                                      \
    for (typeof ((p)[0]) *_t = (p) + pool_get_first_index (p), (e) = *_t;     \
	 _t < vec_end (p);                                                    \
	 _t = (p) + pool_get_next_index (p, _t - (p)), (e) = *_t)

/**
 * @brief Remove all elements from a pool in a safe way
 *
 * @param VAR each element in the pool
 * @param POOL The pool to flush
 * @param BODY The actions to perform on each element before it is returned to
 *        the pool. i.e. before it is 'freed'
 */
#define pool_flush(VAR, POOL, BODY)                     \
{                                                       \
  uword *_pool_var(ii), *_pool_var(dv) = NULL;          \
                                                        \
  pool_foreach((VAR), (POOL))                          \
  {                                                     \
    vec_add1(_pool_var(dv), (VAR) - (POOL));            \
  }                                                     \
  vec_foreach(_pool_var(ii), _pool_var(dv))             \
  {                                                     \
    (VAR) = pool_elt_at_index((POOL), *_pool_var(ii));  \
    do { BODY; } while (0);                             \
    pool_put((POOL), (VAR));                            \
  }                                                     \
  vec_free(_pool_var(dv));                              \
}

#endif /* included_pool_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
