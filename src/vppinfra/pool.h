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

  /** mmap segment info: base + length */
  u8 *mmap_base;
  u64 mmap_size;

} pool_header_t;

/** Align pool header so that pointers are naturally aligned. */
#define pool_aligned_header_bytes \
  vec_aligned_header_bytes (sizeof (pool_header_t), sizeof (void *))

/** Get pool header from user pool pointer */
always_inline pool_header_t *
pool_header (void *v)
{
  return vec_aligned_header (v, sizeof (pool_header_t), sizeof (void *));
}

extern void _pool_init_fixed (void **, u32, u32);
extern void fpool_free (void *);

/** initialize a fixed-size, preallocated pool */
#define pool_init_fixed(pool,max_elts)                  \
{                                                       \
  _pool_init_fixed((void **)&(pool),sizeof(pool[0]),max_elts);  \
}

/** Validate a pool */
always_inline void
pool_validate (void *v)
{
  pool_header_t *p;
  uword i, n_free_bitmap;

  if (!v)
    return;

  p = pool_header (v);
  n_free_bitmap = clib_bitmap_count_set_bits (p->free_bitmap);
  ASSERT (n_free_bitmap == vec_len (p->free_indices));
  for (i = 0; i < vec_len (p->free_indices); i++)
    ASSERT (clib_bitmap_get (p->free_bitmap, p->free_indices[i]) == 1);
}

always_inline void
pool_header_validate_index (void *v, uword index)
{
  pool_header_t *p;

  if (v)
    {
      p = pool_header (v);
      vec_validate (p->free_bitmap, index / BITS (uword));
    }
}

#define pool_validate_index(v,i)				\
do {								\
  uword __pool_validate_index = (i);				\
  vec_validate_ha ((v), __pool_validate_index,			\
		   pool_aligned_header_bytes, /* align */ 0);   \
  pool_header_validate_index ((v), __pool_validate_index);	\
} while (0)

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
  pool_header_t *p;

  if (!v)
    return 0;

  p = pool_header (v);
  return vec_bytes (p->free_bitmap) + vec_bytes (p->free_indices);
}

/** Memory usage of pool. */
#define pool_bytes(P) (vec_bytes (P) + pool_header_bytes (P))

/** Local variable naming macro. */
#define _pool_var(v) _pool_##v

/** Queries whether pool has at least N_FREE free elements. */
always_inline uword
pool_free_elts (void *v)
{
  pool_header_t *p;
  uword n_free = 0;

  if (v)
    {
      p = pool_header (v);
      n_free += vec_len (p->free_indices);

      /*
       * Space left at end of vector?
       * Fixed-size pools have max_elts set non-zero,
       */
      if (p->max_elts == 0)
	n_free += vec_capacity (v, sizeof (p[0])) - vec_len (v);
    }

  return n_free;
}

/** Allocate an object E from a pool P (general version).

   First search free list.  If nothing is free extend vector of objects.
*/
#define _pool_get_aligned_internal_numa(P, E, A, Z, N)                        \
  do                                                                          \
    {                                                                         \
      pool_header_t *_pool_var (p) = P ? pool_header (P) : NULL;              \
      uword _pool_var (l);                                                    \
                                                                              \
      STATIC_ASSERT (A == 0 || ((A % sizeof (P[0])) == 0) ||                  \
		       ((sizeof (P[0]) % A) == 0),                            \
		     "Pool aligned alloc of incorrectly sized object");       \
      _pool_var (l) = 0;                                                      \
      if (P)                                                                  \
	_pool_var (l) = vec_len (_pool_var (p)->free_indices);                \
                                                                              \
      if (_pool_var (l) > 0)                                                  \
	{                                                                     \
	  /* Return free element from free list. */                           \
	  uword _pool_var (i) =                                               \
	    _pool_var (p)->free_indices[_pool_var (l) - 1];                   \
	  (E) = (P) + _pool_var (i);                                          \
	  _pool_var (p)->free_bitmap = clib_bitmap_andnoti_notrim (           \
	    _pool_var (p)->free_bitmap, _pool_var (i));                       \
	  _vec_len (_pool_var (p)->free_indices) = _pool_var (l) - 1;         \
	  CLIB_MEM_UNPOISON ((E), sizeof ((E)[0]));                           \
	}                                                                     \
      else                                                                    \
	{                                                                     \
	  /* fixed-size, preallocated pools cannot expand */                  \
	  if ((P) && _pool_var (p)->max_elts)                                 \
	    {                                                                 \
	      clib_warning ("can't expand fixed-size pool");                  \
	      os_out_of_memory ();                                            \
	    }                                                                 \
	  /* Nothing on free list, make a new element and return it. */       \
	  P = _vec_resize_numa (                                              \
	    P, /* length_increment */ 1,                                      \
	    /* new size */ (vec_len (P) + 1) * sizeof (P[0]),                 \
	    pool_aligned_header_bytes, /* align */ (A), /* numa */ (N));      \
	  E = vec_end (P) - 1;                                                \
	}                                                                     \
      if (Z)                                                                  \
	memset (E, 0, sizeof (*E));                                           \
    }                                                                         \
  while (0)

#define pool_get_aligned_zero_numa(P,E,A,Z,S) \
  _pool_get_aligned_internal_numa(P,E,A,Z,S)

#define pool_get_aligned_numa(P,E,A,S) \
  _pool_get_aligned_internal_numa(P,E,A,0/*zero*/,S)

#define pool_get_numa(P,E,S) \
  _pool_get_aligned_internal_numa(P,E,0/*align*/,0/*zero*/,S)

#define _pool_get_aligned_internal(P,E,A,Z) \
  _pool_get_aligned_internal_numa(P,E,A,Z,VEC_NUMA_UNSPECIFIED)

/** Allocate an object E from a pool P with alignment A */
#define pool_get_aligned(P,E,A) _pool_get_aligned_internal(P,E,A,0)

/** Allocate an object E from a pool P with alignment A and zero it */
#define pool_get_aligned_zero(P,E,A) _pool_get_aligned_internal(P,E,A,1)

/** Allocate an object E from a pool P (unspecified alignment). */
#define pool_get(P,E) pool_get_aligned(P,E,0)

/** Allocate an object E from a pool P and zero it */
#define pool_get_zero(P,E) pool_get_aligned_zero(P,E,0)

/** See if pool_get will expand the pool or not */
#define pool_get_aligned_will_expand(P, YESNO, A)                             \
  do                                                                          \
    {                                                                         \
      pool_header_t *_pool_var (p) = P ? pool_header (P) : NULL;              \
      uword _pool_var (l);                                                    \
                                                                              \
      _pool_var (l) = 0;                                                      \
      if (P)                                                                  \
	{                                                                     \
	  if (_pool_var (p)->max_elts)                                        \
	    _pool_var (l) = _pool_var (p)->max_elts;                          \
	  else                                                                \
	    _pool_var (l) = vec_len (_pool_var (p)->free_indices);            \
	}                                                                     \
                                                                              \
      /* Free elements, certainly won't expand */                             \
      if (_pool_var (l) > 0)                                                  \
	YESNO = 0;                                                            \
      else                                                                    \
	{                                                                     \
	  /* Nothing on free list, make a new element and return it. */       \
	  YESNO = _vec_resize_will_expand (                                   \
	    P, /* length_increment */ 1,                                      \
	    /* new size */ (vec_len (P) + 1) * sizeof (P[0]),                 \
	    pool_aligned_header_bytes, /* align */ (A));                      \
	}                                                                     \
    }                                                                         \
  while (0)

/** See if pool_put will expand free_bitmap or free_indices or not */
#define pool_put_will_expand(P, E, YESNO)                                     \
  do                                                                          \
    {                                                                         \
      pool_header_t *_pool_var (p) = pool_header (P);                         \
                                                                              \
      uword _pool_var (i) = (E) - (P);                                        \
      /* free_bitmap or free_indices may expand. */                           \
      YESNO =                                                                 \
	clib_bitmap_will_expand (_pool_var (p)->free_bitmap, _pool_var (i));  \
                                                                              \
      YESNO += _vec_resize_will_expand (                                      \
	_pool_var (p)->free_indices, 1,                                       \
	(vec_len (_pool_var (p)->free_indices) + 1) *                         \
	  sizeof (_pool_var (p)->free_indices[0]),                            \
	0, 0);                                                                \
    }                                                                         \
  while (0)

/** Tell the caller if pool get will expand the pool */
#define pool_get_will_expand(P,YESNO) pool_get_aligned_will_expand(P,YESNO,0)

/** Use free bitmap to query whether given element is free. */
#define pool_is_free(P, E)                                                    \
  ({                                                                          \
    pool_header_t *_pool_var (p) = (P) ? pool_header (P) : NULL;              \
    uword _pool_var (i) = (P) ? (E) - (P) : 0;                                \
    (_pool_var (i) < vec_len (P)) ?                                           \
      clib_bitmap_get (_pool_var (p)->free_bitmap, _pool_i) :                 \
      1;                                                                      \
  })

/** Use free bitmap to query whether given index is free */
#define pool_is_free_index(P,I) pool_is_free((P),(P)+(I))

/** Free an object E in pool P. */
#define pool_put(P, E)                                                        \
  do                                                                          \
    {                                                                         \
      typeof (P) _pool_var (p__) = (P);                                       \
      typeof (E) _pool_var (e__) = (E);                                       \
      pool_header_t *_pool_var (p) = pool_header (_pool_var (p__));           \
      uword _pool_var (l) = _pool_var (e__) - _pool_var (p__);                \
      if (_pool_var (p)->max_elts == 0)                                       \
	ASSERT (vec_is_member (_pool_var (p__), _pool_var (e__)));            \
      ASSERT (!pool_is_free (_pool_var (p__), _pool_var (e__)));              \
                                                                              \
      /* Add element to free bitmap and to free list. */                      \
      _pool_var (p)->free_bitmap =                                            \
	clib_bitmap_ori_notrim (_pool_var (p)->free_bitmap, _pool_var (l));   \
                                                                              \
      /* Preallocated pool? */                                                \
      if (_pool_var (p)->max_elts)                                            \
	{                                                                     \
	  ASSERT (_pool_var (l) < _pool_var (p)->max_elts);                   \
	  _pool_var (p)                                                       \
	    ->free_indices[_vec_len (_pool_var (p)->free_indices)] =          \
	    _pool_var (l);                                                    \
	  _vec_len (_pool_var (p)->free_indices) += 1;                        \
	}                                                                     \
      else                                                                    \
	vec_add1 (_pool_var (p)->free_indices, _pool_var (l));                \
                                                                              \
      CLIB_MEM_POISON (_pool_var (e__), sizeof (_pool_var (e__)[0]));         \
    }                                                                         \
  while (0)

/** Free pool element with given index. */
#define pool_put_index(p,i)			\
do {						\
  typeof (p) _e = (p) + (i);			\
  pool_put (p, _e);				\
} while (0)

/** Allocate N more free elements to pool (general version). */
#define pool_alloc_aligned(P,N,A)					\
do {									\
  pool_header_t * _p;							\
                                                                        \
  if ((P))                                                              \
    {                                                                   \
      _p = pool_header (P);                                             \
      if (_p->max_elts)                                                 \
        {                                                               \
           clib_warning ("Can't expand fixed-size pool");		\
           os_out_of_memory();                                          \
        }                                                               \
    }                                                                   \
                                                                        \
  (P) = _vec_resize ((P), 0, (vec_len (P) + (N)) * sizeof (P[0]),	\
		     pool_aligned_header_bytes,				\
		     (A));						\
  _p = pool_header (P);							\
  vec_resize (_p->free_indices, (N));					\
  _vec_len (_p->free_indices) -= (N);					\
} while (0)

/** Allocate N more free elements to pool (unspecified alignment). */
#define pool_alloc(P,N) pool_alloc_aligned(P,N,0)

/**
 * Return copy of pool with alignment
 *
 * @param P pool to copy
 * @param A alignment (may be zero)
 * @return copy of pool
 */
#define pool_dup_aligned(P, A)                                                \
  ({                                                                          \
    typeof (P) _pool_var (new) = 0;                                           \
    pool_header_t *_pool_var (ph), *_pool_var (new_ph);                       \
    u32 _pool_var (n) = pool_len (P);                                         \
    if ((P))                                                                  \
      {                                                                       \
	_pool_var (new) = _vec_resize (_pool_var (new), _pool_var (n),        \
				       _pool_var (n) * sizeof ((P)[0]),       \
				       pool_aligned_header_bytes, (A));       \
	CLIB_MEM_OVERFLOW_PUSH ((P), _pool_var (n) * sizeof ((P)[0]));        \
	clib_memcpy_fast (_pool_var (new), (P),                               \
			  _pool_var (n) * sizeof ((P)[0]));                   \
	CLIB_MEM_OVERFLOW_POP ();                                             \
	_pool_var (ph) = pool_header (P);                                     \
	_pool_var (new_ph) = pool_header (_pool_var (new));                   \
	_pool_var (new_ph)->free_bitmap =                                     \
	  clib_bitmap_dup (_pool_var (ph)->free_bitmap);                      \
	_pool_var (new_ph)->free_indices =                                    \
	  vec_dup (_pool_var (ph)->free_indices);                             \
	_pool_var (new_ph)->max_elts = _pool_var (ph)->max_elts;              \
      }                                                                       \
    _pool_var (new);                                                          \
  })

/**
 * Return copy of pool without alignment
 *
 * @param P pool to copy
 * @return copy of pool
 */
#define pool_dup(P) pool_dup_aligned(P,0)

/** Low-level free pool operator (do not call directly). */
always_inline void *
_pool_free (void *v)
{
  pool_header_t *p;
  if (!v)
    return v;
  p = pool_header (v);
  clib_bitmap_free (p->free_bitmap);

  if (p->max_elts)
    {
      int rv;

      rv = munmap (p->mmap_base, p->mmap_size);
      if (rv)
	clib_unix_warning ("munmap");
    }
  else
    {
      vec_free (p->free_indices);
      vec_free_h (v, pool_aligned_header_bytes);
    }
  return 0;
}

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

/** Free a pool. */
#define pool_free(p) (p) = _pool_free(p)

/** Optimized iteration through pool.

    @param LO pointer to first element in chunk
    @param HI pointer to last element in chunk
    @param POOL pool to iterate across
    @param BODY operation to perform

    Optimized version which assumes that BODY is smart enough to
    process multiple (LOW,HI) chunks. See also pool_foreach().
 */
#define pool_foreach_region(LO, HI, POOL, BODY)                               \
  do                                                                          \
    {                                                                         \
      uword _pool_var (i), _pool_var (lo), _pool_var (hi), _pool_var (len);   \
      uword _pool_var (bl), *_pool_var (b);                                   \
      pool_header_t *_pool_var (p);                                           \
                                                                              \
      _pool_var (p) = (POOL) ? pool_header (POOL) : NULL;                     \
      _pool_var (b) = (POOL) ? _pool_var (p)->free_bitmap : 0;                \
      _pool_var (bl) = vec_len (_pool_var (b));                               \
      _pool_var (len) = vec_len (POOL);                                       \
      _pool_var (lo) = 0;                                                     \
                                                                              \
      for (_pool_var (i) = 0; _pool_var (i) <= _pool_var (bl);                \
	   _pool_var (i)++)                                                   \
	{                                                                     \
	  uword _pool_var (m), _pool_var (f);                                 \
	  _pool_var (m) =                                                     \
	    (_pool_var (i) < _pool_var (bl) ? _pool_var (b)[_pool_var (i)] :  \
					      1);                             \
	  while (_pool_var (m) != 0)                                          \
	    {                                                                 \
	      _pool_var (f) = first_set (_pool_var (m));                      \
	      _pool_var (hi) = (_pool_var (i) * BITS (_pool_var (b)[0]) +     \
				min_log2 (_pool_var (f)));                    \
	      _pool_var (hi) =                                                \
		(_pool_var (i) < _pool_var (bl) ? _pool_var (hi) :            \
						  _pool_var (len));           \
	      _pool_var (m) ^= _pool_var (f);                                 \
	      if (_pool_var (hi) > _pool_var (lo))                            \
		{                                                             \
		  (LO) = _pool_var (lo);                                      \
		  (HI) = _pool_var (hi);                                      \
		  do                                                          \
		    {                                                         \
		      BODY;                                                   \
		    }                                                         \
		  while (0);                                                  \
		}                                                             \
	      _pool_var (lo) = _pool_var (hi) + 1;                            \
	    }                                                                 \
	}                                                                     \
    }                                                                         \
  while (0)

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

#define pool_foreach_index(i,v)		\
  if (v)					\
    for (i = pool_get_first_index (v);		\
	 i < vec_len (v);			\
	 i = pool_get_next_index (v, i))	\

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
