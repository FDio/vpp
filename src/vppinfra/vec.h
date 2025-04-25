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

#ifndef included_vec_h
#define included_vec_h

#include <vppinfra/clib.h>	/* word, etc */
#include <vppinfra/mem.h>	/* clib_mem_free */
#include <vppinfra/string.h>	/* memcpy, memmove */
#include <vppinfra/vec_bootstrap.h>

/** \file

   CLIB vectors are ubiquitous dynamically resized arrays with by user
   defined "headers".  Many CLIB data structures (e.g. hash, heap,
   pool) are vectors with various different headers.

   The memory layout looks like this:

~~~~~~~~
		    user header (start of memory allocation)
		    padding
		    heap pointer (optional, only if default_heap == 0)
		    vector header: number of elements, header size
   user's pointer-> vector element #0
		    vector element #1
		    ...
~~~~~~~~

   The user pointer contains the address of vector element # 0.  Null
   pointer vectors are valid and mean a zero length vector.

   You can reset the length of an allocated vector to zero via the
   vec_reset_length(v) macro, or by setting the vector length field to
   zero (e.g. _vec_len (v) = 0). Vec_reset_length(v) preferred: it
   understands Null pointers.

   Typically, the header is not present.  Headers allow for other
   data structures to be built atop CLIB vectors.

   While users may specify the alignment for first data element of a vector
   via the vec_*_aligned macros that is typically not needed as alignment
   is set based on native alignment of the data structure used.

   Vector elements can be any C type e.g. (int, double, struct bar).
   This is also true for data types built atop vectors (e.g. heap,
   pool, etc.).

   Many macros have \_a variants supporting alignment of vector elements
   and \_h variants supporting non-zero-length vector headers. The \_ha
   variants support both.  Additionally cacheline alignment within a
   vector element structure can be specified using the
   CLIB_CACHE_LINE_ALIGN_MARK() macro.

   Standard programming error: memorize a pointer to the ith element
   of a vector then expand it. Vectors expand by 3/2, so such code
   may appear to work for a period of time. Memorize vector indices
   which are invariant.
 */

/** \brief Low-level (re)allocation function, usually not called directly

    @param v pointer to a vector
    @param n_elts requested number of elements
    @param elt_sz requested size of one element
    @param hdr_sz header size in bytes (may be zero)
    @param align alignment (may be zero)
    @return v_prime pointer to resized vector, may or may not equal v
*/

typedef struct
{
  void *heap;
  u32 elt_sz;
  u16 hdr_sz;
  u16 align;
} vec_attr_t;

void *_vec_alloc_internal (uword n_elts, const vec_attr_t *const attr);
void *_vec_realloc_internal (void *v, uword n_elts,
			     const vec_attr_t *const attr);
void *_vec_resize_internal (void *v, uword n_elts,
			    const vec_attr_t *const attr);

/* calculate minimum alignment out of data natural alignment and provided
 * value, should not be < VEC_MIN_ALIGN */
static_always_inline uword
__vec_align (uword data_align, uword configuered_align)
{
  data_align = clib_max (data_align, configuered_align);
  ASSERT (count_set_bits (data_align) == 1);
  return clib_max (VEC_MIN_ALIGN, data_align);
}

/* function used t o catch cases where vec_* macros on used on void * */
static_always_inline uword
__vec_elt_sz (uword elt_sz, int is_void)
{
  /* vector macro operations on void * are not allowed */
  ASSERT (is_void == 0);
  return elt_sz;
}

static_always_inline void
_vec_update_pointer (void **vp, void *v)
{
  /* avoid store if not needed */
  if (v != vp[0])
    vp[0] = v;
}

static_always_inline void *
vec_get_heap (void *v)
{
  if (v == 0 || _vec_find (v)->default_heap == 1)
    return 0;
  return _vec_heap (v);
}

static_always_inline uword
vec_get_align (void *v)
{
  return 1ULL << _vec_find (v)->log2_align;
}

static_always_inline void
_vec_prealloc (void **vp, uword n_elts, uword hdr_sz, uword align, void *heap,
	       uword elt_sz)
{
  const vec_attr_t va = {
    .elt_sz = elt_sz, .hdr_sz = hdr_sz, .align = align, .heap = heap
  };
  void *v;

  ASSERT (vp[0] == 0);

  v = _vec_alloc_internal (n_elts, &va);
  _vec_set_len (v, 0, elt_sz);
  _vec_update_pointer (vp, v);
}

/** \brief Pre-allocate a vector (generic version)

    @param V pointer to a vector
    @param N number of elements to pre-allocate
    @param H header size in bytes (may be zero)
    @param A alignment (zero means default alignment of the data structure)
    @param P heap (zero means default heap)
    @return V (value-result macro parameter)
*/

#define vec_prealloc_hap(V, N, H, A, P)                                       \
  _vec_prealloc ((void **) &(V), N, H, _vec_align (V, A), P, _vec_elt_sz (V))

/** \brief Pre-allocate a vector (simple version)

    @param V pointer to a vector
    @param N number of elements to pre-allocate
    @return V (value-result macro parameter)
*/
#define vec_prealloc(V, N) vec_prealloc_hap (V, N, 0, 0, 0)

/** \brief Pre-allocate a vector (heap version)

    @param V pointer to a vector
    @param N number of elements to pre-allocate
    @param P heap (zero means default heap)
    @return V (value-result macro parameter)
*/
#define vec_prealloc_heap(V, N, P) vec_prealloc_hap (V, N, 0, 0, P)

always_inline int
_vec_resize_will_expand (void *v, uword n_elts, uword elt_sz)
{
  if (v == 0)
    return 1;

  /* Vector header must start heap object. */
  ASSERT (clib_mem_heap_is_heap_object (vec_get_heap (v), vec_header (v)));

  n_elts += _vec_len (v);
  if ((n_elts * elt_sz) <= vec_max_bytes (v))
    return 0;

  return 1;
}

/** \brief Determine if vector will resize with next allocation

    @param V pointer to a vector
    @param N number of elements to add
    @return 1 if vector will resize 0 otherwise
*/

#define vec_resize_will_expand(V, N)                                          \
  _vec_resize_will_expand (V, N, _vec_elt_sz (V))

/* Local variable naming macro (prevents collisions with other macro naming). */
#define _v(var) _vec_##var

/** \brief Resize a vector (general version).
   Add N elements to end of given vector V, return pointer to start of vector.
   Vector will have room for H header bytes and will have user's data aligned
   at alignment A (rounded to next power of 2).

    @param V pointer to a vector
    @param N number of elements to add
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/

static_always_inline void
_vec_resize (void **vp, uword n_add, uword hdr_sz, uword align, uword elt_sz)
{
  void *v = *vp;
  if (PREDICT_FALSE (v == 0))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      *vp = _vec_alloc_internal (n_add, &va);
      return;
    }

  if (PREDICT_FALSE (_vec_find (v)->grow_elts < n_add))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      v = _vec_resize_internal (v, _vec_len (v) + n_add, &va);
      _vec_update_pointer (vp, v);
    }
  else
    _vec_set_len (v, _vec_len (v) + n_add, elt_sz);
}

#define vec_resize_ha(V, N, H, A)                                             \
  _vec_resize ((void **) &(V), N, H, _vec_align (V, A), _vec_elt_sz (V))

/** \brief Resize a vector (no header, unspecified alignment)
   Add N elements to end of given vector V, return pointer to start of vector.
   Vector will have room for H header bytes and will have user's data aligned
   at alignment A (rounded to next power of 2).

    @param V pointer to a vector
    @param N number of elements to add
    @return V (value-result macro parameter)
*/
#define vec_resize(V,N)     vec_resize_ha(V,N,0,0)

/** \brief Resize a vector (no header, alignment specified).
   Add N elements to end of given vector V, return pointer to start of vector.
   Vector will have room for H header bytes and will have user's data aligned
   at alignment A (rounded to next power of 2).

    @param V pointer to a vector
    @param N number of elements to add
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/

#define vec_resize_aligned(V,N,A) vec_resize_ha(V,N,0,A)

/** \brief Allocate space for N more elements

    @param V pointer to a vector
    @param N number of elements to add
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/

#define vec_alloc_ha(V, N, H, A)                                              \
  do                                                                          \
    {                                                                         \
      uword _v (l) = vec_len (V);                                             \
      vec_resize_ha (V, N, H, A);                                             \
      vec_set_len (V, _v (l));                                                \
    }                                                                         \
  while (0)

/** \brief Allocate space for N more elements
    (no header, unspecified alignment)

    @param V pointer to a vector
    @param N number of elements to add
    @return V (value-result macro parameter)
*/
#define vec_alloc(V,N) vec_alloc_ha(V,N,0,0)

/** \brief Allocate space for N more elements (no header, given alignment)
    @param V pointer to a vector
    @param N number of elements to add
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/

#define vec_alloc_aligned(V,N,A) vec_alloc_ha(V,N,0,A)

/** \brief Create new vector of given type and length (general version).
    @param T type of elements in new vector
    @param N number of elements to add
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @param P heap (may be zero)
    @return V new vector
*/
#define vec_new_generic(T, N, H, A, P)                                        \
  _vec_alloc_internal (N, &((vec_attr_t){ .align = _vec_align ((T *) 0, A),   \
					  .hdr_sz = (H),                      \
					  .heap = (P),                        \
					  .elt_sz = sizeof (T) }))

/** \brief Create new vector of given type and length
    (unspecified alignment, no header).

    @param T type of elements in new vector
    @param N number of elements to add
    @return V new vector
*/
#define vec_new(T, N) vec_new_generic (T, N, 0, 0, 0)
/** \brief Create new vector of given type and length
    (alignment specified, no header).

    @param T type of elements in new vector
    @param N number of elements to add
    @param A alignment (may be zero)
    @return V new vector
*/
#define vec_new_aligned(T, N, A) vec_new_generic (T, N, 0, A, 0)
/** \brief Create new vector of given type and length
    (heap specified, no header).

    @param T type of elements in new vector
    @param N number of elements to add
    @param P heap (may be zero)
    @return V new vector
*/
#define vec_new_heap(T, N, P) vec_new_generic (T, N, 0, 0, P)

/** \brief Free vector's memory (no header).
    @param V pointer to a vector
    @return V (value-result parameter, V=0)
*/

static_always_inline void
_vec_free (void **vp)
{
  if (vp[0] == 0)
    return;
  clib_mem_heap_free (vec_get_heap (vp[0]), vec_header (vp[0]));
  vp[0] = 0;
}

#define vec_free(V) _vec_free ((void **) &(V))

void vec_free_not_inline (void *v);

/**\brief Free vector user header (syntactic sugar)
   @param h vector header
   @void
*/
#define vec_free_header(h) clib_mem_free (h)

/** \brief Return copy of vector (general version).

    @param V pointer to a vector
    @param H size of header in bytes
    @param A alignment (may be zero)

    @return Vdup copy of vector
*/

static_always_inline void *
_vec_dup (void *v, uword hdr_size, uword align, uword elt_sz)
{
  uword len = vec_len (v);
  const vec_attr_t va = { .elt_sz = elt_sz, .align = align };
  void *n = 0;

  if (len)
    {
      n = _vec_alloc_internal (len, &va);
      clib_memcpy_fast (n, v, len * elt_sz);
    }
  return n;
}

#define vec_dup_ha(V, H, A)                                                   \
  _vec_dup ((void *) (V), H, _vec_align (V, A), _vec_elt_sz (V))

/** \brief Return copy of vector (no header, no alignment)

    @param V pointer to a vector
    @return Vdup copy of vector
*/
#define vec_dup(V) vec_dup_ha(V,0,0)

/** \brief Return copy of vector (no header, alignment specified).

    @param V pointer to a vector
    @param A alignment (may be zero)

    @return Vdup copy of vector
*/
#define vec_dup_aligned(V,A) vec_dup_ha(V,0,A)

/** \brief Copy a vector, memcpy wrapper. Assumes sizeof(SRC[0]) ==
    sizeof(DST[0])

    @param DST destination
    @param SRC source
*/
#define vec_copy(DST, SRC)                                                    \
  clib_memcpy_fast (DST, SRC, vec_len (DST) * _vec_elt_sz (DST))

/** \brief Clone a vector. Make a new vector with the
    same size as a given vector but possibly with a different type.

    @param NEW_V pointer to new vector
    @param OLD_V pointer to old vector
*/

static_always_inline void
_vec_clone (void **v1p, void *v2, uword align, uword elt_sz)
{
  const vec_attr_t va = { .elt_sz = elt_sz, .align = align };
  v1p[0] = _vec_alloc_internal (vec_len (v2), &va);
}
#define vec_clone(NEW_V, OLD_V)                                               \
  _vec_clone ((void **) &(NEW_V), OLD_V, _vec_align (NEW_V, 0),               \
	      _vec_elt_sz (NEW_V))

/** \brief Make sure vector is long enough for given index (general version).

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/

always_inline void
_vec_zero_elts (void *v, uword first, uword count, uword elt_sz)
{
  clib_memset_u8 (v + (first * elt_sz), 0, count * elt_sz);
}
#define vec_zero_elts(V, F, C) _vec_zero_elts (V, F, C, _vec_elt_sz (V))

static_always_inline void
_vec_validate (void **vp, uword index, uword header_size, uword align,
	       void *heap, uword elt_sz)
{
  void *v = *vp;
  uword vl, n_elts = index + 1;

  if (PREDICT_FALSE (v == 0))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = header_size };
      *vp = _vec_alloc_internal (n_elts, &va);
      return;
    }

  vl = _vec_len (v);

  if (PREDICT_FALSE (index < vl))
    return;

  if (PREDICT_FALSE (index >= _vec_find (v)->grow_elts + vl))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = header_size };
      v = _vec_resize_internal (v, n_elts, &va);
      _vec_update_pointer (vp, v);
    }
  else
    _vec_set_len (v, n_elts, elt_sz);

  _vec_zero_elts (v, vl, n_elts - vl, elt_sz);
}

#define vec_validate_hap(V, I, H, A, P)                                       \
  _vec_validate ((void **) &(V), I, H, _vec_align (V, A), 0, _vec_elt_sz (V))

/** \brief Make sure vector is long enough for given index
    (no header, unspecified alignment)

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @return V (value-result macro parameter)
*/
#define vec_validate(V, I) vec_validate_hap (V, I, 0, 0, 0)

/** \brief Make sure vector is long enough for given index
    (no header, specified alignment)

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/

#define vec_validate_aligned(V, I, A) vec_validate_hap (V, I, 0, A, 0)

/** \brief Make sure vector is long enough for given index
    (no header, specified heap)

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param H heap (may be zero)
    @return V (value-result macro parameter)
*/

#define vec_validate_heap(V, I, P) vec_validate_hap (V, I, 0, 0, P)

/** \brief Make sure vector is long enough for given index
    and initialize empty space (general version)

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param INIT initial value (can be a complex expression!)
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/
#define vec_validate_init_empty_ha(V, I, INIT, H, A)                          \
  do                                                                          \
    {                                                                         \
      word _v (i) = (I);                                                      \
      word _v (l) = vec_len (V);                                              \
      if (_v (i) >= _v (l))                                                   \
	{                                                                     \
	  vec_resize_ha (V, 1 + (_v (i) - _v (l)), H, A);                     \
	  while (_v (l) <= _v (i))                                            \
	    {                                                                 \
	      (V)[_v (l)] = (INIT);                                           \
	      _v (l)++;                                                       \
	    }                                                                 \
	}                                                                     \
    }                                                                         \
  while (0)

/** \brief Make sure vector is long enough for given index
    and initialize empty space (no header, unspecified alignment)

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param INIT initial value (can be a complex expression!)
    @return V (value-result macro parameter)
*/

#define vec_validate_init_empty(V,I,INIT) \
  vec_validate_init_empty_ha(V,I,INIT,0,0)

/** \brief Make sure vector is long enough for given index
    and initialize empty space (no header, alignment alignment)

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param INIT initial value (can be a complex expression!)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/
#define vec_validate_init_empty_aligned(V,I,INIT,A) \
  vec_validate_init_empty_ha(V,I,INIT,0,A)

/** \brief Add 1 element to end of vector (general version).

    @param V pointer to a vector
    @param E element to add
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/

static_always_inline void *
_vec_add1 (void **vp, uword hdr_sz, uword align, uword elt_sz)
{
  void *v = vp[0];
  uword len;

  if (PREDICT_FALSE (v == 0))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      return *vp = _vec_alloc_internal (1, &va);
    }

  len = _vec_len (v);

  if (PREDICT_FALSE (_vec_find (v)->grow_elts == 0))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      v = _vec_resize_internal (v, len + 1, &va);
      _vec_update_pointer (vp, v);
    }
  else
    _vec_set_len (v, len + 1, elt_sz);

  return v + len * elt_sz;
}

#define vec_add1_ha(V, E, H, A)                                               \
  ((__typeof__ ((V)[0]) *) _vec_add1 ((void **) &(V), H, _vec_align (V, A),   \
				      _vec_elt_sz (V)))[0] = (E)

/** \brief Add 1 element to end of vector (unspecified alignment).

    @param V pointer to a vector
    @param E element to add
    @return V (value-result macro parameter)
*/
#define vec_add1(V,E)           vec_add1_ha(V,E,0,0)

/** \brief Add 1 element to end of vector (alignment specified).

    @param V pointer to a vector
    @param E element to add
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/
#define vec_add1_aligned(V,E,A) vec_add1_ha(V,E,0,A)

/** \brief Add N elements to end of vector V,
    return pointer to new elements in P. (general version)

    @param V pointer to a vector
    @param P pointer to new vector element(s)
    @param N number of elements to add
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V and P (value-result macro parameters)
*/

static_always_inline void
_vec_add2 (void **vp, void **pp, uword n_add, uword hdr_sz, uword align,
	   uword elt_sz)
{
  void *v = *vp;
  uword len;

  if (PREDICT_FALSE (v == 0))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      *vp = *pp = _vec_alloc_internal (n_add, &va);
      return;
    }

  len = _vec_len (v);
  if (PREDICT_FALSE (_vec_find (v)->grow_elts < n_add))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      v = _vec_resize_internal (v, len + n_add, &va);
      _vec_update_pointer (vp, v);
    }
  else
    _vec_set_len (v, len + n_add, elt_sz);

  *pp = v + len * elt_sz;
}

#define vec_add2_ha(V, P, N, H, A)                                            \
  _vec_add2 ((void **) &(V), (void **) &(P), N, H, _vec_align (V, A),         \
	     _vec_elt_sz (V))

/** \brief Add N elements to end of vector V,
    return pointer to new elements in P. (no header, unspecified alignment)

    @param V pointer to a vector
    @param P pointer to new vector element(s)
    @param N number of elements to add
    @return V and P (value-result macro parameters)
*/

#define vec_add2(V,P,N)           vec_add2_ha(V,P,N,0,0)

/** \brief Add N elements to end of vector V,
    return pointer to new elements in P. (no header, alignment specified)

    @param V pointer to a vector
    @param P pointer to new vector element(s)
    @param N number of elements to add
    @param A alignment (may be zero)
    @return V and P (value-result macro parameters)
*/

#define vec_add2_aligned(V,P,N,A) vec_add2_ha(V,P,N,0,A)

/** \brief Add N elements to end of vector V (general version)

    @param V pointer to a vector
    @param E pointer to element(s) to add
    @param N number of elements to add
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/
static_always_inline void
_vec_add (void **vp, void *e, word n_add, uword hdr_sz, uword align,
	  uword elt_sz)
{
  void *v = *vp;
  uword len;

  ASSERT (n_add >= 0);

  if (n_add < 1)
    return;

  if (PREDICT_FALSE (v == 0))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      *vp = v = _vec_alloc_internal (n_add, &va);
      clib_memcpy_fast (v, e, n_add * elt_sz);
      return;
    }

  len = _vec_len (v);

  if (PREDICT_FALSE (_vec_find (v)->grow_elts < n_add))
    {
      const vec_attr_t va = { .elt_sz = elt_sz,
			      .align = align,
			      .hdr_sz = hdr_sz };
      v = _vec_resize_internal (v, len + n_add, &va);
      _vec_update_pointer (vp, v);
    }
  else
    _vec_set_len (v, len + n_add, elt_sz);

  clib_memcpy_fast (v + len * elt_sz, e, n_add * elt_sz);
}

#define vec_add_ha(V, E, N, H, A)                                             \
  _vec_add ((void **) &(V), (void *) (E), N, H, _vec_align (V, A),            \
	    _vec_elt_sz (V))

/** \brief Add N elements to end of vector V (no header, unspecified alignment)

    @param V pointer to a vector
    @param E pointer to element(s) to add
    @param N number of elements to add
    @return V (value-result macro parameter)
*/
#define vec_add(V,E,N)           vec_add_ha(V,E,N,0,0)

/** \brief Add N elements to end of vector V (no header, specified alignment)

    @param V pointer to a vector
    @param E pointer to element(s) to add
    @param N number of elements to add
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/
#define vec_add_aligned(V,E,N,A) vec_add_ha(V,E,N,0,A)

/** \brief Returns last element of a vector and decrements its length

    @param V pointer to a vector
    @return E element removed from the end of the vector
*/
#define vec_pop(V)                                                            \
  ({                                                                          \
    uword _v (l) = vec_len (V);                                               \
    __typeof__ ((V)[0]) _v (rv);                                              \
    ASSERT (_v (l) > 0);                                                      \
    _v (l) -= 1;                                                              \
    _v (rv) = (V)[_v (l)];                                                    \
    vec_set_len (V, _v (l));                                                  \
    (_v (rv));                                                                \
  })

/** \brief Set E to the last element of a vector, decrement vector length
    @param V pointer to a vector
    @param E pointer to the last vector element
    @return E element removed from the end of the vector
    (value-result macro parameter
*/

#define vec_pop2(V,E)				\
({						\
  uword _v(l) = vec_len (V);			\
  if (_v(l) > 0) (E) = vec_pop (V);		\
  _v(l) > 0;					\
})

/** \brief Insert N vector elements starting at element M,
    initialize new elements (general version).

    @param V (possibly NULL) pointer to a vector.
    @param N number of elements to insert
    @param M insertion point
    @param INIT initial value (can be a complex expression!)
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/

static_always_inline void
_vec_insert (void **vp, uword n_insert, uword ins_pt, u8 init, uword hdr_sz,
	     uword align, uword elt_sz)
{
  void *v = vp[0];
  uword len = vec_len (v);
  const vec_attr_t va = { .elt_sz = elt_sz, .align = align, .hdr_sz = hdr_sz };

  ASSERT (ins_pt <= len);

  v = _vec_resize_internal (v, len + n_insert, &va);
  clib_memmove (v + va.elt_sz * (ins_pt + n_insert), v + ins_pt * elt_sz,
		(len - ins_pt) * elt_sz);
  _vec_zero_elts (v, ins_pt, n_insert, elt_sz);
  _vec_update_pointer (vp, v);
}

#define vec_insert_init_empty_ha(V, N, M, INIT, H, A)                         \
  _vec_insert ((void **) &(V), N, M, INIT, H, _vec_align (V, A),              \
	       _vec_elt_sz (V))

/** \brief Insert N vector elements starting at element M,
    initialize new elements to zero (general version)

    @param V (possibly NULL) pointer to a vector.
    @param N number of elements to insert
    @param M insertion point
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/
#define vec_insert_ha(V,N,M,H,A)    vec_insert_init_empty_ha(V,N,M,0,H,A)

/** \brief Insert N vector elements starting at element M,
    initialize new elements to zero (no header, unspecified alignment)

    @param V (possibly NULL) pointer to a vector.
    @param N number of elements to insert
    @param M insertion point
    @return V (value-result macro parameter)
*/
#define vec_insert(V,N,M)           vec_insert_ha(V,N,M,0,0)

/** \brief Insert N vector elements starting at element M,
    initialize new elements to zero (no header, alignment specified)

    @param V (possibly NULL) pointer to a vector.
    @param N number of elements to insert
    @param M insertion point
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/
#define vec_insert_aligned(V,N,M,A) vec_insert_ha(V,N,M,0,A)

/** \brief Insert N vector elements starting at element M,
    initialize new elements (no header, unspecified alignment)

    @param V (possibly NULL) pointer to a vector.
    @param N number of elements to insert
    @param M insertion point
    @param INIT initial value (can be a complex expression!)
    @return V (value-result macro parameter)
*/

#define vec_insert_init_empty(V,N,M,INIT) \
  vec_insert_init_empty_ha(V,N,M,INIT,0,0)
/* Resize vector by N elements starting from element M, initialize new elements to INIT (alignment specified, no header). */

/** \brief Insert N vector elements starting at element M,
    initialize new elements (no header, specified alignment)

    @param V (possibly NULL) pointer to a vector.
    @param N number of elements to insert
    @param M insertion point
    @param INIT initial value (can be a complex expression!)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/
#define vec_insert_init_empty_aligned(V,N,M,INIT,A) \
  vec_insert_init_empty_ha(V,N,M,INIT,0,A)

/** \brief Insert N vector elements starting at element M,
    insert given elements (general version)

    @param V (possibly NULL) pointer to a vector.
    @param E element(s) to insert
    @param N number of elements to insert
    @param M insertion point
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/

static_always_inline void
_vec_insert_elts (void **vp, void *e, uword n_insert, uword ins_pt,
		  uword hdr_sz, uword align, uword elt_sz)
{
  void *v = vp[0];
  uword len = vec_len (v);
  const vec_attr_t va = { .elt_sz = elt_sz, .align = align, .hdr_sz = hdr_sz };

  ASSERT (ins_pt <= len);

  v = _vec_resize_internal (v, len + n_insert, &va);
  clib_memmove (v + elt_sz * (ins_pt + n_insert), v + ins_pt * elt_sz,
		(len - ins_pt) * elt_sz);
  _vec_zero_elts (v, ins_pt, n_insert, elt_sz);
  clib_memcpy_fast (v + ins_pt * elt_sz, e, n_insert * elt_sz);
  _vec_update_pointer (vp, v);
}

#define vec_insert_elts_ha(V, E, N, M, H, A)                                  \
  _vec_insert_elts ((void **) &(V), E, N, M, H, _vec_align (V, A),            \
		    _vec_elt_sz (V))

/** \brief Insert N vector elements starting at element M,
    insert given elements (no header, unspecified alignment)

    @param V (possibly NULL) pointer to a vector.
    @param E element(s) to insert
    @param N number of elements to insert
    @param M insertion point
    @return V (value-result macro parameter)
*/
#define vec_insert_elts(V,E,N,M)           vec_insert_elts_ha(V,E,N,M,0,0)

/** \brief Insert N vector elements starting at element M,
    insert given elements (no header, specified alignment)

    @param V (possibly NULL) pointer to a vector.
    @param E element(s) to insert
    @param N number of elements to insert
    @param M insertion point
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/
#define vec_insert_elts_aligned(V,E,N,M,A) vec_insert_elts_ha(V,E,N,M,0,A)

/** \brief Delete N elements starting at element M

    @param V pointer to a vector
    @param N number of elements to delete
    @param M first element to delete
    @return V (value-result macro parameter)
*/

static_always_inline void
_vec_delete (void *v, uword n_del, uword first, uword elt_sz)
{
  word n_bytes_del, n_bytes_to_move, len = vec_len (v);
  u8 *dst;

  if (n_del == 0)
    return;

  ASSERT (first + n_del <= len);

  n_bytes_del = n_del * elt_sz;
  n_bytes_to_move = (len - first - n_del) * elt_sz;
  dst = v + first * elt_sz;

  if (n_bytes_to_move > 0)
    clib_memmove (dst, dst + n_bytes_del, n_bytes_to_move);
  clib_memset (dst + n_bytes_to_move, 0, n_bytes_del);

  _vec_set_len (v, _vec_len (v) - n_del, elt_sz);
}

#define vec_delete(V, N, M) _vec_delete ((void *) (V), N, M, _vec_elt_sz (V))

/** \brief Delete the element at index I

    @param V pointer to a vector
    @param I index to delete
*/

static_always_inline void
_vec_del1 (void *v, uword index, uword elt_sz)
{
  uword len = _vec_len (v) - 1;

  if (index < len)
    clib_memcpy_fast (v + index * elt_sz, v + len * elt_sz, elt_sz);

  _vec_set_len (v, len, elt_sz);
}

#define vec_del1(v, i) _vec_del1 ((void *) (v), i, _vec_elt_sz (v))

static_always_inline void
_vec_append (void **v1p, void *v2, uword v1_elt_sz, uword v2_elt_sz,
	     uword align)
{
  void *v1 = v1p[0];
  uword len1 = vec_len (v1);
  uword len2 = vec_len (v2);

  if (PREDICT_TRUE (len2 > 0))
    {
      const vec_attr_t va = { .elt_sz = v2_elt_sz, .align = align };
      v1 = _vec_resize_internal (v1, len1 + len2, &va);
      clib_memcpy_fast (v1 + len1 * v1_elt_sz, v2, len2 * v2_elt_sz);
      _vec_update_pointer (v1p, v1);
    }
}

/** \brief Append v2 after v1. Result in v1. Specified alignment.
    @param V1 target vector
    @param V2 vector to append
    @param align required alignment
*/

#define vec_append_aligned(v1, v2, align)                                     \
  _vec_append ((void **) &(v1), (void *) (v2), _vec_elt_sz (v1),              \
	       _vec_elt_sz (v2), _vec_align (v1, align))

/** \brief Append v2 after v1. Result in v1.
    @param V1 target vector
    @param V2 vector to append
*/

#define vec_append(v1, v2) vec_append_aligned (v1, v2, 0)

static_always_inline void
_vec_prepend (void *restrict *v1p, void *restrict v2, uword v1_elt_sz,
	      uword v2_elt_sz, uword align)
{
  void *restrict v1 = v1p[0];
  uword len1 = vec_len (v1);
  uword len2 = vec_len (v2);

  if (PREDICT_TRUE (len2 > 0))
    {
      /* prepending vector to itself would result in use-after-free */
      ASSERT (v1 != v2);
      const vec_attr_t va = { .elt_sz = v2_elt_sz, .align = align };
      v1 = _vec_resize_internal (v1, len1 + len2, &va);
      clib_memmove (v1 + len2 * v2_elt_sz, v1, len1 * v1_elt_sz);
      clib_memcpy_fast (v1, v2, len2 * v2_elt_sz);
      _vec_update_pointer ((void **) v1p, v1);
    }
}

/** \brief Prepend v2 before v1. Result in v1. Specified alignment
    @param V1 target vector
    @param V2 vector to prepend, V1 != V2
    @param align required alignment
*/

#define vec_prepend_aligned(v1, v2, align)                                    \
  _vec_prepend ((void **) &(v1), (void *) (v2), _vec_elt_sz (v1),             \
		_vec_elt_sz (v2), _vec_align (v1, align))

/** \brief Prepend v2 before v1. Result in v1.
    @param V1 target vector
    @param V2 vector to prepend, V1 != V2
*/

#define vec_prepend(v1, v2) vec_prepend_aligned (v1, v2, 0)

/** \brief Zero all vector elements. Null-pointer tolerant.
    @param var Vector to zero
*/
static_always_inline void
_vec_zero (void *v, uword elt_sz)
{
  uword len = vec_len (v);

  if (len)
    clib_memset_u8 (v, 0, len * elt_sz);
}

#define vec_zero(var) _vec_zero ((void *) (var), _vec_elt_sz (var))

/** \brief Set all vector elements to given value. Null-pointer tolerant.
    @param v vector to set
    @param val value for each vector element
*/
#define vec_set(v,val)				\
do {						\
  word _v(i);					\
  __typeof__ ((v)[0]) _val = (val);		\
  for (_v(i) = 0; _v(i) < vec_len (v); _v(i)++)	\
    (v)[_v(i)] = _val;				\
} while (0)

#ifdef CLIB_UNIX
#include <stdlib.h>		/* for qsort */
#endif

/** \brief Compare two vectors, not NULL-pointer tolerant

    @param v1 Pointer to a vector
    @param v2 Pointer to a vector
    @return 1 if equal, 0 if unequal
*/
static_always_inline int
_vec_is_equal (void *v1, void *v2, uword v1_elt_sz, uword v2_elt_sz)
{
  uword vec_len_v1 = vec_len (v1);

  if ((vec_len_v1 != vec_len (v2)) || (v1_elt_sz != v2_elt_sz))
    return 0;

  if ((vec_len_v1 == 0) || (memcmp (v1, v2, vec_len_v1 * v1_elt_sz) == 0))
    return 1;

  return 0;
}

#define vec_is_equal(v1, v2)                                                  \
  _vec_is_equal ((void *) (v1), (void *) (v2), _vec_elt_sz (v1),              \
		 _vec_elt_sz (v2))

/** \brief Compare two vectors (only applicable to vectors of signed numbers).
   Used in qsort compare functions.

    @param v1 Pointer to a vector
    @param v2 Pointer to a vector
    @return -1, 0, +1
*/
#define vec_cmp(v1,v2)					\
({							\
  word _v(i), _v(cmp), _v(l);				\
  _v(l) = clib_min (vec_len (v1), vec_len (v2));	\
  _v(cmp) = 0;						\
  for (_v(i) = 0; _v(i) < _v(l); _v(i)++) {		\
    _v(cmp) = (v1)[_v(i)] - (v2)[_v(i)];		\
    if (_v(cmp))					\
      break;						\
  }							\
  if (_v(cmp) == 0 && _v(l) > 0)			\
    _v(cmp) = vec_len(v1) - vec_len(v2);		\
  (_v(cmp) < 0 ? -1 : (_v(cmp) > 0 ? +1 : 0));		\
})

/** \brief Search a vector for the index of the entry that matches.

    @param v Pointer to a vector
    @param E Entry to match
    @return index of match or ~0
*/
#define vec_search(v,E)					\
({							\
  word _v(i) = 0;					\
  while (_v(i) < vec_len(v))				\
  {							\
    if ((v)[_v(i)] == E)				        \
      break;						\
    _v(i)++;						\
  }							\
  if (_v(i) == vec_len(v))				\
    _v(i) = ~0;					        \
  _v(i);						\
})

/** \brief Search a vector for the index of the entry that matches.

    @param v Pointer to a vector
    @param E Pointer to entry to match
    @param fn Comparison function !0 => match
    @return index of match or ~0
*/
#define vec_search_with_function(v,E,fn)                \
({							\
  word _v(i) = 0;					\
  while (_v(i) < vec_len(v))				\
  {							\
    if (0 != fn(&(v)[_v(i)], (E)))                      \
      break;						\
    _v(i)++;						\
  }							\
  if (_v(i) == vec_len(v))				\
    _v(i) = ~0;					        \
  _v(i);						\
})

/** \brief Sort a vector using the supplied element comparison function

    Does not depend on the underlying implementation to deal correctly
    with null, zero-long, or 1-long vectors

    @param vec vector to sort
    @param f comparison function
*/
#define vec_sort_with_function(vec, f)                                        \
  do                                                                          \
    {                                                                         \
      if (vec_len (vec) > 1)                                                  \
	qsort (vec, vec_len (vec), _vec_elt_sz (vec), (void *) (f));          \
    }                                                                         \
  while (0)

/** \brief Make a vector containing a NULL terminated c-string.

    @param V (possibly NULL) pointer to a vector.
    @param S pointer to string buffer.
    @param L string length (NOT including the terminating NULL; a la strlen())
*/
#define vec_validate_init_c_string(V, S, L)                                   \
  do                                                                          \
    {                                                                         \
      vec_reset_length (V);                                                   \
      vec_validate (V, (L));                                                  \
      if ((S) && (L))                                                         \
	clib_memcpy_fast (V, (S), (L));                                       \
      (V)[(L)] = 0;                                                           \
    }                                                                         \
  while (0)

/** \brief Test whether a vector is a NULL terminated c-string.

    @param V (possibly NULL) pointer to a vector.
    @return BOOLEAN indicating if the vector c-string is null terminated.
*/
#define vec_c_string_is_terminated(V)                   \
  (((V) != 0) && (vec_len (V) != 0) && ((V)[vec_len ((V)) - 1] == 0))

/** \brief (If necessary) NULL terminate a vector containing a c-string.

    @param V (possibly NULL) pointer to a vector.
    @return V (value-result macro parameter)
*/
#define vec_terminate_c_string(V)                                             \
  do                                                                          \
    {                                                                         \
      if (!vec_c_string_is_terminated (V))                                    \
	vec_add1 (V, 0);                                                      \
    }                                                                         \
  while (0)

#endif /* included_vec_h */
