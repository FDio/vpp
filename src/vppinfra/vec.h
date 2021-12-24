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
                    user header (aligned to uword boundary)
                    vector length: number of elements
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

   Users may specify the alignment for first data element of a vector
   via the vec_*_aligned macros.

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

/** \brief Low-level resize allocation function, usually not called directly

    @param v pointer to a vector
    @param length_increment length increment in elements
    @param data_bytes requested size in bytes
    @param header_bytes header size in bytes (may be zero)
    @param data_align alignment (may be zero)
    @param numa_id numa id (may be zero)
    @return v_prime pointer to resized vector, may or may not equal v
*/
void *vec_resize_allocate_memory (void *v,
				  word length_increment,
				  uword data_bytes,
				  uword header_bytes, uword data_align,
				  uword numa_id);

/** \brief Low-level vector resize function, usually not called directly

    @param v pointer to a vector
    @param length_increment length increment in elements
    @param data_bytes requested size in bytes
    @param header_bytes header size in bytes (may be zero)
    @param data_align alignment (may be zero)
    @param numa_id (may be ~0)
    @return v_prime pointer to resized vector, may or may not equal v
*/

#define _vec_resize_numa(V,L,DB,HB,A,S)					\
({									\
  __typeof__ ((V)) _V;							\
  _V = _vec_resize_inline((void *)V,L,DB,HB,clib_max((__alignof__((V)[0])),(A)),(S)); \
  _V;									\
})

#define _vec_resize(V,L,DB,HB,A)  \
  _vec_resize_numa(V,L,DB,HB,A,VEC_NUMA_UNSPECIFIED)

always_inline void *
_vec_resize_inline (void *v,
		    word length_increment,
		    uword data_bytes, uword header_bytes, uword data_align,
		    uword numa_id)
{
  vec_header_t *vh;
  uword new_data_bytes, aligned_header_bytes;
  void *oldheap;

  aligned_header_bytes = vec_header_bytes (header_bytes);

  new_data_bytes = data_bytes + aligned_header_bytes;

  if (PREDICT_TRUE (v != 0))
    {
      vh = _vec_find (v);
      void *p = v - aligned_header_bytes;

      if (PREDICT_FALSE (numa_id != VEC_NUMA_UNSPECIFIED))
	{
	  oldheap = clib_mem_get_per_cpu_heap ();
	  clib_mem_set_per_cpu_heap (clib_mem_get_per_numa_heap (numa_id));
	}

      /* Vector header must start heap object. */
      ASSERT (clib_mem_is_heap_object (p));

      /* Typically we'll not need to resize. */
      if (new_data_bytes <= clib_mem_size (p))
	{
	  CLIB_MEM_UNPOISON (v, data_bytes);
	  vh->len += length_increment;
	  if (PREDICT_FALSE (numa_id != VEC_NUMA_UNSPECIFIED))
	    clib_mem_set_per_cpu_heap (oldheap);
	  return v;
	}
      if (PREDICT_FALSE (numa_id != VEC_NUMA_UNSPECIFIED))
	clib_mem_set_per_cpu_heap (oldheap);
    }

  /* Slow path: call helper function. */
  return vec_resize_allocate_memory (v, length_increment, data_bytes,
				     header_bytes,
				     clib_max (sizeof (vec_header_t),
					       data_align), numa_id);
}

/** \brief Determine if vector will resize with next allocation

    @param v pointer to a vector
    @param length_increment length increment in elements
    @param data_bytes requested size in bytes
    @param header_bytes header size in bytes (may be zero)
    @param data_align alignment (may be zero)
    @return 1 if vector will resize 0 otherwise
*/

always_inline int
_vec_resize_will_expand (void *v,
			 word length_increment,
			 uword data_bytes, uword header_bytes,
			 uword data_align)
{
  uword new_data_bytes, aligned_header_bytes;

  aligned_header_bytes = vec_header_bytes (header_bytes);

  new_data_bytes = data_bytes + aligned_header_bytes;

  if (PREDICT_TRUE (v != 0))
    {
      void *p = v - aligned_header_bytes;

      /* Vector header must start heap object. */
      ASSERT (clib_mem_is_heap_object (p));

      /* Typically we'll not need to resize. */
      if (new_data_bytes <= clib_mem_size (p))
	return 0;
    }
  return 1;
}

/** \brief Determine if vector will resize with next allocation

    @param V pointer to a vector
    @param N number of elements to add
    @return 1 if vector will resize 0 otherwise
*/

#define vec_resize_will_expand(V, N)                                          \
  ({                                                                          \
    word _v (n) = (N);                                                        \
    word _v (l) = vec_len (V);                                                \
    _vec_resize_will_expand ((V), _v (n),                                     \
			     (_v (l) + _v (n)) * sizeof ((V)[0]), 0, 0);      \
  })

/** \brief Predicate function, says whether the supplied vector is a clib heap
    object (general version).

    @param v pointer to a vector
    @param header_bytes vector header size in bytes (may be zero)
    @return 0 or 1
*/
uword clib_mem_is_vec_h (void *v, uword header_bytes);


/** \brief Predicate function, says whether the supplied vector is a clib heap
    object

    @param v pointer to a vector
    @return 0 or 1
*/
always_inline uword
clib_mem_is_vec (void *v)
{
  return clib_mem_is_vec_h (v, 0);
}

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
    @param S numa_id (may be zero)
    @return V (value-result macro parameter)
*/

#define vec_resize_has(V,N,H,A,S)                               \
do {                                                            \
  word _v(n) = (N);                                             \
  word _v(l) = vec_len (V);                                     \
  V = _vec_resize_numa ((V), _v(n),                           \
                          (_v(l) + _v(n)) * sizeof ((V)[0]),    \
                          (H), (A),(S));                        \
} while (0)

/** \brief Resize a vector (less general version).
   Add N elements to end of given vector V, return pointer to start of vector.
   Vector will have room for H header bytes and will have user's data aligned
   at alignment A (rounded to next power of 2).

    @param V pointer to a vector
    @param N number of elements to add
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/
#define vec_resize_ha(V,N,H,A) vec_resize_has(V,N,H,A,VEC_NUMA_UNSPECIFIED)

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

#define vec_alloc_ha(V,N,H,A)			\
do {						\
    uword _v(l) = vec_len (V);			\
    vec_resize_ha (V, N, H, A);			\
    _vec_len (V) = _v(l);			\
} while (0)

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
    @return V new vector
*/
#define vec_new_ha(T,N,H,A)						\
({									\
  word _v(n) = (N);							\
  (T *)_vec_resize ((T *) 0, _v(n), _v(n) * sizeof (T), (H), (A));	\
})

/** \brief Create new vector of given type and length
    (unspecified alignment, no header).

    @param T type of elements in new vector
    @param N number of elements to add
    @return V new vector
*/
#define vec_new(T,N)           vec_new_ha(T,N,0,0)
/** \brief Create new vector of given type and length
    (alignment specified, no header).

    @param T type of elements in new vector
    @param N number of elements to add
    @param A alignment (may be zero)
    @return V new vector
*/
#define vec_new_aligned(T,N,A) vec_new_ha(T,N,0,A)

/** \brief Free vector's memory (general version)

    @param V pointer to a vector
    @param H size of header in bytes
    @return V (value-result parameter, V=0)
*/
#define vec_free_h(V,H)				\
do {						\
  if (V)					\
    {						\
      clib_mem_free (vec_header ((V), (H)));	\
      V = 0;					\
    }						\
} while (0)

/** \brief Free vector's memory (no header).
    @param V pointer to a vector
    @return V (value-result parameter, V=0)
*/
#define vec_free(V) vec_free_h(V,0)

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
    @param S numa (may be VEC_NUMA_UNSPECIFIED)

    @return Vdup copy of vector
*/

#define vec_dup_ha_numa(V,H,A,S)                      \
({							\
  __typeof__ ((V)[0]) * _v(v) = 0;			\
  uword _v(l) = vec_len (V);				\
  if (_v(l) > 0)					\
    {							\
      vec_resize_has (_v(v), _v(l), (H), (A), (S));     \
      clib_memcpy_fast (_v(v), (V), _v(l) * sizeof ((V)[0]));\
    }							\
  _v(v);						\
})

/** \brief Return copy of vector (VEC_NUMA_UNSPECIFIED).

    @param V pointer to a vector
    @param H size of header in bytes
    @param A alignment (may be zero)

    @return Vdup copy of vector
*/
#define vec_dup_ha(V,H,A) \
  vec_dup_ha_numa(V,H,A,VEC_NUMA_UNSPECIFIED)


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
#define vec_copy(DST,SRC) clib_memcpy_fast (DST, SRC, vec_len (DST) * \
				       sizeof ((DST)[0]))

/** \brief Clone a vector. Make a new vector with the
    same size as a given vector but possibly with a different type.

    @param NEW_V pointer to new vector
    @param OLD_V pointer to old vector
*/
#define vec_clone(NEW_V,OLD_V)							\
do {										\
  (NEW_V) = 0;									\
  (NEW_V) = _vec_resize ((NEW_V), vec_len (OLD_V),				\
			 vec_len (OLD_V) * sizeof ((NEW_V)[0]), (0), (0));	\
} while (0)

/** \brief Make sure vector is long enough for given index (general version).

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @param N numa_id (may be zero)
    @return V (value-result macro parameter)
*/

#define vec_validate_han(V,I,H,A,N)                                     \
do {                                                                    \
  void *oldheap;                                                        \
  STATIC_ASSERT(A==0 || ((A % sizeof(V[0]))==0)                         \
        || ((sizeof(V[0]) % A) == 0),                                   \
    "vector validate aligned on incorrectly sized object");             \
  word _v(i) = (I);                                                     \
  word _v(l) = vec_len (V);                                             \
  if (_v(i) >= _v(l))                                                   \
    {                                                                   \
      /* switch to the per-numa heap if directed */                   \
      if (PREDICT_FALSE(N != VEC_NUMA_UNSPECIFIED))                   \
        {                                                               \
           oldheap = clib_mem_get_per_cpu_heap();                       \
           clib_mem_set_per_cpu_heap (clib_mem_get_per_numa_heap(N)); \
        }                                                               \
                                                                        \
      vec_resize_ha ((V), 1 + (_v(i) - _v(l)), (H), (A));               \
      /* Must zero new space since user may have previously             \
	 used e.g. _vec_len (v) -= 10 */                                \
      clib_memset ((V) + _v(l), 0,                                      \
                   (1 + (_v(i) - _v(l))) * sizeof ((V)[0]));            \
      /* Switch back to the global heap */                              \
      if (PREDICT_FALSE (N != VEC_NUMA_UNSPECIFIED))                  \
        clib_mem_set_per_cpu_heap (oldheap);                            \
    }                                                                   \
} while (0)

#define vec_validate_ha(V,I,H,A) vec_validate_han(V,I,H,A,VEC_NUMA_UNSPECIFIED)

/** \brief Make sure vector is long enough for given index
    (no header, unspecified alignment)

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @return V (value-result macro parameter)
*/
#define vec_validate(V,I)           vec_validate_ha(V,I,0,0)

/** \brief Make sure vector is long enough for given index
    (no header, specified alignment)

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/

#define vec_validate_aligned(V,I,A) vec_validate_ha(V,I,0,A)

/** \brief Make sure vector is long enough for given index
    and initialize empty space (general version)

    @param V (possibly NULL) pointer to a vector.
    @param I vector index which will be valid upon return
    @param INIT initial value (can be a complex expression!)
    @param H header size in bytes (may be zero)
    @param A alignment (may be zero)
    @return V (value-result macro parameter)
*/
#define vec_validate_init_empty_ha(V,I,INIT,H,A)		\
do {								\
  word _v(i) = (I);						\
  word _v(l) = vec_len (V);					\
  if (_v(i) >= _v(l))						\
    {								\
      vec_resize_ha ((V), 1 + (_v(i) - _v(l)), (H), (A));	\
      while (_v(l) <= _v(i))					\
	{							\
	  (V)[_v(l)] = (INIT);					\
	  _v(l)++;						\
	}							\
    }								\
} while (0)

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
#define vec_add1_ha(V,E,H,A)						\
do {									\
  word _v(l) = vec_len (V);						\
  V = _vec_resize ((V), 1, (_v(l) + 1) * sizeof ((V)[0]), (H), (A));	\
  (V)[_v(l)] = (E);							\
} while (0)

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
#define vec_add2_ha(V,P,N,H,A)							\
do {										\
  word _v(n) = (N);								\
  word _v(l) = vec_len (V);							\
  V = _vec_resize ((V), _v(n), (_v(l) + _v(n)) * sizeof ((V)[0]), (H), (A));	\
  P = (V) + _v(l);								\
} while (0)

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
#define vec_add_ha(V, E, N, H, A)                                             \
  do                                                                          \
    {                                                                         \
      word _v (n) = (N);                                                      \
      if (PREDICT_TRUE (_v (n) > 0))                                          \
	{                                                                     \
	  word _v (l) = vec_len (V);                                          \
	  V = _vec_resize ((V), _v (n), (_v (l) + _v (n)) * sizeof ((V)[0]),  \
			   (H), (A));                                         \
	  clib_memcpy_fast ((V) + _v (l), (E), _v (n) * sizeof ((V)[0]));     \
	}                                                                     \
    }                                                                         \
  while (0)

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
#define vec_pop(V)				\
({						\
  uword _v(l) = vec_len (V);			\
  ASSERT (_v(l) > 0);				\
  _v(l) -= 1;					\
  _vec_len (V) = _v (l);			\
  (V)[_v(l)];					\
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
#define vec_insert_init_empty_ha(V,N,M,INIT,H,A)	\
do {							\
  word _v(l) = vec_len (V);				\
  word _v(n) = (N);					\
  word _v(m) = (M);					\
  V = _vec_resize ((V),					\
		   _v(n),				\
		   (_v(l) + _v(n))*sizeof((V)[0]),	\
		   (H), (A));				\
  ASSERT (_v(m) <= _v(l));				\
  memmove ((V) + _v(m) + _v(n),				\
	   (V) + _v(m),					\
	   (_v(l) - _v(m)) * sizeof ((V)[0]));		\
  clib_memset  ((V) + _v(m), INIT, _v(n) * sizeof ((V)[0]));	\
} while (0)

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

#define vec_insert_elts_ha(V, E, N, M, H, A)                                  \
  do                                                                          \
    {                                                                         \
      word _v (n) = (N);                                                      \
      if (PREDICT_TRUE (_v (n) > 0))                                          \
	{                                                                     \
	  word _v (l) = vec_len (V);                                          \
	  word _v (m) = (M);                                                  \
	  V = _vec_resize ((V), _v (n), (_v (l) + _v (n)) * sizeof ((V)[0]),  \
			   (H), (A));                                         \
	  ASSERT (_v (m) <= _v (l));                                          \
	  memmove ((V) + _v (m) + _v (n), (V) + _v (m),                       \
		   (_v (l) - _v (m)) * sizeof ((V)[0]));                      \
	  clib_memcpy_fast ((V) + _v (m), (E), _v (n) * sizeof ((V)[0]));     \
	}                                                                     \
    }                                                                         \
  while (0)

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
#define vec_delete(V,N,M)					\
do {								\
  word _v(l) = vec_len (V);					\
  word _v(n) = (N);						\
  word _v(m) = (M);						\
  /* Copy over deleted elements. */				\
  if (_v(l) - _v(n) - _v(m) > 0)				\
    memmove ((V) + _v(m), (V) + _v(m) + _v(n),			\
	     (_v(l) - _v(n) - _v(m)) * sizeof ((V)[0]));	\
  /* Zero empty space at end (for future re-allocation). */	\
  if (_v(n) > 0)						\
    clib_memset ((V) + _v(l) - _v(n), 0, _v(n) * sizeof ((V)[0]));	\
  _vec_len (V) -= _v(n);					\
  CLIB_MEM_POISON(vec_end(V), _v(n) * sizeof ((V)[0]));         \
} while (0)

/** \brief Delete the element at index I

    @param V pointer to a vector
    @param I index to delete
*/
#define vec_del1(v,i)				\
do {						\
  uword _vec_del_l = _vec_len (v) - 1;		\
  uword _vec_del_i = (i);			\
  if (_vec_del_i < _vec_del_l)			\
    (v)[_vec_del_i] = (v)[_vec_del_l];		\
  _vec_len (v) = _vec_del_l;			\
  CLIB_MEM_POISON(vec_end(v), sizeof ((v)[0])); \
} while (0)

/** \brief Append v2 after v1. Result in v1.
    @param V1 target vector
    @param V2 vector to append
*/

#define vec_append(v1, v2)                                                    \
  do                                                                          \
    {                                                                         \
      uword _v (l1) = vec_len (v1);                                           \
      uword _v (l2) = vec_len (v2);                                           \
                                                                              \
      if (PREDICT_TRUE (_v (l2) > 0))                                         \
	{                                                                     \
	  v1 = _vec_resize ((v1), _v (l2),                                    \
			    (_v (l1) + _v (l2)) * sizeof ((v1)[0]), 0, 0);    \
	  clib_memcpy_fast ((v1) + _v (l1), (v2),                             \
			    _v (l2) * sizeof ((v2)[0]));                      \
	}                                                                     \
    }                                                                         \
  while (0)

/** \brief Append v2 after v1. Result in v1. Specified alignment.
    @param V1 target vector
    @param V2 vector to append
    @param align required alignment
*/

#define vec_append_aligned(v1, v2, align)                                     \
  do                                                                          \
    {                                                                         \
      uword _v (l1) = vec_len (v1);                                           \
      uword _v (l2) = vec_len (v2);                                           \
                                                                              \
      if (PREDICT_TRUE (_v (l2) > 0))                                         \
	{                                                                     \
	  v1 = _vec_resize (                                                  \
	    (v1), _v (l2), (_v (l1) + _v (l2)) * sizeof ((v1)[0]), 0, align); \
	  clib_memcpy_fast ((v1) + _v (l1), (v2),                             \
			    _v (l2) * sizeof ((v2)[0]));                      \
	}                                                                     \
    }                                                                         \
  while (0)

/** \brief Prepend v2 before v1. Result in v1.
    @param V1 target vector
    @param V2 vector to prepend
*/

#define vec_prepend(v1, v2)                                                   \
  do                                                                          \
    {                                                                         \
      uword _v (l1) = vec_len (v1);                                           \
      uword _v (l2) = vec_len (v2);                                           \
                                                                              \
      if (PREDICT_TRUE (_v (l2) > 0))                                         \
	{                                                                     \
	  v1 = _vec_resize ((v1), _v (l2),                                    \
			    (_v (l1) + _v (l2)) * sizeof ((v1)[0]), 0, 0);    \
	  memmove ((v1) + _v (l2), (v1), _v (l1) * sizeof ((v1)[0]));         \
	  clib_memcpy_fast ((v1), (v2), _v (l2) * sizeof ((v2)[0]));          \
	}                                                                     \
    }                                                                         \
  while (0)

/** \brief Prepend v2 before v1. Result in v1. Specified alignment
    @param V1 target vector
    @param V2 vector to prepend
    @param align required alignment
*/

#define vec_prepend_aligned(v1, v2, align)                                    \
  do                                                                          \
    {                                                                         \
      uword _v (l1) = vec_len (v1);                                           \
      uword _v (l2) = vec_len (v2);                                           \
                                                                              \
      if (PREDICT_TRUE (_v (l2) > 0))                                         \
	{                                                                     \
	  v1 = _vec_resize (                                                  \
	    (v1), _v (l2), (_v (l1) + _v (l2)) * sizeof ((v1)[0]), 0, align); \
	  memmove ((v1) + _v (l2), (v1), _v (l1) * sizeof ((v1)[0]));         \
	  clib_memcpy_fast ((v1), (v2), _v (l2) * sizeof ((v2)[0]));          \
	}                                                                     \
    }                                                                         \
  while (0)

/** \brief Zero all vector elements. Null-pointer tolerant.
    @param var Vector to zero
*/
#define vec_zero(var)						\
do {								\
  if (var)							\
    clib_memset ((var), 0, vec_len (var) * sizeof ((var)[0]));	\
} while (0)

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
#define vec_is_equal(v1,v2) \
  (vec_len (v1) == vec_len (v2) && ! memcmp ((v1), (v2), vec_len (v1) * sizeof ((v1)[0])))

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
#define vec_sort_with_function(vec,f)                           \
do {                                                            \
  if (vec_len (vec) > 1)                                        \
    qsort (vec, vec_len (vec), sizeof (vec[0]), (void *) (f));  \
} while (0)

/** \brief Make a vector containing a NULL terminated c-string.

    @param V (possibly NULL) pointer to a vector.
    @param S pointer to string buffer.
    @param L string length (NOT including the terminating NULL; a la strlen())
*/
#define vec_validate_init_c_string(V, S, L)     \
  do {                                          \
    vec_reset_length (V);                       \
    vec_validate ((V), (L));                    \
    if ((S) && (L))                             \
        clib_memcpy_fast ((V), (S), (L));            \
    (V)[(L)] = 0;                               \
  } while (0)


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
#define vec_terminate_c_string(V)               \
  do {                                          \
    u32 vl = vec_len ((V));                     \
    if (!vec_c_string_is_terminated(V))         \
      {                                         \
        vec_validate ((V), vl);                 \
        (V)[vl] = 0;                            \
      }                                         \
  } while (0)

#endif /* included_vec_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
