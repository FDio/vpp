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

#ifndef included_clib_vec_bootstrap_h
#define included_clib_vec_bootstrap_h

/** \file
    Vector bootstrap header file
*/

/* Bootstrap include so that #include <vppinfra/mem.h> can include e.g.
   <vppinfra/mheap.h> which depends on <vppinfra/vec.h>. */

/** \brief vector header structure

   Bookkeeping header preceding vector elements in memory.
   User header information may preceed standard vec header.
   If you change u32 len -> u64 len, single vectors can
   exceed 2**32 elements. Clib heaps are vectors. */

typedef struct
{
  u32 len; /**< Number of elements in vector (NOT its allocated length). */
  u8 hdr_size;	      /**< header size divided by VEC_MIN_ALIGN */
  u8 log2_align : 7;  /**< data alignment */
  u8 default_heap : 1; /**< vector uses default heap */
  u8 grow_elts;	       /**< number of elts vector can grow without realloc */
  u8 vpad[1];	       /**< pad to 8 bytes */
  u8 vector_data[0];  /**< Vector data . */
} vec_header_t;

#define VEC_MIN_ALIGN 8

/** \brief Find the vector header

    Given the user's pointer to a vector, find the corresponding
    vector header

    @param v pointer to a vector
    @return pointer to the vector's vector_header_t
*/
#define _vec_find(v)	((vec_header_t *) (v) - 1)
#define _vec_heap(v)	(((void **) (_vec_find (v)))[-1])

always_inline uword __vec_align (uword data_align, uword configuered_align);
always_inline uword __vec_elt_sz (uword elt_sz, int is_void);

#define _vec_round_size(s) \
  (((s) + sizeof (uword) - 1) &~ (sizeof (uword) - 1))
#define _vec_is_void(P)                                                       \
  __builtin_types_compatible_p (__typeof__ ((P)[0]), void)
#define _vec_elt_sz(V)	 __vec_elt_sz (sizeof ((V)[0]), _vec_is_void (V))
#define _vec_align(V, A) __vec_align (__alignof__((V)[0]), A)

always_inline __clib_nosanitize_addr uword
vec_get_header_size (void *v)
{
  uword header_size = _vec_find (v)->hdr_size * VEC_MIN_ALIGN;
  return header_size;
}

/** \brief Find a user vector header

    Finds the user header of a vector with unspecified alignment given
    the user pointer to the vector.
*/

always_inline void *
vec_header (void *v)
{
  return v ? v - vec_get_header_size (v) : 0;
}

/** \brief Find the end of user vector header

    Finds the end of the user header of a vector with unspecified
    alignment given the user pointer to the vector.
*/

always_inline void *
vec_header_end (void *v)
{
  return v + vec_get_header_size (v);
}

/** \brief Number of elements in vector (rvalue-only, NULL tolerant)

    vec_len (v) checks for NULL, but cannot be used as an lvalue.
    If in doubt, use vec_len...
*/

static_always_inline u32
__vec_len (void *v)
{
  return _vec_find (v)->len;
}

#define _vec_len(v)	__vec_len ((void *) (v))
#define vec_len(v)	((v) ? _vec_len(v) : 0)

u32 vec_len_not_inline (void *v);

/** \brief Number of data bytes in vector. */

#define vec_bytes(v) (vec_len (v) * sizeof (v[0]))

/**
 * Return size of memory allocated for the vector
 *
 * @param v vector
 * @return memory size allocated for the vector
 */

uword vec_mem_size (void *v);

/**
 * Number of elements that can fit into generic vector
 *
 * @param v vector
 * @param b extra header bytes
 * @return number of elements that can fit into vector
 */

always_inline uword
vec_max_bytes (void *v)
{
  return v ? vec_mem_size (v) - vec_get_header_size (v) : 0;
}

always_inline uword
_vec_max_len (void *v, uword elt_sz)
{
  return vec_max_bytes (v) / elt_sz;
}

#define vec_max_len(v) _vec_max_len (v, _vec_elt_sz (v))

static_always_inline void
_vec_set_grow_elts (void *v, uword n_elts)
{
  uword max = pow2_mask (BITS (_vec_find (0)->grow_elts));

  if (PREDICT_FALSE (n_elts > max))
    n_elts = max;

  _vec_find (v)->grow_elts = n_elts;
}

always_inline void
_vec_set_len (void *v, uword len, uword elt_sz)
{
  ASSERT (v);
  ASSERT (len <= _vec_max_len (v, elt_sz));
  uword old_len = _vec_len (v);
  uword grow_elts = _vec_find (v)->grow_elts;

  if (len > old_len)
    clib_mem_unpoison (v + old_len * elt_sz, (len - old_len) * elt_sz);
  else if (len < old_len)
    clib_mem_poison (v + len * elt_sz, (old_len - len) * elt_sz);

  _vec_set_grow_elts (v, old_len + grow_elts - len);
  _vec_find (v)->len = len;
}

#define vec_set_len(v, l) _vec_set_len ((void *) v, l, _vec_elt_sz (v))
#define vec_inc_len(v, l) vec_set_len (v, _vec_len (v) + (l))
#define vec_dec_len(v, l) vec_set_len (v, _vec_len (v) - (l))

/** \brief Reset vector length to zero
    NULL-pointer tolerant
*/
#define vec_reset_length(v) do { if (v) vec_set_len (v, 0); } while (0)

/** \brief End (last data address) of vector. */
#define vec_end(v)	((v) + vec_len (v))

/** \brief True if given pointer is within given vector. */
#define vec_is_member(v,e) ((e) >= (v) && (e) < vec_end (v))

/** \brief Get vector value at index i checking that i is in bounds. */
#define vec_elt_at_index(v,i)			\
({						\
  ASSERT ((i) < vec_len (v));			\
  (v) + (i);					\
})

/** \brief Get vector value at index i */
#define vec_elt(v,i) (vec_elt_at_index(v,i))[0]

/** \brief Vector iterator */
#define vec_foreach(var,vec) for (var = (vec); var < vec_end (vec); var++)

/** \brief Vector iterator (reverse) */
#define vec_foreach_backwards(var, vec)                                       \
  if (vec)                                                                    \
    for (var = vec_end (vec) - 1; var >= (vec); var--)

/** \brief Iterate over vector indices. */
#define vec_foreach_index(var,v) for ((var) = 0; (var) < vec_len (v); (var)++)

/** \brief Iterate over vector indices (reverse). */
#define vec_foreach_index_backwards(var, v)                                   \
  if (v)                                                                      \
    for ((var) = vec_len ((v)) - 1; (var) >= 0; (var)--)

#define vec_foreach_pointer(e, v)                                             \
  for (typeof (**v) **__ep = (v), *(e) = *__ep; __ep - (v) < vec_len (v);     \
       __ep++, (e) = *__ep)

#endif /* included_clib_vec_bootstrap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
