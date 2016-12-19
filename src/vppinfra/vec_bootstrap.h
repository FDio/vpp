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
    Vector bootsrap header file
*/

/* Bootstrap include so that #include <vppinfra/mem.h> can include e.g.
   <vppinfra/mheap.h> which depends on <vppinfra/vec.h>. */

/** \brief vector header structure

   Bookeeping header preceding vector elements in memory.
   User header information may preceed standard vec header.
   If you change u32 len -> u64 len, single vectors can
   exceed 2**32 elements. Clib heaps are vectors. */

typedef struct
{
#if CLIB_VEC64 > 0
  u64 len;
#else
  u32 len; /**< Number of elements in vector (NOT its allocated length). */
#endif
  u8 vector_data[0];  /**< Vector data . */
} vec_header_t;

/** \brief Find the vector header

    Given the user's pointer to a vector, find the corresponding
    vector header

    @param v pointer to a vector
    @return pointer to the vector's vector_header_t
*/
#define _vec_find(v)	((vec_header_t *) (v) - 1)

#define _vec_round_size(s) \
  (((s) + sizeof (uword) - 1) &~ (sizeof (uword) - 1))

always_inline uword
vec_header_bytes (uword header_bytes)
{
  return round_pow2 (header_bytes + sizeof (vec_header_t),
		     sizeof (vec_header_t));
}

/** \brief Find a user vector header

    Finds the user header of a vector with unspecified alignment given
    the user pointer to the vector.
*/

always_inline void *
vec_header (void *v, uword header_bytes)
{
  return v - vec_header_bytes (header_bytes);
}

/** \brief Find the end of user vector header

    Finds the end of the user header of a vector with unspecified
    alignment given the user pointer to the vector.
*/

always_inline void *
vec_header_end (void *v, uword header_bytes)
{
  return v + vec_header_bytes (header_bytes);
}

always_inline uword
vec_aligned_header_bytes (uword header_bytes, uword align)
{
  return round_pow2 (header_bytes + sizeof (vec_header_t), align);
}

always_inline void *
vec_aligned_header (void *v, uword header_bytes, uword align)
{
  return v - vec_aligned_header_bytes (header_bytes, align);
}

always_inline void *
vec_aligned_header_end (void *v, uword header_bytes, uword align)
{
  return v + vec_aligned_header_bytes (header_bytes, align);
}


/** \brief Number of elements in vector (lvalue-capable)

   _vec_len (v) does not check for null, but can be used as a lvalue
   (e.g. _vec_len (v) = 99).
*/

#define _vec_len(v)	(_vec_find(v)->len)

/** \brief Number of elements in vector (rvalue-only, NULL tolerant)

    vec_len (v) checks for NULL, but cannot be used as an lvalue.
    If in doubt, use vec_len...
*/

#define vec_len(v)	((v) ? _vec_len(v) : 0)

/** \brief Reset vector length to zero
    NULL-pointer tolerant
*/

#define vec_reset_length(v) do { if (v) _vec_len (v) = 0; } while (0)

/** \brief Number of data bytes in vector. */

#define vec_bytes(v) (vec_len (v) * sizeof (v[0]))

/** \brief Total number of bytes that can fit in vector with current allocation. */

#define vec_capacity(v,b)							\
({										\
  void * _vec_capacity_v = (void *) (v);					\
  uword _vec_capacity_b = (b);							\
  _vec_capacity_b = sizeof (vec_header_t) + _vec_round_size (_vec_capacity_b);	\
  _vec_capacity_v ? clib_mem_size (_vec_capacity_v - _vec_capacity_b) : 0;	\
})

/** \brief Total number of elements that can fit into vector. */
#define vec_max_len(v) (vec_capacity(v,0) / sizeof (v[0]))

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
#define vec_foreach_backwards(var,vec) \
for (var = vec_end (vec) - 1; var >= (vec); var--)

/** \brief Iterate over vector indices. */
#define vec_foreach_index(var,v) for ((var) = 0; (var) < vec_len (v); (var)++)

#endif /* included_clib_vec_bootstrap_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
