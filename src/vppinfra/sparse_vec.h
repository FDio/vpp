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
  Copyright (c) 2005 Eliot Dresselhaus

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

#ifndef included_sparse_vec_h
#define included_sparse_vec_h

#include <vppinfra/clib.h>
#include <vppinfra/vec.h>

/* Sparsely indexed vectors.  Basic idea taken from Hacker's delight.
   Eliot added ranges. */
typedef struct
{
  /* Bitmap one for each sparse index. */
  uword *is_member_bitmap;

  /* member_counts[i] = total number of members with j < i. */
  u16 *member_counts;

#define SPARSE_VEC_IS_RANGE (1 << 0)
#define SPARSE_VEC_IS_VALID_RANGE (1 << 1)
  u8 *range_flags;
} sparse_vec_header_t;

always_inline sparse_vec_header_t *
sparse_vec_header (void *v)
{
  return vec_header (v, sizeof (sparse_vec_header_t));
}

/* Index 0 is always used to mark indices that are not valid in
   sparse vector.  For example, you look up V[0x1234] and 0x1234 is not
   known you'll get 0 back as an index. */
#define SPARSE_VEC_INVALID_INDEX (0)

always_inline void *
sparse_vec_new (uword elt_bytes, uword sparse_index_bits)
{
  void *v;
  sparse_vec_header_t *h;
  word n;

  ASSERT (sparse_index_bits <= 16);

  v = _vec_resize ((void *) 0,
		   /* length increment */ 8,
		   /* data bytes */ 8 * elt_bytes,
		   /* header bytes */ sizeof (h[0]),
		   /* data align */ 0);

  /* Make space for invalid entry (entry 0). */
  _vec_len (v) = 1;

  h = sparse_vec_header (v);

  n = sparse_index_bits - min_log2 (BITS (uword));
  if (n < 0)
    n = 0;
  n = 1ULL << n;
  vec_resize (h->is_member_bitmap, n);
  vec_resize (h->member_counts, n);

  return v;
}

always_inline uword
sparse_vec_index_internal (void *v,
			   uword sparse_index,
			   uword maybe_range, u32 * insert)
{
  sparse_vec_header_t *h;
  uword i, b, d, w;
  u8 is_member;

  h = sparse_vec_header (v);
  i = sparse_index / BITS (h->is_member_bitmap[0]);
  b = sparse_index % BITS (h->is_member_bitmap[0]);

  ASSERT (i < vec_len (h->is_member_bitmap));
  ASSERT (i < vec_len (h->member_counts));

  w = h->is_member_bitmap[i];

  /* count_trailing_zeros(0) == 0, take care of that case */
  if (PREDICT_FALSE (maybe_range == 0 && insert == 0 && w == 0))
    return 0;

  if (PREDICT_TRUE (maybe_range == 0 && insert == 0 &&
		    count_trailing_zeros (w) == b))
    return h->member_counts[i] + 1;

  d = h->member_counts[i] + count_set_bits (w & ((1ULL << b) - 1));
  is_member = (w & (1ULL << b)) != 0;

  if (maybe_range)
    {
      u8 r = h->range_flags[d];
      u8 is_range, is_valid_range;

      is_range = maybe_range & (r & SPARSE_VEC_IS_RANGE);
      is_valid_range = (r & SPARSE_VEC_IS_VALID_RANGE) != 0;

      is_member = is_range ? is_valid_range : is_member;
    }

  if (insert)
    {
      *insert = !is_member;
      if (!is_member)
	{
	  uword j;
	  w |= 1ULL << b;
	  h->is_member_bitmap[i] = w;
	  for (j = i + 1; j < vec_len (h->member_counts); j++)
	    h->member_counts[j] += 1;
	}

      return 1 + d;
    }

  d = is_member ? d : 0;

  return is_member + d;
}

always_inline uword
sparse_vec_index (void *v, uword sparse_index)
{
  return sparse_vec_index_internal (v, sparse_index,
				    /* maybe range */ 0,
				    /* insert? */ 0);
}

always_inline void
sparse_vec_index2 (void *v,
		   u32 si0, u32 si1, u32 * i0_return, u32 * i1_return)
{
  sparse_vec_header_t *h;
  uword b0, b1, w0, w1, v0, v1;
  u32 i0, i1, d0, d1;
  u8 is_member0, is_member1;

  h = sparse_vec_header (v);

  i0 = si0 / BITS (h->is_member_bitmap[0]);
  i1 = si1 / BITS (h->is_member_bitmap[0]);

  b0 = si0 % BITS (h->is_member_bitmap[0]);
  b1 = si1 % BITS (h->is_member_bitmap[0]);

  ASSERT (i0 < vec_len (h->is_member_bitmap));
  ASSERT (i1 < vec_len (h->is_member_bitmap));

  ASSERT (i0 < vec_len (h->member_counts));
  ASSERT (i1 < vec_len (h->member_counts));

  w0 = h->is_member_bitmap[i0];
  w1 = h->is_member_bitmap[i1];

  if (PREDICT_TRUE ((count_trailing_zeros (w0) == b0) +
		    (count_trailing_zeros (w1) == b1) == 2))
    {
      *i0_return = h->member_counts[i0] + 1;
      *i1_return = h->member_counts[i1] + 1;
      return;
    }

  v0 = w0 & ((1ULL << b0) - 1);
  v1 = w1 & ((1ULL << b1) - 1);

  /* Speculate that masks will have zero or one bits set. */
  d0 = h->member_counts[i0] + (v0 != 0);
  d1 = h->member_counts[i1] + (v1 != 0);

  /* Validate speculation. */
  if (PREDICT_FALSE (!is_pow2 (v0) || !is_pow2 (v1)))
    {
      d0 += count_set_bits (v0) - (v0 != 0);
      d1 += count_set_bits (v1) - (v1 != 0);
    }

  is_member0 = (w0 & (1ULL << b0)) != 0;
  is_member1 = (w1 & (1ULL << b1)) != 0;

  d0 = is_member0 ? d0 : 0;
  d1 = is_member1 ? d1 : 0;

  *i0_return = is_member0 + d0;
  *i1_return = is_member1 + d1;
}

#define sparse_vec_free(V)                                                    \
  do                                                                          \
    {                                                                         \
      if (V)                                                                  \
	{                                                                     \
	  clib_mem_free (sparse_vec_header (V));                              \
	  V = 0;                                                              \
	}                                                                     \
    }                                                                         \
  while (0)

#define sparse_vec_elt_at_index(v,i) \
  vec_elt_at_index ((v), sparse_vec_index ((v), (i)))

#define sparse_vec_validate(v,i)					\
({									\
  uword _i;								\
  u32 _insert;								\
									\
  if (! (v))								\
    (v) = sparse_vec_new (sizeof ((v)[0]), BITS (u16));			\
									\
  _i = sparse_vec_index_internal ((v), (i),				\
				  /* maybe range */ 0,			\
				  /* insert? */ &_insert);		\
  if (_insert)								\
    vec_insert_ha ((v), 1, _i,						\
		   /* header size */ sizeof (sparse_vec_header_t),	\
		   /* align */ 0);					\
									\
  /* Invalid index is 0. */						\
  ASSERT (_i > 0);							\
									\
  (v) + _i;								\
})

#endif /* included_sparse_vec_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
