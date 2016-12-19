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
  Copyright (c) 2006 Eliot Dresselhaus

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

#ifndef included_qhash_h
#define included_qhash_h

#include <vppinfra/cache.h>
#include <vppinfra/hash.h>

/* Word hash tables. */
typedef struct
{
  /* Number of elements in hash. */
  u32 n_elts;

  u32 log2_hash_size;

  /* Jenkins hash seeds. */
  u32 hash_seeds[3];

  /* Fall back CLIB hash for overflow in fixed sized buckets. */
  uword *overflow_hash;

  u32 *overflow_counts, *overflow_free_indices;

  u8 *hash_key_valid_bitmap;

  uword *hash_keys;
} qhash_t;

always_inline qhash_t *
qhash_header (void *v)
{
  return vec_header (v, sizeof (qhash_t));
}

always_inline uword
qhash_elts (void *v)
{
  return v ? qhash_header (v)->n_elts : 0;
}

always_inline uword
qhash_n_overflow (void *v)
{
  return v ? hash_elts (qhash_header (v)->overflow_hash) : 0;
}

#define QHASH_LOG2_KEYS_PER_BUCKET 2
#define QHASH_KEYS_PER_BUCKET (1 << QHASH_LOG2_KEYS_PER_BUCKET)

always_inline uword
qhash_hash_mix (qhash_t * h, uword key)
{
  u32 a, b, c;

  a = h->hash_seeds[0];
  b = h->hash_seeds[1];
  c = h->hash_seeds[2];

  a ^= key;
#if uword_bits == 64
  b ^= key >> 32;
#endif

  hash_mix32 (a, b, c);

  return c & pow2_mask (h->log2_hash_size);
}

#define qhash_resize(v,n) (v) = _qhash_resize ((v), (n), sizeof ((v)[0]))

#define qhash_foreach(var,v,body)

#define qhash_set_multiple(v,keys,n,results) \
  (v) = _qhash_set_multiple ((v), sizeof ((v)[0]), (keys), (n), (results))

#define qhash_unset_multiple(v,keys,n,results) \
  _qhash_unset_multiple ((v), sizeof ((v)[0]), (keys), (n), (results))

#define qhash_get(v,key)					\
({								\
  uword _qhash_get_k = (key);					\
  qhash_get_first_match ((v), &_qhash_get_k, 1, &_qhash_get_k);	\
})

#define qhash_set(v,k)						\
({								\
  uword _qhash_set_k = (k);					\
  qhash_set_multiple ((v), &_qhash_set_k, 1, &_qhash_set_k);	\
  _qhash_set_k;							\
})

#define qhash_unset(v,k)						\
({									\
  uword _qhash_unset_k = (k);						\
  qhash_unset_multiple ((v), &_qhash_unset_k, 1, &_qhash_unset_k);	\
  _qhash_unset_k;							\
})

void *_qhash_resize (void *v, uword length, uword elt_bytes);

/* Lookup multiple keys in the same hash table. */
void
qhash_get_multiple (void *v,
		    uword * search_keys,
		    uword n_search_keys, u32 * result_indices);

/* Lookup multiple keys in the same hash table.
   Returns index of first matching key. */
u32
qhash_get_first_match (void *v,
		       uword * search_keys,
		       uword n_search_keys, uword * matching_key);

/* Set/unset helper functions. */
void *_qhash_set_multiple (void *v,
			   uword elt_bytes,
			   uword * search_keys,
			   uword n_search_keys, u32 * result_indices);
void
_qhash_unset_multiple (void *v,
		       uword elt_bytes,
		       uword * search_keys,
		       uword n_search_keys, u32 * result_indices);

#endif /* included_qhash_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
