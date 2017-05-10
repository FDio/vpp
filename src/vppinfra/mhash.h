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
#ifndef included_clib_mhash_h
#define included_clib_mhash_h

/*
  Copyright (c) 2010 Eliot Dresselhaus

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

#include <vppinfra/format.h>
#include <vppinfra/hash.h>
#include <vppinfra/heap.h>

/* Hash table plus vector of keys. */
typedef struct
{
  /* Vector or heap used to store keys.  Hash table stores keys as byte
     offsets into this vector. */
  u8 *key_vector_or_heap;

  /* Byte offsets of free keys in vector (used to store free keys when
     n_key_bytes > 1). */
  u32 *key_vector_free_indices;

  u8 **key_tmps;

  /* Possibly fixed size of key.
     0 means keys are vectors of u8's.
     1 means keys are null terminated c strings. */
#define MHASH_VEC_STRING_KEY 0
#define MHASH_C_STRING_KEY 1
  u32 n_key_bytes;

  /* Seed value for Jenkins hash. */
  u32 hash_seed;

  /* Hash table mapping key -> value. */
  uword *hash;

  /* Format function for keys. */
  format_function_t *format_key;
} mhash_t;

void mhash_init (mhash_t * h, uword n_value_bytes, uword n_key_bytes);

always_inline void
mhash_init_c_string (mhash_t * h, uword n_value_bytes)
{
  mhash_init (h, n_value_bytes, MHASH_C_STRING_KEY);
}

always_inline void
mhash_init_vec_string (mhash_t * h, uword n_value_bytes)
{
  mhash_init (h, n_value_bytes, MHASH_VEC_STRING_KEY);
}

always_inline void *
mhash_key_to_mem (mhash_t * h, uword key)
{
  if (key == ~0)
    {
      u8 *key_tmp;

      int my_cpu = os_get_thread_index ();
      vec_validate (h->key_tmps, my_cpu);
      key_tmp = h->key_tmps[my_cpu];
      return key_tmp;
    }
  return vec_elt_at_index (h->key_vector_or_heap, key);
}

hash_pair_t *mhash_get_pair (mhash_t * h, const void *key);
uword mhash_set_mem (mhash_t * h, void *key, uword * new_value,
		     uword * old_value);
uword mhash_unset (mhash_t * h, void *key, uword * old_value);

always_inline uword *
mhash_get (mhash_t * h, const void *key)
{
  hash_pair_t *p = mhash_get_pair (h, key);
  return p ? &p->value[0] : 0;
}

always_inline uword
mhash_set (mhash_t * h, void *key, uword new_value, uword * old_value)
{
  return mhash_set_mem (h, key, &new_value, old_value);
}

always_inline uword
mhash_unset_key (mhash_t * h, uword key, uword * old_value)
{
  void *k = mhash_key_to_mem (h, key);
  return mhash_unset (h, k, old_value);
}

always_inline uword
mhash_value_bytes (mhash_t * m)
{
  hash_t *h = hash_header (m->hash);
  return hash_value_bytes (h);
}

always_inline uword
mhash_elts (mhash_t * m)
{
  return hash_elts (m->hash);
}

always_inline uword
mhash_key_vector_is_heap (mhash_t * h)
{
  return h->n_key_bytes <= 1;
}

always_inline void
mhash_free (mhash_t * h)
{
  if (mhash_key_vector_is_heap (h))
    heap_free (h->key_vector_or_heap);
  else
    vec_free (h->key_vector_or_heap);
  vec_free (h->key_vector_free_indices);
  hash_free (h->hash);
}

#define mhash_foreach(k,v,mh,body)				\
do {								\
  hash_pair_t * _mhash_foreach_p;				\
  hash_foreach_pair (_mhash_foreach_p, (mh)->hash, ({		\
    (k) = mhash_key_to_mem ((mh), _mhash_foreach_p->key);	\
    (v) = &_mhash_foreach_p->value[0];				\
    body;							\
  }));								\
} while (0)

format_function_t format_mhash_key;

#endif /* included_clib_mhash_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
