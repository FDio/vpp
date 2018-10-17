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

#include <vppinfra/mhash.h>

always_inline u32
load_partial_u32 (void *d, uword n)
{
  if (n == 4)
    return ((u32 *) d)[0];
  if (n == 3)
    return ((u16 *) d)[0] | (((u8 *) d)[2] << 16);
  if (n == 2)
    return ((u16 *) d)[0];
  if (n == 1)
    return ((u8 *) d)[0];
  ASSERT (0);
  return 0;
}

always_inline u32
mhash_key_sum_inline (void *data, uword n_data_bytes, u32 seed)
{
  u32 *d32 = data;
  u32 a, b, c, n_left;

  a = b = c = seed;
  n_left = n_data_bytes;
  a ^= n_data_bytes;

  while (n_left > 12)
    {
      a += d32[0];
      b += d32[1];
      c += d32[2];
      hash_v3_mix32 (a, b, c);
      n_left -= 12;
      d32 += 3;
    }

  if (n_left > 8)
    {
      c += load_partial_u32 (d32 + 2, n_left - 8);
      n_left = 8;
    }
  if (n_left > 4)
    {
      b += load_partial_u32 (d32 + 1, n_left - 4);
      n_left = 4;
    }
  if (n_left > 0)
    a += load_partial_u32 (d32 + 0, n_left - 0);

  hash_v3_finalize32 (a, b, c);

  return c;
}

#define foreach_mhash_key_size			\
  _ (2) _ (3) _ (4) _ (5) _ (6) _ (7)		\
  _ (8) _ (12) _ (16) _ (20)			\
  _ (24) _ (28) _ (32) _ (36)			\
  _ (40) _ (44) _ (48) _ (52)			\
  _ (56) _ (60) _ (64)

#define _(N_KEY_BYTES)							\
  static uword								\
  mhash_key_sum_##N_KEY_BYTES (hash_t * h, uword key)			\
  {									\
    mhash_t * hv = uword_to_pointer (h->user, mhash_t *);		\
    return mhash_key_sum_inline (mhash_key_to_mem (hv, key),		\
				 (N_KEY_BYTES),				\
				 hv->hash_seed);			\
  }									\
									\
  static uword								\
  mhash_key_equal_##N_KEY_BYTES (hash_t * h, uword key1, uword key2)	\
  {									\
    mhash_t * hv = uword_to_pointer (h->user, mhash_t *);		\
    void * k1 = mhash_key_to_mem (hv, key1);				\
    void * k2 = mhash_key_to_mem (hv, key2);				\
    return ! memcmp (k1, k2, (N_KEY_BYTES));				\
  }

foreach_mhash_key_size
#undef _
static uword
mhash_key_sum_c_string (hash_t * h, uword key)
{
  mhash_t *hv = uword_to_pointer (h->user, mhash_t *);
  void *k = mhash_key_to_mem (hv, key);
  return mhash_key_sum_inline (k, strlen (k), hv->hash_seed);
}

static uword
mhash_key_equal_c_string (hash_t * h, uword key1, uword key2)
{
  mhash_t *hv = uword_to_pointer (h->user, mhash_t *);
  void *k1 = mhash_key_to_mem (hv, key1);
  void *k2 = mhash_key_to_mem (hv, key2);
  return strcmp (k1, k2) == 0;
}

static uword
mhash_key_sum_vec_string (hash_t * h, uword key)
{
  mhash_t *hv = uword_to_pointer (h->user, mhash_t *);
  void *k = mhash_key_to_mem (hv, key);
  return mhash_key_sum_inline (k, vec_len (k), hv->hash_seed);
}

static uword
mhash_key_equal_vec_string (hash_t * h, uword key1, uword key2)
{
  mhash_t *hv = uword_to_pointer (h->user, mhash_t *);
  void *k1 = mhash_key_to_mem (hv, key1);
  void *k2 = mhash_key_to_mem (hv, key2);
  return vec_len (k1) == vec_len (k2) && memcmp (k1, k2, vec_len (k1)) == 0;
}

/* The CLIB hash user pointer must always point to a valid mhash_t.
   Now, the address of mhash_t can change (think vec_resize).
   So we must always be careful that it points to the correct
   address. */
always_inline void
mhash_sanitize_hash_user (mhash_t * mh)
{
  uword *hash = mh->hash;
  hash_t *h = hash_header (hash);
  h->user = pointer_to_uword (mh);
}

void
mhash_init (mhash_t * h, uword n_value_bytes, uword n_key_bytes)
{
  static struct
  {
    hash_key_sum_function_t *key_sum;
    hash_key_equal_function_t *key_equal;
  } t[] =
  {
#define _(N_KEY_BYTES)					\
    [N_KEY_BYTES] = {					\
      .key_sum = mhash_key_sum_##N_KEY_BYTES,		\
      .key_equal = mhash_key_equal_##N_KEY_BYTES,	\
    },

    foreach_mhash_key_size
#undef _
      [MHASH_C_STRING_KEY] =
    {
    .key_sum = mhash_key_sum_c_string,.key_equal = mhash_key_equal_c_string,},
      [MHASH_VEC_STRING_KEY] =
    {
  .key_sum = mhash_key_sum_vec_string,.key_equal =
	mhash_key_equal_vec_string,},};

  if (mhash_key_vector_is_heap (h))
    heap_free (h->key_vector_or_heap);
  else
    vec_free (h->key_vector_or_heap);
  vec_free (h->key_vector_free_indices);
  {
    int i;
    for (i = 0; i < vec_len (h->key_tmps); i++)
      vec_free (h->key_tmps[i]);
  }
  vec_free (h->key_tmps);
  hash_free (h->hash);

  clib_memset (h, 0, sizeof (h[0]));
  h->n_key_bytes = n_key_bytes;

#if 0
  if (h->n_key_bytes > 0)
    {
      vec_validate (h->key_tmp, h->n_key_bytes - 1);
      _vec_len (h->key_tmp) = 0;
    }
#endif

  ASSERT (n_key_bytes < ARRAY_LEN (t));
  h->hash = hash_create2 ( /* elts */ 0,
			  /* user */ pointer_to_uword (h),
			  /* value_bytes */ n_value_bytes,
			  t[n_key_bytes].key_sum, t[n_key_bytes].key_equal,
			  /* format pair/arg */
			  0, 0);
}

static uword
mhash_set_tmp_key (mhash_t * h, const void *key)
{
  u8 *key_tmp;
  int my_cpu = os_get_thread_index ();

  vec_validate (h->key_tmps, my_cpu);
  key_tmp = h->key_tmps[my_cpu];

  vec_reset_length (key_tmp);

  if (mhash_key_vector_is_heap (h))
    {
      uword is_c_string = h->n_key_bytes == MHASH_C_STRING_KEY;

      if (is_c_string)
	vec_add (key_tmp, key, strlen (key) + 1);
      else
	vec_add (key_tmp, key, vec_len (key));
    }
  else
    vec_add (key_tmp, key, h->n_key_bytes);

  h->key_tmps[my_cpu] = key_tmp;

  return ~0;
}

hash_pair_t *
mhash_get_pair (mhash_t * h, const void *key)
{
  uword ikey;
  mhash_sanitize_hash_user (h);
  ikey = mhash_set_tmp_key (h, key);
  return hash_get_pair (h->hash, ikey);
}

typedef struct
{
  u32 heap_handle;

  /* Must coincide with vec_header. */
  vec_header_t vec;
} mhash_string_key_t;

uword
mhash_set_mem (mhash_t * h, void *key, uword * new_value, uword * old_value)
{
  u8 *k;
  uword ikey, i, l = 0, n_key_bytes, old_n_elts, key_alloc_from_free_list = 0;

  mhash_sanitize_hash_user (h);

  if (mhash_key_vector_is_heap (h))
    {
      mhash_string_key_t *sk;
      uword is_c_string = h->n_key_bytes == MHASH_C_STRING_KEY;
      uword handle;

      n_key_bytes = is_c_string ? (strlen (key) + 1) : vec_len (key);
      i =
	heap_alloc (h->key_vector_or_heap, n_key_bytes + sizeof (sk[0]),
		    handle);

      sk = (void *) (h->key_vector_or_heap + i);
      sk->heap_handle = handle;
      sk->vec.len = n_key_bytes;
      clib_memcpy (sk->vec.vector_data, key, n_key_bytes);

      /* Advance key past vector header. */
      i += sizeof (sk[0]);
    }
  else
    {
      key_alloc_from_free_list = (l =
				  vec_len (h->key_vector_free_indices)) > 0;
      if (key_alloc_from_free_list)
	{
	  i = h->key_vector_free_indices[l - 1];
	  k = vec_elt_at_index (h->key_vector_or_heap, i);
	  _vec_len (h->key_vector_free_indices) = l - 1;
	}
      else
	{
	  vec_add2 (h->key_vector_or_heap, k, h->n_key_bytes);
	  i = k - h->key_vector_or_heap;
	}

      n_key_bytes = h->n_key_bytes;
      clib_memcpy (k, key, n_key_bytes);
    }
  ikey = i;

  old_n_elts = hash_elts (h->hash);
  h->hash = _hash_set3 (h->hash, ikey, new_value, old_value);

  /* If element already existed remove duplicate key. */
  if (hash_elts (h->hash) == old_n_elts)
    {
      hash_pair_t *p;

      /* Fetch old key for return value. */
      p = hash_get_pair (h->hash, ikey);
      ikey = p->key;

      /* Remove duplicate key. */
      if (mhash_key_vector_is_heap (h))
	{
	  mhash_string_key_t *sk;
	  sk = (void *) (h->key_vector_or_heap + i - sizeof (sk[0]));
	  heap_dealloc (h->key_vector_or_heap, sk->heap_handle);
	}
      else
	{
	  if (key_alloc_from_free_list)
	    {
	      h->key_vector_free_indices[l] = i;
	      _vec_len (h->key_vector_free_indices) = l + 1;
	    }
	  else
	    _vec_len (h->key_vector_or_heap) -= h->n_key_bytes;
	}
    }

  return ikey;
}

uword
mhash_unset (mhash_t * h, void *key, uword * old_value)
{
  hash_pair_t *p;
  uword i;

  mhash_sanitize_hash_user (h);
  i = mhash_set_tmp_key (h, key);

  p = hash_get_pair (h->hash, i);
  if (!p)
    return 0;

  ASSERT (p->key != ~0);
  i = p->key;

  if (mhash_key_vector_is_heap (h))
    {
      mhash_string_key_t *sk;
      sk = (void *) (h->key_vector_or_heap + i) - sizeof (sk[0]);
      heap_dealloc (h->key_vector_or_heap, sk->heap_handle);
    }
  else
    vec_add1 (h->key_vector_free_indices, i);

  hash_unset3 (h->hash, i, old_value);
  return 1;
}

u8 *
format_mhash_key (u8 * s, va_list * va)
{
  mhash_t *h = va_arg (*va, mhash_t *);
  u32 ki = va_arg (*va, u32);
  void *k = mhash_key_to_mem (h, ki);

  if (mhash_key_vector_is_heap (h))
    {
      uword is_c_string = h->n_key_bytes == MHASH_C_STRING_KEY;
      u32 l = is_c_string ? strlen (k) : vec_len (k);
      vec_add (s, k, l);
    }
  else if (h->format_key)
    s = format (s, "%U", h->format_key, k);
  else
    s = format (s, "%U", format_hex_bytes, k, h->n_key_bytes);

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
