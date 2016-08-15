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

#include <vppinfra/qhash.h>

#define QHASH_ALL_VALID ((1 << QHASH_KEYS_PER_BUCKET) - 1)

void *
_qhash_resize (void *v, uword length, uword elt_bytes)
{
  qhash_t *h;
  uword l;

  l = clib_max (max_log2 (length), 2 + QHASH_LOG2_KEYS_PER_BUCKET);

  /* Round up if less than 1/2 full. */
  l += ((f64) length / (f64) (1 << l)) < .5;

  v = _vec_resize (0, 1 << l, elt_bytes << l, sizeof (h[0]),
		   /* align */ sizeof (uword));

  h = qhash_header (v);
  h->n_elts = 0;
  h->log2_hash_size = l;
  h->hash_keys =
    clib_mem_alloc_aligned_no_fail (sizeof (h->hash_keys[0]) << l,
				    CLIB_CACHE_LINE_BYTES);
  vec_resize (h->hash_key_valid_bitmap,
	      1 << (l - QHASH_LOG2_KEYS_PER_BUCKET));
  memset (v, ~0, elt_bytes << l);

  return v;
}

static u8 min_log2_table[256];

static inline uword
qhash_min_log2 (uword x)
{
  ASSERT (is_pow2 (x));
  ASSERT (x < 256);
  return min_log2_table[x];
}

static void
qhash_min_log2_init ()
{
  int i;
  for (i = 0; i < 256; i++)
    min_log2_table[i] = min_log2 (i);
}

always_inline uword
qhash_get_valid_elt_mask (qhash_t * h, uword i)
{
  return h->hash_key_valid_bitmap[i / QHASH_KEYS_PER_BUCKET];
}

always_inline void
qhash_set_valid_elt_mask (qhash_t * h, uword i, uword mask)
{
  h->hash_key_valid_bitmap[i / QHASH_KEYS_PER_BUCKET] = mask;
}

always_inline uword
qhash_search_bucket (uword * hash_keys, uword search_key, uword m)
{
  uword t;
#define _(i) ((hash_keys[i] == search_key) << i)
  t = (_(0) | _(1) | _(2) | _(3));
  if (QHASH_KEYS_PER_BUCKET > 4)
    t |= (_(4) | _(5) | _(6) | _(7));
  if (QHASH_KEYS_PER_BUCKET > 8)
    t |= (_(8) | _(9) | _(10) | _(11) | _(12) | _(13) | _(14) | _(15));
#undef _
  return m & t;
}

/* Lookup multiple keys in the same hash table. */
void
qhash_get_multiple (void *v,
		    uword * search_keys,
		    uword n_search_keys, u32 * result_indices)
{
  qhash_t *h = qhash_header (v);
  uword *k, *hash_keys;
  uword n_left, bucket_mask;
  u32 *r;

  if (!v)
    {
      memset (result_indices, ~0, sizeof (result_indices[0]) * n_search_keys);
      return;
    }

  bucket_mask = pow2_mask (h->log2_hash_size) & ~(QHASH_KEYS_PER_BUCKET - 1);

  k = search_keys;
  n_left = n_search_keys;
  hash_keys = h->hash_keys;
  r = result_indices;

  while (n_left >= 2)
    {
      u32 a0, b0, c0, bi0, valid0, match0;
      u32 a1, b1, c1, bi1, valid1, match1;
      uword k0, k1, *h0, *h1;

      k0 = k[0];
      k1 = k[1];
      n_left -= 2;
      k += 2;

      a0 = a1 = h->hash_seeds[0];
      b0 = b1 = h->hash_seeds[1];
      c0 = c1 = h->hash_seeds[2];
      a0 ^= k0;
      a1 ^= k1;
#if uword_bits == 64
      b0 ^= k0 >> 32;
      b1 ^= k1 >> 32;
#endif

      hash_mix32_step_1 (a0, b0, c0);
      hash_mix32_step_1 (a1, b1, c1);
      hash_mix32_step_2 (a0, b0, c0);
      hash_mix32_step_2 (a1, b1, c1);
      hash_mix32_step_3 (a0, b0, c0);
      hash_mix32_step_3 (a1, b1, c1);

      bi0 = c0 & bucket_mask;
      bi1 = c1 & bucket_mask;

      h0 = hash_keys + bi0;
      h1 = hash_keys + bi1;

      /* Search two buckets. */
      valid0 = qhash_get_valid_elt_mask (h, bi0);
      valid1 = qhash_get_valid_elt_mask (h, bi1);

      match0 = qhash_search_bucket (h0, k0, valid0);
      match1 = qhash_search_bucket (h1, k1, valid1);

      bi0 += qhash_min_log2 (match0);
      bi1 += qhash_min_log2 (match1);

      r[0] = match0 ? bi0 : ~0;
      r[1] = match1 ? bi1 : ~0;
      r += 2;

      /* Full buckets trigger search of overflow hash. */
      if (PREDICT_FALSE (!match0 && valid0 == QHASH_ALL_VALID))
	{
	  uword *p = hash_get (h->overflow_hash, k0);
	  r[-2] = p ? p[0] : ~0;
	}

      /* Full buckets trigger search of overflow hash. */
      if (PREDICT_FALSE (!match1 && valid1 == QHASH_ALL_VALID))
	{
	  uword *p = hash_get (h->overflow_hash, k1);
	  r[-1] = p ? p[0] : ~0;
	}
    }

  while (n_left >= 1)
    {
      u32 a0, b0, c0, bi0, valid0, match0;
      uword k0, *h0;

      k0 = k[0];
      n_left -= 1;
      k += 1;

      a0 = h->hash_seeds[0];
      b0 = h->hash_seeds[1];
      c0 = h->hash_seeds[2];
      a0 ^= k0;
#if uword_bits == 64
      b0 ^= k0 >> 32;
#endif

      hash_mix32 (a0, b0, c0);

      bi0 = c0 & bucket_mask;

      h0 = hash_keys + bi0;

      /* Search one bucket. */
      valid0 = qhash_get_valid_elt_mask (h, bi0);
      match0 = qhash_search_bucket (h0, k0, valid0);

      bi0 += qhash_min_log2 (match0);

      r[0] = match0 ? bi0 : ~0;
      r += 1;

      /* Full buckets trigger search of overflow hash. */
      if (PREDICT_FALSE (!match0 && valid0 == QHASH_ALL_VALID))
	{
	  uword *p = hash_get (h->overflow_hash, k0);
	  r[-1] = p ? p[0] : ~0;
	}
    }
}

/* Lookup multiple keys in the same hash table.
   Returns index of first matching key. */
u32
qhash_get_first_match (void *v,
		       uword * search_keys,
		       uword n_search_keys, uword * matching_key)
{
  qhash_t *h = qhash_header (v);
  uword *k, *hash_keys;
  uword n_left, match_mask, bucket_mask;

  if (!v)
    return ~0;

  match_mask = 0;
  bucket_mask = pow2_mask (h->log2_hash_size) & ~(QHASH_KEYS_PER_BUCKET - 1);

  k = search_keys;
  n_left = n_search_keys;
  hash_keys = h->hash_keys;
  while (n_left >= 2)
    {
      u32 a0, b0, c0, bi0, valid0;
      u32 a1, b1, c1, bi1, valid1;
      uword k0, k1, *h0, *h1;

      k0 = k[0];
      k1 = k[1];
      n_left -= 2;
      k += 2;

      a0 = a1 = h->hash_seeds[0];
      b0 = b1 = h->hash_seeds[1];
      c0 = c1 = h->hash_seeds[2];
      a0 ^= k0;
      a1 ^= k1;
#if uword_bits == 64
      b0 ^= k0 >> 32;
      b1 ^= k1 >> 32;
#endif

      hash_mix32_step_1 (a0, b0, c0);
      hash_mix32_step_1 (a1, b1, c1);
      hash_mix32_step_2 (a0, b0, c0);
      hash_mix32_step_2 (a1, b1, c1);
      hash_mix32_step_3 (a0, b0, c0);
      hash_mix32_step_3 (a1, b1, c1);

      bi0 = c0 & bucket_mask;
      bi1 = c1 & bucket_mask;

      h0 = hash_keys + bi0;
      h1 = hash_keys + bi1;

      /* Search two buckets. */
      valid0 = qhash_get_valid_elt_mask (h, bi0);
      valid1 = qhash_get_valid_elt_mask (h, bi1);
      match_mask = qhash_search_bucket (h0, k0, valid0);
      match_mask |= (qhash_search_bucket (h1, k1, valid1)
		     << QHASH_KEYS_PER_BUCKET);
      if (match_mask)
	{
	  uword bi, is_match1;

	  bi = qhash_min_log2 (match_mask);
	  is_match1 = bi >= QHASH_KEYS_PER_BUCKET;

	  bi += ((is_match1 ? bi1 : bi0)
		 - (is_match1 << QHASH_LOG2_KEYS_PER_BUCKET));
	  *matching_key = (k - 2 - search_keys) + is_match1;
	  return bi;
	}

      /* Full buckets trigger search of overflow hash. */
      if (PREDICT_FALSE (valid0 == QHASH_ALL_VALID
			 || valid1 == QHASH_ALL_VALID))
	{
	  uword *p = 0;
	  uword ki = k - 2 - search_keys;

	  if (valid0 == QHASH_ALL_VALID)
	    p = hash_get (h->overflow_hash, k0);

	  if (!p && valid1 == QHASH_ALL_VALID)
	    {
	      p = hash_get (h->overflow_hash, k1);
	      ki++;
	    }

	  if (p)
	    {
	      *matching_key = ki;
	      return p[0];
	    }
	}
    }

  while (n_left >= 1)
    {
      u32 a0, b0, c0, bi0, valid0;
      uword k0, *h0;

      k0 = k[0];
      n_left -= 1;
      k += 1;

      a0 = h->hash_seeds[0];
      b0 = h->hash_seeds[1];
      c0 = h->hash_seeds[2];
      a0 ^= k0;
#if uword_bits == 64
      b0 ^= k0 >> 32;
#endif

      hash_mix32 (a0, b0, c0);

      bi0 = c0 & bucket_mask;

      h0 = hash_keys + bi0;

      /* Search one bucket. */
      valid0 = qhash_get_valid_elt_mask (h, bi0);
      match_mask = qhash_search_bucket (h0, k0, valid0);
      if (match_mask)
	{
	  uword bi;
	  bi = bi0 + qhash_min_log2 (match_mask);
	  *matching_key = (k - 1 - search_keys);
	  return bi;
	}

      /* Full buckets trigger search of overflow hash. */
      if (PREDICT_FALSE (valid0 == QHASH_ALL_VALID))
	{
	  uword *p = hash_get (h->overflow_hash, k0);
	  if (p)
	    {
	      *matching_key = (k - 1 - search_keys);
	      return p[0];
	    }
	}
    }

  return ~0;
}

static void *
qhash_set_overflow (void *v, uword elt_bytes,
		    uword key, uword bi, uword * n_elts, u32 * result)
{
  qhash_t *h = qhash_header (v);
  uword *p = hash_get (h->overflow_hash, key);
  uword i;

  bi /= QHASH_KEYS_PER_BUCKET;

  if (p)
    i = p[0];
  else
    {
      uword l = vec_len (h->overflow_free_indices);
      if (l > 0)
	{
	  i = h->overflow_free_indices[l - 1];
	  _vec_len (h->overflow_free_indices) = l - 1;
	}
      else
	i = (1 << h->log2_hash_size) + hash_elts (h->overflow_hash);
      hash_set (h->overflow_hash, key, i);
      vec_validate (h->overflow_counts, bi);
      h->overflow_counts[bi] += 1;
      *n_elts += 1;

      l = vec_len (v);
      if (i >= l)
	{
	  uword dl = round_pow2 (1 + i - l, 8);
	  v = _vec_resize (v, dl, (l + dl) * elt_bytes, sizeof (h[0]),
			   /* align */ sizeof (uword));
	  memset (v + l * elt_bytes, ~0, dl * elt_bytes);
	}
    }

  *result = i;

  return v;
}

static uword
qhash_unset_overflow (void *v, uword key, uword bi, uword * n_elts)
{
  qhash_t *h = qhash_header (v);
  uword *p = hash_get (h->overflow_hash, key);
  uword result;

  bi /= QHASH_KEYS_PER_BUCKET;

  if (p)
    {
      result = p[0];
      hash_unset (h->overflow_hash, key);
      ASSERT (bi < vec_len (h->overflow_counts));
      ASSERT (h->overflow_counts[bi] > 0);
      ASSERT (*n_elts > 0);
      vec_add1 (h->overflow_free_indices, result);
      h->overflow_counts[bi] -= 1;
      *n_elts -= 1;
    }
  else
    result = ~0;

  return result;
}

always_inline uword
qhash_find_free (uword i, uword valid_mask)
{
  return first_set (~valid_mask & pow2_mask (QHASH_KEYS_PER_BUCKET));
}

void *
_qhash_set_multiple (void *v,
		     uword elt_bytes,
		     uword * search_keys,
		     uword n_search_keys, u32 * result_indices)
{
  qhash_t *h = qhash_header (v);
  uword *k, *hash_keys;
  uword n_left, n_elts, bucket_mask;
  u32 *r;

  if (vec_len (v) < n_search_keys)
    v = _qhash_resize (v, n_search_keys, elt_bytes);

  if (qhash_min_log2 (2) != 1)
    {
      qhash_min_log2_init ();
      ASSERT (qhash_min_log2 (2) == 1);
    }

  ASSERT (v != 0);

  bucket_mask = pow2_mask (h->log2_hash_size) & ~(QHASH_KEYS_PER_BUCKET - 1);

  hash_keys = h->hash_keys;
  k = search_keys;
  r = result_indices;
  n_left = n_search_keys;
  n_elts = h->n_elts;

  while (n_left >= 2)
    {
      u32 a0, b0, c0, bi0, match0, valid0, free0;
      u32 a1, b1, c1, bi1, match1, valid1, free1;
      uword k0, *h0;
      uword k1, *h1;

      k0 = k[0];
      k1 = k[1];

      /* Keys must be unique. */
      ASSERT (k0 != k1);

      n_left -= 2;
      k += 2;

      a0 = a1 = h->hash_seeds[0];
      b0 = b1 = h->hash_seeds[1];
      c0 = c1 = h->hash_seeds[2];
      a0 ^= k0;
      a1 ^= k1;
#if uword_bits == 64
      b0 ^= k0 >> 32;
      b1 ^= k1 >> 32;
#endif

      hash_mix32_step_1 (a0, b0, c0);
      hash_mix32_step_1 (a1, b1, c1);
      hash_mix32_step_2 (a0, b0, c0);
      hash_mix32_step_2 (a1, b1, c1);
      hash_mix32_step_3 (a0, b0, c0);
      hash_mix32_step_3 (a1, b1, c1);

      bi0 = c0 & bucket_mask;
      bi1 = c1 & bucket_mask;

      h0 = hash_keys + bi0;
      h1 = hash_keys + bi1;

      /* Search two buckets. */
      valid0 = qhash_get_valid_elt_mask (h, bi0);
      valid1 = qhash_get_valid_elt_mask (h, bi1);

      match0 = qhash_search_bucket (h0, k0, valid0);
      match1 = qhash_search_bucket (h1, k1, valid1);

      /* Find first free element starting at hash offset into bucket. */
      free0 = qhash_find_free (c0 & (QHASH_KEYS_PER_BUCKET - 1), valid0);

      valid1 = valid1 | (bi0 == bi1 ? free0 : 0);
      free1 = qhash_find_free (c1 & (QHASH_KEYS_PER_BUCKET - 1), valid1);

      n_elts += (match0 == 0) + (match1 == 0);

      match0 = match0 ? match0 : free0;
      match1 = match1 ? match1 : free1;

      valid0 |= match0;
      valid1 |= match1;

      h0 += qhash_min_log2 (match0);
      h1 += qhash_min_log2 (match1);

      if (PREDICT_FALSE (!match0 || !match1))
	goto slow_path2;

      h0[0] = k0;
      h1[0] = k1;
      r[0] = h0 - hash_keys;
      r[1] = h1 - hash_keys;
      r += 2;
      qhash_set_valid_elt_mask (h, bi0, valid0);
      qhash_set_valid_elt_mask (h, bi1, valid1);
      continue;

    slow_path2:
      if (!match0)
	{
	  n_elts -= 1;
	  v = qhash_set_overflow (v, elt_bytes, k0, bi0, &n_elts, &r[0]);
	}
      else
	{
	  h0[0] = k0;
	  r[0] = h0 - hash_keys;
	  qhash_set_valid_elt_mask (h, bi0, valid0);
	}
      if (!match1)
	{
	  n_elts -= 1;
	  v = qhash_set_overflow (v, elt_bytes, k1, bi1, &n_elts, &r[1]);
	}
      else
	{
	  h1[0] = k1;
	  r[1] = h1 - hash_keys;
	  qhash_set_valid_elt_mask (h, bi1, valid1);
	}
      r += 2;
    }

  while (n_left >= 1)
    {
      u32 a0, b0, c0, bi0, match0, valid0, free0;
      uword k0, *h0;

      k0 = k[0];
      n_left -= 1;
      k += 1;

      a0 = h->hash_seeds[0];
      b0 = h->hash_seeds[1];
      c0 = h->hash_seeds[2];
      a0 ^= k0;
#if uword_bits == 64
      b0 ^= k0 >> 32;
#endif

      hash_mix32 (a0, b0, c0);

      bi0 = c0 & bucket_mask;

      h0 = hash_keys + bi0;

      valid0 = qhash_get_valid_elt_mask (h, bi0);

      /* Find first free element starting at hash offset into bucket. */
      free0 = qhash_find_free (c0 & (QHASH_KEYS_PER_BUCKET - 1), valid0);

      match0 = qhash_search_bucket (h0, k0, valid0);

      n_elts += (match0 == 0);

      match0 = match0 ? match0 : free0;

      valid0 |= match0;

      h0 += qhash_min_log2 (match0);

      if (PREDICT_FALSE (!match0))
	goto slow_path1;

      h0[0] = k0;
      r[0] = h0 - hash_keys;
      r += 1;
      qhash_set_valid_elt_mask (h, bi0, valid0);
      continue;

    slow_path1:
      n_elts -= 1;
      v = qhash_set_overflow (v, elt_bytes, k0, bi0, &n_elts, &r[0]);
      r += 1;
    }

  h = qhash_header (v);
  h->n_elts = n_elts;

  return v;
}

static uword
unset_slow_path (void *v, uword elt_bytes,
		 uword k0, uword bi0, uword valid0, uword match0,
		 uword * n_elts)
{
  qhash_t *h = qhash_header (v);
  uword i, j = 0, k, l, t = ~0;
  hash_pair_t *p, *found;

  if (!match0)
    {
      if (valid0 == QHASH_ALL_VALID)
	t = qhash_unset_overflow (v, k0, bi0, n_elts);
      return t;
    }

  i = bi0 / QHASH_KEYS_PER_BUCKET;
  t = bi0 + qhash_min_log2 (match0);

  if (valid0 == QHASH_ALL_VALID
      && i < vec_len (h->overflow_counts) && h->overflow_counts[i] > 0)
    {
      found = 0;
      /* *INDENT-OFF* */
      hash_foreach_pair (p, h->overflow_hash, ({
	j = qhash_hash_mix (h, p->key) / QHASH_KEYS_PER_BUCKET;
	if (j == i)
	  {
	    found = p;
	    break;
	  }
      }));
      /* *INDENT-ON* */
      ASSERT (found != 0);
      ASSERT (j == i);

      l = found->value[0];
      k = found->key;
      hash_unset3 (h->overflow_hash, k, &j);
      vec_add1 (h->overflow_free_indices, j);
      h->overflow_counts[i] -= 1;

      qhash_set_valid_elt_mask (h, bi0, valid0);

      h->hash_keys[t] = k;
      clib_memswap (v + t * elt_bytes, v + l * elt_bytes, elt_bytes);
      t = l;
    }
  else
    qhash_set_valid_elt_mask (h, bi0, valid0 ^ match0);

  return t;
}

void
_qhash_unset_multiple (void *v,
		       uword elt_bytes,
		       uword * search_keys,
		       uword n_search_keys, u32 * result_indices)
{
  qhash_t *h = qhash_header (v);
  uword *k, *hash_keys;
  uword n_left, n_elts, bucket_mask;
  u32 *r;

  if (!v)
    {
      uword i;
      for (i = 0; i < n_search_keys; i++)
	result_indices[i] = ~0;
    }

  bucket_mask = pow2_mask (h->log2_hash_size) & ~(QHASH_KEYS_PER_BUCKET - 1);

  hash_keys = h->hash_keys;
  k = search_keys;
  r = result_indices;
  n_left = n_search_keys;
  n_elts = h->n_elts;

  while (n_left >= 2)
    {
      u32 a0, b0, c0, bi0, match0, valid0;
      u32 a1, b1, c1, bi1, match1, valid1;
      uword k0, *h0;
      uword k1, *h1;

      k0 = k[0];
      k1 = k[1];

      /* Keys must be unique. */
      ASSERT (k0 != k1);

      n_left -= 2;
      k += 2;

      a0 = a1 = h->hash_seeds[0];
      b0 = b1 = h->hash_seeds[1];
      c0 = c1 = h->hash_seeds[2];
      a0 ^= k0;
      a1 ^= k1;
#if uword_bits == 64
      b0 ^= k0 >> 32;
      b1 ^= k1 >> 32;
#endif

      hash_mix32_step_1 (a0, b0, c0);
      hash_mix32_step_1 (a1, b1, c1);
      hash_mix32_step_2 (a0, b0, c0);
      hash_mix32_step_2 (a1, b1, c1);
      hash_mix32_step_3 (a0, b0, c0);
      hash_mix32_step_3 (a1, b1, c1);

      bi0 = c0 & bucket_mask;
      bi1 = c1 & bucket_mask;

      h0 = hash_keys + bi0;
      h1 = hash_keys + bi1;

      /* Search two buckets. */
      valid0 = qhash_get_valid_elt_mask (h, bi0);
      valid1 = qhash_get_valid_elt_mask (h, bi1);

      match0 = qhash_search_bucket (h0, k0, valid0);
      match1 = qhash_search_bucket (h1, k1, valid1);

      n_elts -= (match0 != 0) + (match1 != 0);

      if (PREDICT_FALSE (valid0 == QHASH_ALL_VALID
			 || valid1 == QHASH_ALL_VALID))
	goto slow_path2;

      valid0 ^= match0;
      qhash_set_valid_elt_mask (h, bi0, valid0);

      valid1 = bi0 == bi1 ? valid0 : valid1;
      valid1 ^= match1;

      qhash_set_valid_elt_mask (h, bi1, valid1);

      r[0] = match0 ? bi0 + qhash_min_log2 (match0) : ~0;
      r[1] = match1 ? bi1 + qhash_min_log2 (match1) : ~0;
      r += 2;
      continue;

    slow_path2:
      r[0] = unset_slow_path (v, elt_bytes, k0, bi0, valid0, match0, &n_elts);
      if (bi0 == bi1)
	{
	  /* Search again in same bucket to test new overflow element. */
	  valid1 = qhash_get_valid_elt_mask (h, bi0);
	  if (!match1)
	    {
	      match1 = qhash_search_bucket (h1, k1, valid1);
	      n_elts -= (match1 != 0);
	    }
	}
      r[1] = unset_slow_path (v, elt_bytes, k1, bi1, valid1, match1, &n_elts);
      r += 2;
    }

  while (n_left >= 1)
    {
      u32 a0, b0, c0, bi0, match0, valid0;
      uword k0, *h0;

      k0 = k[0];
      n_left -= 1;
      k += 1;

      a0 = h->hash_seeds[0];
      b0 = h->hash_seeds[1];
      c0 = h->hash_seeds[2];
      a0 ^= k0;
#if uword_bits == 64
      b0 ^= k0 >> 32;
#endif

      hash_mix32 (a0, b0, c0);

      bi0 = c0 & bucket_mask;

      h0 = hash_keys + bi0;

      valid0 = qhash_get_valid_elt_mask (h, bi0);

      match0 = qhash_search_bucket (h0, k0, valid0);
      n_elts -= (match0 != 0);
      qhash_set_valid_elt_mask (h, bi0, valid0 ^ match0);

      r[0] = match0 ? bi0 + qhash_min_log2 (match0) : ~0;
      r += 1;

      if (PREDICT_FALSE (valid0 == QHASH_ALL_VALID))
	r[-1] = unset_slow_path (v, elt_bytes, k0, bi0, valid0, match0,
				 &n_elts);
    }

  h->n_elts = n_elts;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
