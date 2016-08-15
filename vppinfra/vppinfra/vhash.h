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

#ifndef included_clib_vhash_h
#define included_clib_vhash_h

#include <vppinfra/vector.h>

#ifdef CLIB_HAVE_VEC128

#include <vppinfra/cache.h>
#include <vppinfra/hash.h>
#include <vppinfra/pipeline.h>

/* Gathers 32 bits worth of key with given index. */
typedef u32 (vhash_key_function_t) (void *state, u32 vector_index,
				    u32 key_word_index);
typedef u32x4 (vhash_4key_function_t) (void *state, u32 vector_index,
				       u32 key_word_index);
/* Sets/gets result of hash lookup. */
typedef u32 (vhash_result_function_t) (void *state, u32 vector_index,
				       u32 result, u32 n_key_u32);
typedef u32x4 (vhash_4result_function_t) (void *state, u32 vector_index,
					  u32x4 results, u32 n_key_u32);

typedef struct
{
  u32x4_union_t hashed_key[3];
} vhash_hashed_key_t;

/* Search buckets are really this structure. */
typedef struct
{
  /* 4 results for this bucket.
     Zero is used to mark empty results.  This means user can't use the result ~0
     since user results differ from internal results stored in buckets by 1.
     e.g. internal result = user result + 1. */
  u32x4_union_t result;

  /* n_key_u32s u32x4s of key data follow. */
  u32x4_union_t key[0];
} vhash_search_bucket_t;

typedef struct
{
  u32x4_union_t *search_buckets;

  /* Vector of bucket free indices. */
  u32 *free_indices;

  /* Number of entries in this overflow bucket. */
  u32 n_overflow;
} vhash_overflow_buckets_t;

typedef struct
{
  /* 2^log2_n_keys keys grouped in groups of 4.
     Each bucket contains 4 results plus 4 keys for a
     total of (1 + n_key_u32) u32x4s. */
  u32x4_union_t *search_buckets;

  /* When a bucket of 4 results/keys are full we search
     the overflow.  hash_key is used to select which overflow
     bucket. */
  vhash_overflow_buckets_t overflow_buckets[16];

  /* Total count of occupied elements in hash table. */
  u32 n_elts;

  u32 log2_n_keys;

  /* Number of 32 bit words in a hash key. */
  u32 n_key_u32;

  u32x4_union_t bucket_mask;

  /* table[i] = min_log2 (first_set (~i)). */
  u8 find_first_zero_table[16];

  /* Hash seeds for Jenkins hash. */
  u32x4_union_t hash_seeds[3];

  /* Key work space is a vector of length
     n_key_u32s << log2_n_key_word_len_u32x. */
  u32 log2_n_key_word_len_u32x;

  /* Work space to store keys between pipeline stages. */
  u32x4_union_t *key_work_space;

  /* Hash work space to store Jenkins hash values between
     pipeline stages. */
  vhash_hashed_key_t *hash_work_space;
} vhash_t;

always_inline vhash_overflow_buckets_t *
vhash_get_overflow_buckets (vhash_t * h, u32 key)
{
  u32 i = (((key & h->bucket_mask.as_u32[0]) >> 2) & 0xf);
  ASSERT (i < ARRAY_LEN (h->overflow_buckets));
  return h->overflow_buckets + i;
}

always_inline uword
vhash_is_non_empty_overflow_bucket (vhash_t * h, u32 key)
{
  u32 i = (((key & h->bucket_mask.as_u32[0]) >> 2) & 0xf);
  ASSERT (i < ARRAY_LEN (h->overflow_buckets));
  return h->overflow_buckets[i].n_overflow > 0;
}

always_inline void
vhash_free_overflow_buckets (vhash_overflow_buckets_t * obs)
{
  vec_free (obs->search_buckets);
  vec_free (obs->free_indices);
}

always_inline void
vhash_free (vhash_t * h)
{
  uword i;
  for (i = 0; i < ARRAY_LEN (h->overflow_buckets); i++)
    vhash_free_overflow_buckets (&h->overflow_buckets[i]);
  vec_free (h->search_buckets);
  vec_free (h->key_work_space);
  vec_free (h->hash_work_space);
}

always_inline void
vhash_set_key_word (vhash_t * h, u32 wi, u32 vi, u32 value)
{
  u32 i0 = (wi << h->log2_n_key_word_len_u32x) + (vi / 4);
  u32 i1 = vi % 4;
  vec_elt (h->key_work_space, i0).as_u32[i1] = value;
}

always_inline void
vhash_set_key_word_u32x (vhash_t * h, u32 wi, u32 vi, u32x value)
{
  u32 i0 = (wi << h->log2_n_key_word_len_u32x) + (vi / 4);
  vec_elt (h->key_work_space, i0).as_u32x4 = value;
}

always_inline u32
vhash_get_key_word (vhash_t * h, u32 wi, u32 vi)
{
  u32 i0 = (wi << h->log2_n_key_word_len_u32x) + (vi / 4);
  u32 i1 = vi % 4;
  return vec_elt (h->key_work_space, i0).as_u32[i1];
}

always_inline u32x
vhash_get_key_word_u32x (vhash_t * h, u32 wi, u32 vi)
{
  u32 i0 = (wi << h->log2_n_key_word_len_u32x) + vi;
  return vec_elt (h->key_work_space, i0).as_u32x4;
}

always_inline void
vhash_validate_sizes (vhash_t * h, u32 n_key_u32, u32 n_vectors)
{
  u32 n, l;

  n = max_pow2 (n_vectors) / 4;
  n = clib_max (n, 8);

  h->log2_n_key_word_len_u32x = l = min_log2 (n);
  vec_validate_aligned (h->key_work_space, (n_key_u32 << l) - 1,
			CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (h->hash_work_space, n - 1, CLIB_CACHE_LINE_BYTES);
}

always_inline void
vhash_gather_key_stage (vhash_t * h,
			u32 vector_index,
			u32 n_vectors,
			vhash_key_function_t key_function,
			void *state, u32 n_key_u32s)
{
  u32 i, j, vi;

  /* Gather keys for 4 packets (for 128 bit vector length e.g. u32x4). */
  for (i = 0; i < n_vectors; i++)
    {
      vi = vector_index * 4 + i;
      for (j = 0; j < n_key_u32s; j++)
	vhash_set_key_word (h, j, vi, key_function (state, vi, j));
    }
}

always_inline void
vhash_gather_4key_stage (vhash_t * h,
			 u32 vector_index,
			 vhash_4key_function_t key_function,
			 void *state, u32 n_key_u32s)
{
  u32 j, vi;
  vi = vector_index * 4;
  for (j = 0; j < n_key_u32s; j++)
    vhash_set_key_word_u32x (h, j, vi, key_function (state, vi, j));
}

always_inline void
vhash_mix_stage (vhash_t * h, u32 vector_index, u32 n_key_u32s)
{
  i32 i, n_left;
  u32x a, b, c;

  /* Only need to do this for keys longer than 12 bytes. */
  ASSERT (n_key_u32s > 3);

  a = h->hash_seeds[0].as_u32x4;
  b = h->hash_seeds[1].as_u32x4;
  c = h->hash_seeds[2].as_u32x4;
  for (i = 0, n_left = n_key_u32s - 3; n_left > 0; n_left -= 3, i += 3)
    {
      a +=
	vhash_get_key_word_u32x (h, n_key_u32s - 1 - (i + 0), vector_index);
      if (n_left > 1)
	b +=
	  vhash_get_key_word_u32x (h, n_key_u32s - 1 - (i + 1), vector_index);
      if (n_left > 2)
	c +=
	  vhash_get_key_word_u32x (h, n_key_u32s - 1 - (i + 2), vector_index);

      hash_v3_mix_u32x (a, b, c);
    }

  /* Save away a, b, c for later finalize. */
  {
    vhash_hashed_key_t *hk =
      vec_elt_at_index (h->hash_work_space, vector_index);
    hk->hashed_key[0].as_u32x4 = a;
    hk->hashed_key[1].as_u32x4 = b;
    hk->hashed_key[2].as_u32x4 = c;
  }
}

always_inline vhash_search_bucket_t *
vhash_get_search_bucket_with_index (vhash_t * h, u32 i, u32 n_key_u32s)
{
  return ((vhash_search_bucket_t *)
	  vec_elt_at_index (h->search_buckets,
			    (i / 4) *
			    ((sizeof (vhash_search_bucket_t) /
			      sizeof (u32x4)) + n_key_u32s)));
}

always_inline vhash_search_bucket_t *
vhash_get_search_bucket (vhash_t * h, u32 key_hash, u32 n_key_u32s)
{
  u32 i = key_hash & h->bucket_mask.as_u32[0];
  return vhash_get_search_bucket_with_index (h, i, n_key_u32s);
}

always_inline u32x4
vhash_get_4_search_bucket_byte_offsets (vhash_t * h, u32x4 key_hash,
					u32 n_key_u32s)
{
  vhash_search_bucket_t *b;
  u32 n_bytes_per_bucket = sizeof (b[0]) + n_key_u32s * sizeof (b->key[0]);
  u32x4 r = key_hash & h->bucket_mask.as_u32x4;

  /* Multiply with shifts and adds to get bucket byte offset. */
#define _(x) u32x4_ishift_left (r, (x) - 2)
  if (n_bytes_per_bucket == (1 << 5))
    r = _(5);
  else if (n_bytes_per_bucket == ((1 << 5) + (1 << 4)))
    r = _(5) + _(4);
  else if (n_bytes_per_bucket == (1 << 6))
    r = _(6);
  else if (n_bytes_per_bucket == ((1 << 6) + (1 << 4)))
    r = _(6) + _(4);
  else if (n_bytes_per_bucket == ((1 << 6) + (1 << 5)))
    r = _(6) + _(5);
  else if (n_bytes_per_bucket == ((1 << 6) + (1 << 5) + (1 << 4)))
    r = _(6) + _(5) + _(4);
  else
    ASSERT (0);
#undef _
  return r;
}

always_inline void
vhash_finalize_stage (vhash_t * h, u32 vector_index, u32 n_key_u32s)
{
  i32 n_left;
  u32x a, b, c;
  vhash_hashed_key_t *hk =
    vec_elt_at_index (h->hash_work_space, vector_index);

  if (n_key_u32s <= 3)
    {
      a = h->hash_seeds[0].as_u32x4;
      b = h->hash_seeds[1].as_u32x4;
      c = h->hash_seeds[2].as_u32x4;
      n_left = n_key_u32s;
    }
  else
    {
      a = hk->hashed_key[0].as_u32x4;
      b = hk->hashed_key[1].as_u32x4;
      c = hk->hashed_key[2].as_u32x4;
      n_left = 3;
    }

  if (n_left > 0)
    a += vhash_get_key_word_u32x (h, 0, vector_index);
  if (n_left > 1)
    b += vhash_get_key_word_u32x (h, 1, vector_index);
  if (n_left > 2)
    c += vhash_get_key_word_u32x (h, 2, vector_index);

  hash_v3_finalize_u32x (a, b, c);

  /* Only save away last 32 bits of hash code. */
  hk->hashed_key[2].as_u32x4 = c;

  /* Prefetch buckets.  This costs a bit for small tables but saves
     big for large ones. */
  {
    vhash_search_bucket_t *b0, *b1, *b2, *b3;
    u32x4_union_t kh;

    kh.as_u32x4 = vhash_get_4_search_bucket_byte_offsets (h, c, n_key_u32s);
    hk->hashed_key[1].as_u32x4 = kh.as_u32x4;

    b0 = (void *) h->search_buckets + kh.as_u32[0];
    b1 = (void *) h->search_buckets + kh.as_u32[1];
    b2 = (void *) h->search_buckets + kh.as_u32[2];
    b3 = (void *) h->search_buckets + kh.as_u32[3];

    CLIB_PREFETCH (b0, sizeof (b0[0]) + n_key_u32s * sizeof (b0->key[0]),
		   READ);
    CLIB_PREFETCH (b1, sizeof (b1[0]) + n_key_u32s * sizeof (b1->key[0]),
		   READ);
    CLIB_PREFETCH (b2, sizeof (b2[0]) + n_key_u32s * sizeof (b2->key[0]),
		   READ);
    CLIB_PREFETCH (b3, sizeof (b3[0]) + n_key_u32s * sizeof (b3->key[0]),
		   READ);
  }
}

always_inline u32
vhash_merge_results (u32x4 r)
{
  r = r | u32x4_word_shift_right (r, 2);
  r = r | u32x4_word_shift_right (r, 1);
  return u32x4_get0 (r);
}

/* Bucket is full if none of its 4 results are 0. */
always_inline u32
vhash_search_bucket_is_full (u32x4 r)
{
  return u32x4_zero_byte_mask (r) == 0;
}

always_inline u32
vhash_non_empty_result_index (u32x4 x)
{
  u32 empty_mask = u32x4_zero_byte_mask (x);
  ASSERT (empty_mask != 0xffff);
  return min_log2 (0xffff & ~empty_mask) / 4;
}

always_inline u32
vhash_empty_result_index (u32x4 x)
{
  u32 empty_mask = u32x4_zero_byte_mask (x);
  ASSERT (empty_mask != 0);
  return min_log2 (0xffff & empty_mask) / 4;
}

always_inline u32x4
vhash_bucket_compare (vhash_t * h,
		      u32x4_union_t * bucket, u32 key_word_index, u32 vi)
{
  u32 k = vhash_get_key_word (h, key_word_index, vi);
  u32x4 x = { k, k, k, k };
  return u32x4_is_equal (bucket[key_word_index].as_u32x4, x);
}

#define vhash_bucket_compare_4(h,wi,vi,b0,b1,b2,b3,cmp0,cmp1,cmp2,cmp3)	\
do {									\
  u32x4 _k4 = vhash_get_key_word_u32x ((h), (wi), (vi));		\
  u32x4 _k0 = u32x4_splat_word (_k4, 0);				\
  u32x4 _k1 = u32x4_splat_word (_k4, 1);				\
  u32x4 _k2 = u32x4_splat_word (_k4, 2);				\
  u32x4 _k3 = u32x4_splat_word (_k4, 3);				\
									\
  cmp0 = u32x4_is_equal (b0->key[wi].as_u32x4, _k0);			\
  cmp1 = u32x4_is_equal (b1->key[wi].as_u32x4, _k1);			\
  cmp2 = u32x4_is_equal (b2->key[wi].as_u32x4, _k2);			\
  cmp3 = u32x4_is_equal (b3->key[wi].as_u32x4, _k3);			\
} while (0)

u32 vhash_get_overflow (vhash_t * h, u32 key_hash, u32 vi, u32 n_key_u32s);

always_inline void
vhash_get_stage (vhash_t * h,
		 u32 vector_index,
		 u32 n_vectors,
		 vhash_result_function_t result_function,
		 void *state, u32 n_key_u32s)
{
  u32 i, j;
  vhash_hashed_key_t *hk =
    vec_elt_at_index (h->hash_work_space, vector_index);
  vhash_search_bucket_t *b;

  for (i = 0; i < n_vectors; i++)
    {
      u32 vi = vector_index * 4 + i;
      u32 key_hash = hk->hashed_key[2].as_u32[i];
      u32 result;
      u32x4 r, r0;

      b = vhash_get_search_bucket (h, key_hash, n_key_u32s);

      r = r0 = b->result.as_u32x4;
      for (j = 0; j < n_key_u32s; j++)
	r &= vhash_bucket_compare (h, &b->key[0], j, vi);

      /* At this point only one of 4 results should be non-zero.
         So we can or all 4 together and get the valid result (if there is one). */
      result = vhash_merge_results (r);

      if (!result && vhash_search_bucket_is_full (r0))
	result = vhash_get_overflow (h, key_hash, vi, n_key_u32s);

      result_function (state, vi, result - 1, n_key_u32s);
    }
}

always_inline void
vhash_get_4_stage (vhash_t * h,
		   u32 vector_index,
		   vhash_4result_function_t result_function,
		   void *state, u32 n_key_u32s)
{
  u32 i, vi;
  vhash_hashed_key_t *hk =
    vec_elt_at_index (h->hash_work_space, vector_index);
  vhash_search_bucket_t *b0, *b1, *b2, *b3;
  u32x4 r0, r1, r2, r3, r0_before, r1_before, r2_before, r3_before;
  u32x4_union_t kh;

  kh.as_u32x4 = hk->hashed_key[1].as_u32x4;

  b0 = (void *) h->search_buckets + kh.as_u32[0];
  b1 = (void *) h->search_buckets + kh.as_u32[1];
  b2 = (void *) h->search_buckets + kh.as_u32[2];
  b3 = (void *) h->search_buckets + kh.as_u32[3];

  r0 = r0_before = b0->result.as_u32x4;
  r1 = r1_before = b1->result.as_u32x4;
  r2 = r2_before = b2->result.as_u32x4;
  r3 = r3_before = b3->result.as_u32x4;

  vi = vector_index * 4;

  for (i = 0; i < n_key_u32s; i++)
    {
      u32x4 c0, c1, c2, c3;
      vhash_bucket_compare_4 (h, i, vector_index,
			      b0, b1, b2, b3, c0, c1, c2, c3);
      r0 &= c0;
      r1 &= c1;
      r2 &= c2;
      r3 &= c3;
    }

  u32x4_transpose (r0, r1, r2, r3);

  /* Gather together 4 results. */
  {
    u32x4_union_t r;
    u32x4 ones = { 1, 1, 1, 1 };
    u32 not_found_mask;

    r.as_u32x4 = r0 | r1 | r2 | r3;
    not_found_mask = u32x4_zero_byte_mask (r.as_u32x4);
    not_found_mask &= ((vhash_search_bucket_is_full (r0_before) << (4 * 0))
		       | (vhash_search_bucket_is_full (r1_before) << (4 * 1))
		       | (vhash_search_bucket_is_full (r2_before) << (4 * 2))
		       | (vhash_search_bucket_is_full (r3_before) <<
			  (4 * 3)));
    if (not_found_mask)
      {
	u32x4_union_t key_hash;

	key_hash.as_u32x4 =
	  hk->hashed_key[2].as_u32x4 & h->bucket_mask.as_u32x4;

	/* Slow path: one of the buckets may have been full and we need to search overflow. */
	if (not_found_mask & (1 << (4 * 0)))
	  r.as_u32[0] = vhash_get_overflow (h, key_hash.as_u32[0],
					    vi + 0, n_key_u32s);
	if (not_found_mask & (1 << (4 * 1)))
	  r.as_u32[1] = vhash_get_overflow (h, key_hash.as_u32[1],
					    vi + 1, n_key_u32s);
	if (not_found_mask & (1 << (4 * 2)))
	  r.as_u32[2] = vhash_get_overflow (h, key_hash.as_u32[2],
					    vi + 2, n_key_u32s);
	if (not_found_mask & (1 << (4 * 3)))
	  r.as_u32[3] = vhash_get_overflow (h, key_hash.as_u32[3],
					    vi + 3, n_key_u32s);
      }

    result_function (state, vi, r.as_u32x4 - ones, n_key_u32s);
  }
}

u32
vhash_set_overflow (vhash_t * h,
		    u32 key_hash, u32 vi, u32 new_result, u32 n_key_u32s);

always_inline void
vhash_set_stage (vhash_t * h,
		 u32 vector_index,
		 u32 n_vectors,
		 vhash_result_function_t result_function,
		 void *state, u32 n_key_u32s)
{
  u32 i, j, n_new_elts = 0;
  vhash_hashed_key_t *hk =
    vec_elt_at_index (h->hash_work_space, vector_index);
  vhash_search_bucket_t *b;

  for (i = 0; i < n_vectors; i++)
    {
      u32 vi = vector_index * 4 + i;
      u32 key_hash = hk->hashed_key[2].as_u32[i];
      u32 old_result, new_result;
      u32 i_set;
      u32x4 r, r0, cmp;

      b = vhash_get_search_bucket (h, key_hash, n_key_u32s);

      cmp = vhash_bucket_compare (h, &b->key[0], 0, vi);
      for (j = 1; j < n_key_u32s; j++)
	cmp &= vhash_bucket_compare (h, &b->key[0], j, vi);

      r0 = b->result.as_u32x4;
      r = r0 & cmp;

      /* At this point only one of 4 results should be non-zero.
         So we can or all 4 together and get the valid result (if there is one). */
      old_result = vhash_merge_results (r);

      if (!old_result && vhash_search_bucket_is_full (r0))
	old_result = vhash_get_overflow (h, key_hash, vi, n_key_u32s);

      /* Get new result; possibly do something with old result. */
      new_result = result_function (state, vi, old_result - 1, n_key_u32s);

      /* User cannot use ~0 as a hash result since a result of 0 is
         used to mark unused bucket entries. */
      ASSERT (new_result + 1 != 0);
      new_result += 1;

      /* Set over-writes existing result. */
      if (old_result)
	{
	  i_set = vhash_non_empty_result_index (r);
	  b->result.as_u32[i_set] = new_result;
	}
      else
	{
	  /* Set allocates new result. */
	  u32 valid_mask;

	  valid_mask = (((b->result.as_u32[0] != 0) << 0)
			| ((b->result.as_u32[1] != 0) << 1)
			| ((b->result.as_u32[2] != 0) << 2)
			| ((b->result.as_u32[3] != 0) << 3));

	  /* Rotate 4 bit valid mask so that key_hash corresponds to bit 0. */
	  i_set = key_hash & 3;
	  valid_mask =
	    ((valid_mask >> i_set) | (valid_mask << (4 - i_set))) & 0xf;

	  /* Insert into first empty position in bucket after key_hash. */
	  i_set = (i_set + h->find_first_zero_table[valid_mask]) & 3;

	  if (valid_mask != 0xf)
	    {
	      n_new_elts += 1;

	      b->result.as_u32[i_set] = new_result;

	      /* Insert new key into search bucket. */
	      for (j = 0; j < n_key_u32s; j++)
		b->key[j].as_u32[i_set] = vhash_get_key_word (h, j, vi);
	    }
	  else
	    vhash_set_overflow (h, key_hash, vi, new_result, n_key_u32s);
	}
    }

  h->n_elts += n_new_elts;
}

u32 vhash_unset_overflow (vhash_t * h, u32 key_hash, u32 vi, u32 n_key_u32s);

void
vhash_unset_refill_from_overflow (vhash_t * h,
				  vhash_search_bucket_t * b,
				  u32 key_hash, u32 n_key_u32s);

/* Note: Eliot tried doing 4 unsets at once and could not get a speed up
   and abandoned vhash_unset_4_stage. */
always_inline void
vhash_unset_stage (vhash_t * h,
		   u32 vector_index,
		   u32 n_vectors,
		   vhash_result_function_t result_function,
		   void *state, u32 n_key_u32s)
{
  u32 i, j, n_elts_unset = 0;
  vhash_hashed_key_t *hk =
    vec_elt_at_index (h->hash_work_space, vector_index);
  vhash_search_bucket_t *b;

  for (i = 0; i < n_vectors; i++)
    {
      u32 vi = vector_index * 4 + i;
      u32 key_hash = hk->hashed_key[2].as_u32[i];
      u32 old_result;
      u32x4 cmp, r0;

      b = vhash_get_search_bucket (h, key_hash, n_key_u32s);

      cmp = vhash_bucket_compare (h, &b->key[0], 0, vi);
      for (j = 1; j < n_key_u32s; j++)
	cmp &= vhash_bucket_compare (h, &b->key[0], j, vi);

      r0 = b->result.as_u32x4;

      /* At this point cmp is all ones where key matches and zero otherwise.
         So, this will invalidate results for matching key and do nothing otherwise. */
      b->result.as_u32x4 = r0 & ~cmp;

      old_result = vhash_merge_results (r0 & cmp);

      n_elts_unset += old_result != 0;

      if (vhash_search_bucket_is_full (r0))
	{
	  if (old_result)
	    vhash_unset_refill_from_overflow (h, b, key_hash, n_key_u32s);
	  else
	    old_result = vhash_unset_overflow (h, key_hash, vi, n_key_u32s);
	}

      result_function (state, vi, old_result - 1, n_key_u32s);
    }
  ASSERT (h->n_elts >= n_elts_unset);
  h->n_elts -= n_elts_unset;
}

void vhash_init (vhash_t * h, u32 log2_n_keys, u32 n_key_u32,
		 u32 * hash_seeds);

void vhash_resize (vhash_t * old, u32 log2_n_keys);

typedef struct
{
  vhash_t *vhash;

  union
  {
    struct
    {
      u32 *keys;
      u32 *results;
    };

    /* Vector layout for get keys. */
    struct
    {
      u32x4_union_t *get_keys;
      u32x4_union_t *get_results;
    };
  };

  u32 n_vectors_div_4;
  u32 n_vectors_mod_4;

  u32 n_key_u32;

  u32 n_keys;
} vhash_main_t;

always_inline u32
vhash_get_alloc_keys (vhash_main_t * vm, u32 n_keys, u32 n_key_u32)
{
  u32 i, n;

  i = vm->n_keys;
  vm->n_keys = i + n_keys;

  n = (round_pow2 (vm->n_keys, 4) / 4) * n_key_u32;

  vec_validate_aligned (vm->get_keys, n - 1, sizeof (vm->get_keys[0]));
  vec_validate_aligned (vm->get_results, n - 1, sizeof (vm->get_results[0]));

  return i;
}

always_inline void
vhash_get_set_key_word (vhash_main_t * vm, u32 vi, u32 wi, u32 n_key_u32,
			u32 value)
{
  u32x4_union_t *k = vec_elt_at_index (vm->get_keys, (vi / 4) * n_key_u32);
  ASSERT (wi < n_key_u32);
  k[wi].as_u32[vi % 4] = value;
}

always_inline u32
vhash_get_fetch_result (vhash_main_t * vm, u32 vi)
{
  u32x4_union_t *r = vec_elt_at_index (vm->get_results, vi / 4);
  return r->as_u32[vi % 4];
}

void vhash_main_get (vhash_main_t * vm);

always_inline u32
vhash_set_alloc_keys (vhash_main_t * vm, u32 n_keys, u32 n_key_u32)
{
  u32 i;

  i = vm->n_keys;
  vm->n_keys = i + n_keys;

  vec_resize (vm->keys, n_keys * n_key_u32);
  vec_resize (vm->results, n_keys);

  return i;
}

always_inline void
vhash_set_set_key_word (vhash_main_t * vm, u32 vi, u32 wi, u32 n_key_u32,
			u32 value)
{
  u32 *k = vec_elt_at_index (vm->keys, vi * n_key_u32);
  ASSERT (wi < n_key_u32);
  k[wi] = value;
}

always_inline void
vhash_set_set_result (vhash_main_t * vm, u32 vi, u32 result)
{
  u32 *r = vec_elt_at_index (vm->results, vi);
  r[0] = result;
}

always_inline u32
vhash_set_fetch_old_result (vhash_main_t * vm, u32 vi)
{
  u32 *r = vec_elt_at_index (vm->results, vi);
  return r[0];
}

void vhash_main_set (vhash_main_t * vm);

always_inline u32
vhash_unset_alloc_keys (vhash_main_t * vm, u32 n_keys, u32 n_key_u32)
{
  return vhash_set_alloc_keys (vm, n_keys, n_key_u32);
}

always_inline void
vhash_unset_set_key_word (vhash_main_t * vm, u32 vi, u32 wi, u32 n_key_u32,
			  u32 value)
{
  vhash_set_set_key_word (vm, vi, wi, n_key_u32, value);
}

always_inline void
vhash_unset_set_result (vhash_main_t * vm, u32 vi, u32 result)
{
  vhash_set_set_result (vm, vi, result);
}

always_inline u32
vhash_unset_fetch_old_result (vhash_main_t * vm, u32 vi)
{
  return vhash_set_fetch_old_result (vm, vi);
}

void vhash_main_unset (vhash_main_t * vm);

typedef struct
{
  vhash_main_t new;

  vhash_t *old;
} vhash_resize_t;

u32 vhash_resize_incremental (vhash_resize_t * vr, u32 vector_index,
			      u32 n_vectors);

#endif /* CLIB_HAVE_VEC128 */

#endif /* included_clib_vhash_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
