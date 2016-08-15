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

#include <vppinfra/vhash.h>

#ifdef CLIB_HAVE_VEC128

/* Overflow search buckets have an extra u32x4 for saving key_hash data.
   This makes it easier to refill main search bucket from overflow vector. */
typedef struct
{
  /* 4 results for this bucket. */
  u32x4_union_t result;

  /* 4 hash codes for this bucket.  These are used to refill main
     search buckets from overflow buckets when space becomes available. */
  u32x4_union_t key_hash;

  /* n_key_u32s u32x4s of key data follow. */
  u32x4_union_t key[0];
} vhash_overflow_search_bucket_t;

always_inline void
set_overflow_result (vhash_overflow_search_bucket_t * b,
		     u32 i, u32 result, u32 key_hash)
{
  b->result.as_u32[i] = result;
  b->key_hash.as_u32[i] = key_hash;
}

always_inline void
free_overflow_bucket (vhash_overflow_buckets_t * ob,
		      vhash_overflow_search_bucket_t * b, u32 i)
{
  u32 o = (u32x4_union_t *) b - ob->search_buckets;
  ASSERT (o < vec_len (ob->search_buckets));
  vec_add1 (ob->free_indices, 4 * o + i);
}

always_inline vhash_overflow_search_bucket_t *
get_overflow_search_bucket (vhash_overflow_buckets_t * obs, u32 i,
			    u32 n_key_u32s)
{
  return ((vhash_overflow_search_bucket_t *)
	  vec_elt_at_index (obs->search_buckets, i));
}

always_inline vhash_overflow_search_bucket_t *
next_overflow_bucket (vhash_overflow_search_bucket_t * b, u32 n_key_u32s)
{
  return (vhash_overflow_search_bucket_t *) & b->key[n_key_u32s];
}

#define foreach_vhash_overflow_bucket(b,ob,n_key_u32s)			\
  for ((b) = (vhash_overflow_search_bucket_t *) ob->search_buckets;	\
       (u32x4_union_t *) (b) < vec_end (ob->search_buckets);		\
       b = next_overflow_bucket (b, n_key_u32s))

u32
vhash_get_overflow (vhash_t * h, u32 key_hash, u32 vi, u32 n_key_u32s)
{
  vhash_overflow_buckets_t *ob = vhash_get_overflow_buckets (h, key_hash);
  vhash_overflow_search_bucket_t *b;
  u32 i, result = 0;

  foreach_vhash_overflow_bucket (b, ob, n_key_u32s)
  {
    u32x4 r = b->result.as_u32x4;

    for (i = 0; i < n_key_u32s; i++)
      r &= vhash_bucket_compare (h, &b->key[0], i, vi);

    result = vhash_merge_results (r);
    if (result)
      break;
  }

  return result;
}

u32
vhash_set_overflow (vhash_t * h,
		    u32 key_hash, u32 vi, u32 new_result, u32 n_key_u32s)
{
  vhash_overflow_buckets_t *ob = vhash_get_overflow_buckets (h, key_hash);
  vhash_overflow_search_bucket_t *b;
  u32 i_set, i, old_result;

  foreach_vhash_overflow_bucket (b, ob, n_key_u32s)
  {
    u32x4 r;

    r = b->result.as_u32x4;
    for (i = 0; i < n_key_u32s; i++)
      r &= vhash_bucket_compare (h, &b->key[0], i, vi);

    old_result = vhash_merge_results (r);
    if (old_result)
      {
	i_set = vhash_non_empty_result_index (r);
	set_overflow_result (b, i_set, new_result, key_hash);
	return old_result;
      }
  }

  /* Check free list. */
  if (vec_len (ob->free_indices) == 0)
    {
      /* Out of free overflow buckets.  Resize. */
      u32 j, *p;
      i = vec_len (ob->search_buckets);
      vec_resize_aligned (ob->search_buckets,
			  sizeof (b[0]) / sizeof (u32x4) + n_key_u32s,
			  CLIB_CACHE_LINE_BYTES);
      vec_add2 (ob->free_indices, p, 4);
      for (j = 0; j < 4; j++)
	p[j] = 4 * i + j;
    }

  i = vec_pop (ob->free_indices);

  i_set = i & 3;
  b = ((vhash_overflow_search_bucket_t *)
       vec_elt_at_index (ob->search_buckets, i / 4));

  /* Insert result. */
  set_overflow_result (b, i_set, new_result, key_hash);

  /* Insert key. */
  for (i = 0; i < n_key_u32s; i++)
    b->key[i].as_u32[i_set] = vhash_get_key_word (h, i, vi);

  ob->n_overflow++;
  h->n_elts++;

  return /* old result was invalid */ 0;
}

u32
vhash_unset_overflow (vhash_t * h, u32 key_hash, u32 vi, u32 n_key_u32s)
{
  vhash_overflow_buckets_t *ob = vhash_get_overflow_buckets (h, key_hash);
  vhash_overflow_search_bucket_t *b;
  u32 i_set, i, old_result;

  foreach_vhash_overflow_bucket (b, ob, n_key_u32s)
  {
    u32x4 r;

    r = b->result.as_u32x4;
    for (i = 0; i < n_key_u32s; i++)
      r &= vhash_bucket_compare (h, &b->key[0], i, vi);

    old_result = vhash_merge_results (r);
    if (old_result)
      {
	i_set = vhash_non_empty_result_index (r);

	/* Invalidate result and invert key hash so that this will
	   never match since all keys in this overflow bucket have
	   matching key hashs. */
	set_overflow_result (b, i_set, 0, ~key_hash);

	free_overflow_bucket (ob, b, i_set);

	ASSERT (ob->n_overflow > 0);
	ob->n_overflow--;
	h->n_elts--;
	return old_result;
      }
  }

  /* Could not find key. */
  return 0;
}

void
vhash_unset_refill_from_overflow (vhash_t * h,
				  vhash_search_bucket_t * sb,
				  u32 key_hash, u32 n_key_u32s)
{
  vhash_overflow_buckets_t *obs = vhash_get_overflow_buckets (h, key_hash);
  vhash_overflow_search_bucket_t *ob;
  u32 i, j, i_refill, bucket_mask = h->bucket_mask.as_u32[0];

  /* Find overflow element with matching key hash. */
  foreach_vhash_overflow_bucket (ob, obs, n_key_u32s)
  {
    for (i = 0; i < 4; i++)
      {
	if (!ob->result.as_u32[i])
	  continue;
	if ((ob->key_hash.as_u32[i] & bucket_mask)
	    != (key_hash & bucket_mask))
	  continue;

	i_refill = vhash_empty_result_index (sb->result.as_u32x4);
	sb->result.as_u32[i_refill] = ob->result.as_u32[i];
	for (j = 0; j < n_key_u32s; j++)
	  sb->key[j].as_u32[i_refill] = ob->key[j].as_u32[i];
	set_overflow_result (ob, i, 0, ~key_hash);
	free_overflow_bucket (obs, ob, i);
	return;
      }
  }
}

void
vhash_init (vhash_t * h, u32 log2_n_keys, u32 n_key_u32, u32 * hash_seeds)
{
  uword i, j, m;
  vhash_search_bucket_t *b;

  memset (h, 0, sizeof (h[0]));

  /* Must have at least 4 keys (e.g. one search bucket). */
  log2_n_keys = clib_max (log2_n_keys, 2);

  h->log2_n_keys = log2_n_keys;
  h->n_key_u32 = n_key_u32;
  m = pow2_mask (h->log2_n_keys) & ~3;
  for (i = 0; i < VECTOR_WORD_TYPE_LEN (u32); i++)
    h->bucket_mask.as_u32[i] = m;

  /* Allocate and zero search buckets. */
  i = (sizeof (b[0]) / sizeof (u32x4) + n_key_u32) << (log2_n_keys - 2);
  vec_validate_aligned (h->search_buckets, i - 1, CLIB_CACHE_LINE_BYTES);

  for (i = 0; i < ARRAY_LEN (h->find_first_zero_table); i++)
    h->find_first_zero_table[i] = min_log2 (first_set (~i));

  for (i = 0; i < ARRAY_LEN (h->hash_seeds); i++)
    for (j = 0; j < VECTOR_WORD_TYPE_LEN (u32); j++)
      h->hash_seeds[i].as_u32[j] = hash_seeds[i];
}

static_always_inline u32
vhash_main_key_gather (void *_vm, u32 vi, u32 wi, u32 n_key_u32)
{
  vhash_main_t *vm = _vm;
  return vec_elt (vm->keys, vi * n_key_u32 + wi);
}

static_always_inline u32x4
vhash_main_4key_gather (void *_vm, u32 vi, u32 wi, u32 n_key_u32s)
{
  vhash_main_t *vm = _vm;
  u32x4_union_t x;

  ASSERT (n_key_u32s == vm->n_key_u32);
  ASSERT (wi < n_key_u32s);

  x.as_u32[0] = vec_elt (vm->keys, (vi + 0) * n_key_u32s + wi);
  x.as_u32[1] = vec_elt (vm->keys, (vi + 1) * n_key_u32s + wi);
  x.as_u32[2] = vec_elt (vm->keys, (vi + 2) * n_key_u32s + wi);
  x.as_u32[3] = vec_elt (vm->keys, (vi + 3) * n_key_u32s + wi);
  return x.as_u32x4;
}

static_always_inline u32
vhash_main_set_result (void *_vm, u32 vi, u32 old_result, u32 n_key_u32)
{
  vhash_main_t *vm = _vm;
  u32 *p = vec_elt_at_index (vm->results, vi);
  u32 new_result = p[0];
  p[0] = old_result;
  return new_result;
}

static_always_inline u32
vhash_main_get_result (void *_vm, u32 vi, u32 old_result, u32 n_key_u32)
{
  vhash_main_t *vm = _vm;
  vec_elt (vm->results, vi) = old_result;
  return old_result;
}

static_always_inline u32x4
vhash_main_get_4result (void *_vm, u32 vi, u32x4 old_result, u32 n_key_u32)
{
  vhash_main_t *vm = _vm;
  u32x4 *p = (u32x4 *) vec_elt_at_index (vm->results, vi);
  p[0] = old_result;
  return old_result;
}

#define _(N_KEY_U32)							\
  static_always_inline u32						\
  vhash_main_key_gather_##N_KEY_U32 (void * _vm, u32 vi, u32 i)		\
  { return vhash_main_key_gather (_vm, vi, i, N_KEY_U32); }		\
									\
  static_always_inline u32x4						\
  vhash_main_4key_gather_##N_KEY_U32 (void * _vm, u32 vi, u32 i)	\
  { return vhash_main_4key_gather (_vm, vi, i, N_KEY_U32); }		\
									\
  clib_pipeline_stage_static						\
  (vhash_main_gather_keys_stage_##N_KEY_U32,				\
   vhash_main_t *, vm, i,						\
   {									\
     vhash_gather_4key_stage						\
       (vm->vhash,							\
	/* vector_index */ i,						\
	vhash_main_4key_gather_##N_KEY_U32,				\
	vm,								\
	N_KEY_U32);							\
   })									\
									\
  clib_pipeline_stage_no_inline						\
  (vhash_main_gather_keys_mod_stage_##N_KEY_U32,			\
   vhash_main_t *, vm, i,						\
   {									\
     vhash_gather_key_stage						\
       (vm->vhash,							\
	/* vector_index */ vm->n_vectors_div_4,				\
	/* n_vectors */ vm->n_vectors_mod_4,				\
	vhash_main_key_gather_##N_KEY_U32,				\
	vm,								\
	N_KEY_U32);							\
   })									\
									\
  clib_pipeline_stage							\
  (vhash_main_hash_finalize_stage_##N_KEY_U32,				\
   vhash_main_t *, vm, i,						\
   {									\
     vhash_finalize_stage (vm->vhash, i, N_KEY_U32);			\
   })									\
									\
  clib_pipeline_stage_no_inline						\
  (vhash_main_hash_finalize_mod_stage_##N_KEY_U32,			\
   vhash_main_t *, vm, i,						\
   {									\
     vhash_finalize_stage (vm->vhash, vm->n_vectors_div_4, N_KEY_U32);	\
   })									\
									\
  clib_pipeline_stage_static						\
  (vhash_main_get_stage_##N_KEY_U32,					\
   vhash_main_t *, vm, i,						\
   {									\
     vhash_get_4_stage (vm->vhash,					\
			/* vector_index */ i,				\
			vhash_main_get_4result,				\
			vm, N_KEY_U32);					\
   })									\
									\
  clib_pipeline_stage_no_inline						\
  (vhash_main_get_mod_stage_##N_KEY_U32,				\
   vhash_main_t *, vm, i,						\
   {									\
     vhash_get_stage (vm->vhash,					\
		      /* vector_index */ vm->n_vectors_div_4,		\
		      /* n_vectors */ vm->n_vectors_mod_4,		\
		      vhash_main_get_result,				\
		      vm, N_KEY_U32);					\
   })									\
									\
  clib_pipeline_stage_static						\
  (vhash_main_set_stage_##N_KEY_U32,					\
   vhash_main_t *, vm, i,						\
   {									\
     vhash_set_stage (vm->vhash,					\
		      /* vector_index */ i,				\
		      /* n_vectors */ VECTOR_WORD_TYPE_LEN (u32),	\
		      vhash_main_set_result,				\
		      vm, N_KEY_U32);					\
   })									\
									\
  clib_pipeline_stage_no_inline						\
  (vhash_main_set_mod_stage_##N_KEY_U32,				\
   vhash_main_t *, vm, i,						\
   {									\
     vhash_set_stage (vm->vhash,					\
		      /* vector_index */ vm->n_vectors_div_4,		\
		      /* n_vectors */ vm->n_vectors_mod_4,		\
		      vhash_main_set_result,				\
		      vm, N_KEY_U32);					\
   })									\
									\
  clib_pipeline_stage_static						\
  (vhash_main_unset_stage_##N_KEY_U32,					\
   vhash_main_t *, vm, i,						\
   {									\
     vhash_unset_stage (vm->vhash,					\
		      /* vector_index */ i,				\
		      /* n_vectors */ VECTOR_WORD_TYPE_LEN (u32),	\
		      vhash_main_get_result,				\
		      vm, N_KEY_U32);					\
   })									\
									\
  clib_pipeline_stage_no_inline						\
  (vhash_main_unset_mod_stage_##N_KEY_U32,				\
   vhash_main_t *, vm, i,						\
   {									\
     vhash_unset_stage (vm->vhash,					\
		      /* vector_index */ vm->n_vectors_div_4,		\
		      /* n_vectors */ vm->n_vectors_mod_4,		\
		      vhash_main_get_result,				\
		      vm, N_KEY_U32);					\
   })

_(1);
_(2);
_(3);
_(4);
_(5);
_(6);

#undef _

#define _(N_KEY_U32)							\
  clib_pipeline_stage							\
  (vhash_main_hash_mix_stage_##N_KEY_U32,				\
   vhash_main_t *, vm, i,						\
   {									\
     vhash_mix_stage (vm->vhash, i, N_KEY_U32);				\
   })									\
									\
  clib_pipeline_stage_no_inline						\
  (vhash_main_hash_mix_mod_stage_##N_KEY_U32,				\
   vhash_main_t *, vm, i,						\
   {									\
     vhash_mix_stage (vm->vhash, vm->n_vectors_div_4, N_KEY_U32);	\
   })

_(4);
_(5);
_(6);

#undef _

typedef enum
{
  GET, SET, UNSET,
} vhash_main_op_t;

static void
vhash_main_op (vhash_main_t * vm, vhash_main_op_t op)
{
  u32 n_keys = vec_len (vm->results);

  vm->n_key_u32 = vm->vhash->n_key_u32;

  vhash_validate_sizes (vm->vhash, vm->n_key_u32, n_keys);

  vm->n_vectors_div_4 = n_keys / 4;
  vm->n_vectors_mod_4 = n_keys % 4;

  if (vm->n_vectors_div_4 > 0)
    {
      switch (vm->n_key_u32)
	{
	default:
	  ASSERT (0);
	  break;

#define _(N_KEY_U32)						\
	case N_KEY_U32:						\
	  if (op == GET)					\
	    clib_pipeline_run_3_stage				\
	      (vm->n_vectors_div_4,				\
	       vm,						\
	       vhash_main_gather_keys_stage_##N_KEY_U32,	\
	       vhash_main_hash_finalize_stage_##N_KEY_U32,	\
	       vhash_main_get_stage_##N_KEY_U32);		\
	  else if (op == SET)					\
	    clib_pipeline_run_3_stage				\
	      (vm->n_vectors_div_4,				\
	       vm,						\
	       vhash_main_gather_keys_stage_##N_KEY_U32,	\
	       vhash_main_hash_finalize_stage_##N_KEY_U32,	\
	       vhash_main_set_stage_##N_KEY_U32);		\
	  else							\
	    clib_pipeline_run_3_stage				\
	      (vm->n_vectors_div_4,				\
	       vm,						\
	       vhash_main_gather_keys_stage_##N_KEY_U32,	\
	       vhash_main_hash_finalize_stage_##N_KEY_U32,	\
	       vhash_main_unset_stage_##N_KEY_U32);		\
	  break;

	  _(1);
	  _(2);
	  _(3);

#undef _

#define _(N_KEY_U32)						\
	case N_KEY_U32:						\
	  if (op == GET)					\
	    clib_pipeline_run_4_stage				\
	      (vm->n_vectors_div_4,				\
	       vm,						\
	       vhash_main_gather_keys_stage_##N_KEY_U32,	\
	       vhash_main_hash_mix_stage_##N_KEY_U32,		\
	       vhash_main_hash_finalize_stage_##N_KEY_U32,	\
	       vhash_main_get_stage_##N_KEY_U32);		\
	  else if (op == SET)					\
	    clib_pipeline_run_4_stage				\
	      (vm->n_vectors_div_4,				\
	       vm,						\
	       vhash_main_gather_keys_stage_##N_KEY_U32,	\
	       vhash_main_hash_mix_stage_##N_KEY_U32,		\
	       vhash_main_hash_finalize_stage_##N_KEY_U32,	\
	       vhash_main_set_stage_##N_KEY_U32);		\
	  else							\
	    clib_pipeline_run_4_stage				\
	      (vm->n_vectors_div_4,				\
	       vm,						\
	       vhash_main_gather_keys_stage_##N_KEY_U32,	\
	       vhash_main_hash_mix_stage_##N_KEY_U32,		\
	       vhash_main_hash_finalize_stage_##N_KEY_U32,	\
	       vhash_main_unset_stage_##N_KEY_U32);		\
	  break;

	  _(4);
	  _(5);
	  _(6);

#undef _
	}
    }


  if (vm->n_vectors_mod_4 > 0)
    {
      switch (vm->n_key_u32)
	{
	default:
	  ASSERT (0);
	  break;

#define _(N_KEY_U32)						\
	case N_KEY_U32:						\
	  if (op == GET)					\
	    clib_pipeline_run_3_stage				\
	      (1,						\
	       vm,						\
	       vhash_main_gather_keys_mod_stage_##N_KEY_U32,	\
	       vhash_main_hash_finalize_mod_stage_##N_KEY_U32,	\
	       vhash_main_get_mod_stage_##N_KEY_U32);		\
	  else if (op == SET)					\
	    clib_pipeline_run_3_stage				\
	      (1,						\
	       vm,						\
	       vhash_main_gather_keys_mod_stage_##N_KEY_U32,	\
	       vhash_main_hash_finalize_mod_stage_##N_KEY_U32,	\
	       vhash_main_set_mod_stage_##N_KEY_U32);		\
	  else							\
	    clib_pipeline_run_3_stage				\
	      (1,						\
	       vm,						\
	       vhash_main_gather_keys_mod_stage_##N_KEY_U32,	\
	       vhash_main_hash_finalize_mod_stage_##N_KEY_U32,	\
	       vhash_main_unset_mod_stage_##N_KEY_U32);		\
	break;

	  _(1);
	  _(2);
	  _(3);

#undef _

#define _(N_KEY_U32)						\
	case N_KEY_U32:						\
	  if (op == GET)					\
	    clib_pipeline_run_4_stage				\
	      (1,						\
	       vm,						\
	       vhash_main_gather_keys_mod_stage_##N_KEY_U32,	\
	       vhash_main_hash_mix_mod_stage_##N_KEY_U32,	\
	       vhash_main_hash_finalize_mod_stage_##N_KEY_U32,	\
	       vhash_main_get_mod_stage_##N_KEY_U32);		\
	  else if (op == SET)					\
	    clib_pipeline_run_4_stage				\
	      (1,						\
	       vm,						\
	       vhash_main_gather_keys_mod_stage_##N_KEY_U32,	\
	       vhash_main_hash_mix_mod_stage_##N_KEY_U32,	\
	       vhash_main_hash_finalize_mod_stage_##N_KEY_U32,	\
	       vhash_main_set_mod_stage_##N_KEY_U32);		\
	  else							\
	    clib_pipeline_run_4_stage				\
	      (1,						\
	       vm,						\
	       vhash_main_gather_keys_mod_stage_##N_KEY_U32,	\
	       vhash_main_hash_mix_mod_stage_##N_KEY_U32,	\
	       vhash_main_hash_finalize_mod_stage_##N_KEY_U32,	\
	       vhash_main_unset_mod_stage_##N_KEY_U32);		\
	  break;

	  _(4);
	  _(5);
	  _(6);

#undef _
	}
    }
}

void
vhash_main_get (vhash_main_t * vm)
{
  vhash_main_op (vm, GET);
}

void
vhash_main_set (vhash_main_t * vm)
{
  vhash_main_op (vm, SET);
}

void
vhash_main_unset (vhash_main_t * vm)
{
  vhash_main_op (vm, UNSET);
}

u32
vhash_resize_incremental (vhash_resize_t * vr, u32 vector_index,
			  u32 n_keys_this_call)
{
  vhash_t *old = vr->old;
  vhash_main_t *vm = &vr->new;
  vhash_t *new = vm->vhash;
  uword i, j, n_key_u32;

  n_key_u32 = old->n_key_u32;

  if (vector_index == 0)
    {
      u32 hash_seeds[3];
      hash_seeds[0] = old->hash_seeds[0].as_u32[0];
      hash_seeds[1] = old->hash_seeds[1].as_u32[0];
      hash_seeds[2] = old->hash_seeds[2].as_u32[0];
      vhash_init (new, old->log2_n_keys + 1, n_key_u32, hash_seeds);
    }

  vec_reset_length (vm->keys);
  vec_reset_length (vm->results);

  if (0 == (vector_index >> old->log2_n_keys))
    {
      for (i = vector_index; 0 == (i >> (old->log2_n_keys - 2)); i++)
	{
	  vhash_search_bucket_t *b =
	    vhash_get_search_bucket_with_index (old, 4 * i, n_key_u32);
	  u32 r, *k;

#define _(I)					\
  if ((r = b->result.as_u32[I]) != 0)		\
    {						\
      vec_add1 (vm->results, r - 1);		\
      vec_add2 (vm->keys, k, n_key_u32);	\
      for (j = 0; j < n_key_u32; j++)		\
	k[j] = b->key[j].as_u32[I];		\
    }

	  _(0);
	  _(1);
	  _(2);
	  _(3);

#undef _

	  if (vec_len (vm->results) >= n_keys_this_call)
	    {
	      vhash_main_op (vm, SET);
	      return i;
	    }
	}
    }

  /* Add overflow buckets. */
  {
    vhash_overflow_buckets_t *ob;
    vhash_overflow_search_bucket_t *b;

    for (ob = old->overflow_buckets;
	 ob < old->overflow_buckets + ARRAY_LEN (old->overflow_buckets); ob++)
      {
	foreach_vhash_overflow_bucket (b, ob, old->n_key_u32)
	{
	  u32 r, *k;

#define _(I)					\
  if ((r = b->result.as_u32[I]) != 0)		\
    {						\
      vec_add1 (vm->results, r - 1);		\
      vec_add2 (vm->keys, k, n_key_u32);	\
      for (j = 0; j < n_key_u32; j++)		\
	k[j] = b->key[j].as_u32[I];		\
    }

	  _(0);
	  _(1);
	  _(2);
	  _(3);

#undef _
	}
      }
  }

  vhash_main_op (vm, SET);

  /* Let caller know we are done. */
  return ~0;
}

void
vhash_resize (vhash_t * old, u32 log2_n_keys)
{
  static vhash_resize_t vr;
  vhash_t new;
  u32 i = 0;

  vr.old = old;
  vr.new.vhash = &new;

  while (1)
    {
      i = vhash_resize_incremental (&vr, i, 1024);
      if (i == ~0)
	break;
    }

  vhash_free (old);
  *old = new;
}

#endif /* CLIB_HAVE_VEC128 */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
