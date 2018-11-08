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

#if 0
#ifdef __OPTIMIZE__
#undef CLIB_DEBUG
#endif
#endif

#include <vppinfra/bitmap.h>
#include <vppinfra/error.h>
#include <vppinfra/os.h>
#include <vppinfra/random.h>
#include <vppinfra/time.h>
#include <vppinfra/vhash.h>

#ifdef CLIB_HAVE_VEC128

typedef struct
{
  u32 n_iter;
  u32 seed;
  u32 verbose;
  u32 n_keys;
  u32 log2_size;
  u32 n_key_u32;

  u32 n_vectors_div_4;
  u32 n_vectors_mod_4;

  u32 *keys;
  u32 *results;

  u32 *vhash_get_key_indices;
  u32 *vhash_get_results;

  u32 *vhash_key_indices;
  u32 *vhash_results;

  vhash_t vhash;

  uword **key_hash;

  struct
  {
    u64 n_clocks;
    u64 n_vectors;
    u64 n_calls;
  } get_stats, set_stats, unset_stats;
} test_vhash_main_t;

always_inline u32
test_vhash_key_gather (void *_tm, u32 vi, u32 wi, u32 n_key_u32s)
{
  test_vhash_main_t *tm = _tm;
  ASSERT (n_key_u32s == tm->n_key_u32);
  ASSERT (wi < n_key_u32s);
  vi = vec_elt (tm->vhash_key_indices, vi);
  return vec_elt (tm->keys, vi * n_key_u32s + wi);
}

always_inline u32x4
test_vhash_4key_gather (void *_tm, u32 vi, u32 wi, u32 n_key_u32s)
{
  test_vhash_main_t *tm = _tm;
  u32 *p;
  u32x4_union_t x;

  ASSERT (n_key_u32s == tm->n_key_u32);
  ASSERT (wi < n_key_u32s);

  p = vec_elt_at_index (tm->vhash_key_indices, vi + 0);
  x.as_u32[0] = tm->keys[p[0] * n_key_u32s + wi];
  x.as_u32[1] = tm->keys[p[1] * n_key_u32s + wi];
  x.as_u32[2] = tm->keys[p[2] * n_key_u32s + wi];
  x.as_u32[3] = tm->keys[p[3] * n_key_u32s + wi];
  return x.as_u32x4;
}

always_inline u32
test_vhash_get_result (void *_tm,
		       u32 vector_index, u32 result_index, u32 n_key_u32s)
{
  test_vhash_main_t *tm = _tm;
  u32 *p = vec_elt_at_index (tm->vhash_results, vector_index);
  p[0] = result_index;
  return result_index;
}

always_inline u32x4
test_vhash_get_4result (void *_tm,
			u32 vector_index, u32x4 results, u32 n_key_u32s)
{
  test_vhash_main_t *tm = _tm;
  u32 *p = vec_elt_at_index (tm->vhash_results, vector_index);
  *(u32x4 *) p = results;
  return results;
}

always_inline u32
test_vhash_set_result (void *_tm,
		       u32 vector_index, u32 old_result, u32 n_key_u32s)
{
  test_vhash_main_t *tm = _tm;
  u32 *p = vec_elt_at_index (tm->vhash_results, vector_index);
  u32 new_result = p[0];
  p[0] = old_result;
  return new_result;
}

always_inline u32
test_vhash_unset_result (void *_tm, u32 i, u32 old_result, u32 n_key_u32s)
{
  test_vhash_main_t *tm = _tm;
  u32 *p = vec_elt_at_index (tm->vhash_results, i);
  p[0] = old_result;
  return 0;
}

#define _(N_KEY_U32)							\
  always_inline u32							\
  test_vhash_key_gather_##N_KEY_U32 (void * _tm, u32 vi, u32 i)		\
  { return test_vhash_key_gather (_tm, vi, i, N_KEY_U32); }		\
									\
  always_inline u32x4							\
  test_vhash_key_gather_4_##N_KEY_U32 (void * _tm, u32 vi, u32 i)	\
  {  return test_vhash_4key_gather (_tm, vi, i, N_KEY_U32); }		\
									\
  clib_pipeline_stage							\
  (test_vhash_gather_keys_stage_##N_KEY_U32,				\
   test_vhash_main_t *, tm, i,						\
   {									\
     vhash_gather_4key_stage						\
       (&tm->vhash,							\
	/* vector_index */ i,						\
	test_vhash_key_gather_4_##N_KEY_U32,				\
	tm,								\
	N_KEY_U32);							\
   })									\
									\
  clib_pipeline_stage_no_inline						\
  (test_vhash_gather_keys_mod_stage_##N_KEY_U32,			\
   test_vhash_main_t *, tm, i,						\
   {									\
     vhash_gather_key_stage						\
       (&tm->vhash,							\
	/* vector_index */ tm->n_vectors_div_4,				\
	/* n_vectors */ tm->n_vectors_mod_4,				\
	test_vhash_key_gather_##N_KEY_U32,				\
	tm,								\
	N_KEY_U32);							\
   })									\
									\
  clib_pipeline_stage							\
  (test_vhash_hash_finalize_stage_##N_KEY_U32,				\
   test_vhash_main_t *, tm, i,						\
   {									\
     vhash_finalize_stage (&tm->vhash, i, N_KEY_U32);			\
   })									\
									\
  clib_pipeline_stage_no_inline						\
  (test_vhash_hash_finalize_mod_stage_##N_KEY_U32,			\
   test_vhash_main_t *, tm, i,						\
   {									\
     vhash_finalize_stage (&tm->vhash, tm->n_vectors_div_4, N_KEY_U32);	\
   })									\
									\
  clib_pipeline_stage							\
  (test_vhash_get_stage_##N_KEY_U32,					\
   test_vhash_main_t *, tm, i,						\
   {									\
     vhash_get_4_stage (&tm->vhash,					\
			/* vector_index */ i,				\
			test_vhash_get_4result,				\
			tm, N_KEY_U32);					\
   })									\
									\
  clib_pipeline_stage_no_inline						\
  (test_vhash_get_mod_stage_##N_KEY_U32,				\
   test_vhash_main_t *, tm, i,						\
   {									\
     vhash_get_stage (&tm->vhash,					\
		      /* vector_index */ tm->n_vectors_div_4,		\
		      /* n_vectors */ tm->n_vectors_mod_4,		\
		      test_vhash_get_result,				\
		      tm, N_KEY_U32);					\
   })									\
									\
  clib_pipeline_stage							\
  (test_vhash_set_stage_##N_KEY_U32,					\
   test_vhash_main_t *, tm, i,						\
   {									\
     vhash_set_stage (&tm->vhash,					\
		      /* vector_index */ i,				\
		      /* n_vectors */ VECTOR_WORD_TYPE_LEN (u32),	\
		      test_vhash_set_result,				\
		      tm, N_KEY_U32);					\
   })									\
									\
  clib_pipeline_stage_no_inline						\
  (test_vhash_set_mod_stage_##N_KEY_U32,				\
   test_vhash_main_t *, tm, i,						\
   {									\
     vhash_set_stage (&tm->vhash,					\
		      /* vector_index */ tm->n_vectors_div_4,		\
		      /* n_vectors */ tm->n_vectors_mod_4,		\
		      test_vhash_set_result,				\
		      tm, N_KEY_U32);					\
   })									\
									\
  clib_pipeline_stage							\
  (test_vhash_unset_stage_##N_KEY_U32,					\
   test_vhash_main_t *, tm, i,						\
   {									\
     vhash_unset_stage (&tm->vhash,					\
			/* vector_index */ i,				\
			/* n_vectors */ VECTOR_WORD_TYPE_LEN (u32),	\
			test_vhash_unset_result,			\
			tm, N_KEY_U32);					\
   })									\
									\
  clib_pipeline_stage_no_inline						\
  (test_vhash_unset_mod_stage_##N_KEY_U32,				\
   test_vhash_main_t *, tm, i,						\
   {									\
     vhash_unset_stage (&tm->vhash,					\
			/* vector_index */ tm->n_vectors_div_4,		\
			/* n_vectors */ tm->n_vectors_mod_4,		\
			test_vhash_unset_result,			\
			tm, N_KEY_U32);					\
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
  (test_vhash_hash_mix_stage_##N_KEY_U32,				\
   test_vhash_main_t *, tm, i,						\
   {									\
     vhash_mix_stage (&tm->vhash, i, N_KEY_U32);			\
   })									\
									\
  clib_pipeline_stage_no_inline						\
  (test_vhash_hash_mix_mod_stage_##N_KEY_U32,				\
   test_vhash_main_t *, tm, i,						\
   {									\
     vhash_mix_stage (&tm->vhash, tm->n_vectors_div_4, N_KEY_U32);	\
   })

_(4);
_(5);
_(6);

#undef _

typedef enum
{
  GET, SET, UNSET,
} test_vhash_op_t;

static void
test_vhash_op (test_vhash_main_t * tm,
	       u32 * key_indices,
	       u32 * results, uword n_keys, test_vhash_op_t op)
{
  vhash_validate_sizes (&tm->vhash, tm->n_key_u32, n_keys);

  tm->vhash_results = results;
  tm->vhash_key_indices = key_indices;
  tm->n_vectors_div_4 = n_keys / 4;
  tm->n_vectors_mod_4 = n_keys % 4;

  if (tm->n_vectors_div_4 > 0)
    {
      switch (tm->n_key_u32)
	{
	default:
	  ASSERT (0);
	  break;

#define _(N_KEY_U32)						\
	case N_KEY_U32:						\
	  if (op == GET)					\
	    clib_pipeline_run_3_stage				\
	      (tm->n_vectors_div_4,				\
	       tm,						\
	       test_vhash_gather_keys_stage_##N_KEY_U32,	\
	       test_vhash_hash_finalize_stage_##N_KEY_U32,	\
	       test_vhash_get_stage_##N_KEY_U32);		\
	  else if (op == SET)					\
	    clib_pipeline_run_3_stage				\
	      (tm->n_vectors_div_4,				\
	       tm,						\
	       test_vhash_gather_keys_stage_##N_KEY_U32,	\
	       test_vhash_hash_finalize_stage_##N_KEY_U32,	\
	       test_vhash_set_stage_##N_KEY_U32);		\
	  else							\
	    clib_pipeline_run_3_stage				\
	      (tm->n_vectors_div_4,				\
	       tm,						\
	       test_vhash_gather_keys_stage_##N_KEY_U32,	\
	       test_vhash_hash_finalize_stage_##N_KEY_U32,	\
	       test_vhash_unset_stage_##N_KEY_U32);		\
	  break;

	  _(1);
	  _(2);
	  _(3);

#undef _

#define _(N_KEY_U32)						\
	case N_KEY_U32:						\
	  if (op == GET)					\
	    clib_pipeline_run_4_stage				\
	      (tm->n_vectors_div_4,				\
	       tm,						\
	       test_vhash_gather_keys_stage_##N_KEY_U32,	\
	       test_vhash_hash_mix_stage_##N_KEY_U32,		\
	       test_vhash_hash_finalize_stage_##N_KEY_U32,	\
	       test_vhash_get_stage_##N_KEY_U32);		\
	  else if (op == SET)					\
	    clib_pipeline_run_4_stage				\
	      (tm->n_vectors_div_4,				\
	       tm,						\
	       test_vhash_gather_keys_stage_##N_KEY_U32,	\
	       test_vhash_hash_mix_stage_##N_KEY_U32,		\
	       test_vhash_hash_finalize_stage_##N_KEY_U32,	\
	       test_vhash_set_stage_##N_KEY_U32);		\
	  else							\
	    clib_pipeline_run_4_stage				\
	      (tm->n_vectors_div_4,				\
	       tm,						\
	       test_vhash_gather_keys_stage_##N_KEY_U32,	\
	       test_vhash_hash_mix_stage_##N_KEY_U32,		\
	       test_vhash_hash_finalize_stage_##N_KEY_U32,	\
	       test_vhash_unset_stage_##N_KEY_U32);		\
	  break;

	  _(4);
	  _(5);
	  _(6);

#undef _
	}
    }


  if (tm->n_vectors_mod_4 > 0)
    {
      switch (tm->n_key_u32)
	{
	default:
	  ASSERT (0);
	  break;

#define _(N_KEY_U32)						\
	case N_KEY_U32:						\
	  if (op == GET)					\
	    clib_pipeline_run_3_stage				\
	      (1,						\
	       tm,						\
	       test_vhash_gather_keys_mod_stage_##N_KEY_U32,	\
	       test_vhash_hash_finalize_mod_stage_##N_KEY_U32,	\
	       test_vhash_get_mod_stage_##N_KEY_U32);		\
	  else if (op == SET)					\
	    clib_pipeline_run_3_stage				\
	      (1,						\
	       tm,						\
	       test_vhash_gather_keys_mod_stage_##N_KEY_U32,	\
	       test_vhash_hash_finalize_mod_stage_##N_KEY_U32,	\
	       test_vhash_set_mod_stage_##N_KEY_U32);		\
	  else							\
	    clib_pipeline_run_3_stage				\
	      (1,						\
	       tm,						\
	       test_vhash_gather_keys_mod_stage_##N_KEY_U32,	\
	       test_vhash_hash_finalize_mod_stage_##N_KEY_U32,	\
	       test_vhash_unset_mod_stage_##N_KEY_U32);		\
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
	       tm,						\
	       test_vhash_gather_keys_mod_stage_##N_KEY_U32,	\
	       test_vhash_hash_mix_mod_stage_##N_KEY_U32,	\
	       test_vhash_hash_finalize_mod_stage_##N_KEY_U32,	\
	       test_vhash_get_mod_stage_##N_KEY_U32);		\
	  else if (op == SET)					\
	    clib_pipeline_run_4_stage				\
	      (1,						\
	       tm,						\
	       test_vhash_gather_keys_mod_stage_##N_KEY_U32,	\
	       test_vhash_hash_mix_mod_stage_##N_KEY_U32,	\
	       test_vhash_hash_finalize_mod_stage_##N_KEY_U32,	\
	       test_vhash_set_mod_stage_##N_KEY_U32);		\
	  else							\
	    clib_pipeline_run_4_stage				\
	      (1,						\
	       tm,						\
	       test_vhash_gather_keys_mod_stage_##N_KEY_U32,	\
	       test_vhash_hash_mix_mod_stage_##N_KEY_U32,	\
	       test_vhash_hash_finalize_mod_stage_##N_KEY_U32,	\
	       test_vhash_unset_mod_stage_##N_KEY_U32);		\
	  break;

	  _(4);
	  _(5);
	  _(6);

#undef _
	}
    }
}

int
test_vhash_main (unformat_input_t * input)
{
  clib_error_t *error = 0;
  test_vhash_main_t _tm, *tm = &_tm;
  vhash_t *vh = &tm->vhash;
  uword i, j;

  memset (tm, 0, sizeof (tm[0]));
  tm->n_iter = 100;
  tm->seed = 1;
  tm->n_keys = 1;
  tm->n_key_u32 = 1;
  tm->log2_size = 8;
  tm->verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "iter %d", &tm->n_iter))
	;
      else if (unformat (input, "seed %d", &tm->seed))
	;
      else if (unformat (input, "n-keys %d", &tm->n_keys))
	;
      else if (unformat (input, "log2-size %d", &tm->log2_size))
	;
      else if (unformat (input, "key-words %d", &tm->n_key_u32))
	;
      else if (unformat (input, "verbose %=", &tm->verbose, 1))
	;
      else
	{
	  error = clib_error_create ("unknown input `%U'\n",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (tm->seed == 0)
    tm->seed = random_default_seed ();

  clib_warning ("iter %d seed %d n-keys %d log2-size %d key-words %d",
		tm->n_iter, tm->seed, tm->n_keys, tm->log2_size,
		tm->n_key_u32);

  {
    u32 seeds[3];
    seeds[0] = seeds[1] = seeds[2] = 0xdeadbeef;
    vhash_init (vh, tm->log2_size, tm->n_key_u32, seeds);
  }

  /* Choose unique keys. */
  vec_resize (tm->keys, tm->n_keys * tm->n_key_u32);
  vec_resize (tm->key_hash, tm->n_key_u32);
  for (i = j = 0; i < vec_len (tm->keys); i++, j++)
    {
      j = j == tm->n_key_u32 ? 0 : j;
      do
	{
	  tm->keys[i] = random_u32 (&tm->seed);
	}
      while (hash_get (tm->key_hash[j], tm->keys[i]));
      hash_set (tm->key_hash[j], tm->keys[i], 0);
    }

  vec_resize (tm->results, tm->n_keys);
  for (i = 0; i < vec_len (tm->results); i++)
    {
      do
	{
	  tm->results[i] = random_u32 (&tm->seed);
	}
      while (tm->results[i] == ~0);
    }

  vec_resize_aligned (tm->vhash_get_results, tm->n_keys,
		      CLIB_CACHE_LINE_BYTES);
  vec_clone (tm->vhash_get_key_indices, tm->results);
  for (i = 0; i < vec_len (tm->vhash_get_key_indices); i++)
    tm->vhash_get_key_indices[i] = i;

  {
    uword *is_set_bitmap = 0;
    uword *to_set_bitmap = 0;
    uword *to_unset_bitmap = 0;
    u32 *to_set = 0, *to_unset = 0;
    u32 *to_set_results = 0, *to_unset_results = 0;
    u64 t[2];

    for (i = 0; i < tm->n_iter; i++)
      {
	vec_reset_length (to_set);
	vec_reset_length (to_unset);
	vec_reset_length (to_set_results);
	vec_reset_length (to_unset_results);

	do
	  {
	    to_set_bitmap = clib_bitmap_random (to_set_bitmap,
						tm->n_keys, &tm->seed);
	  }
	while (clib_bitmap_is_zero (to_set_bitmap));
	to_unset_bitmap = clib_bitmap_dup_and (to_set_bitmap, is_set_bitmap);
	to_set_bitmap = clib_bitmap_andnot (to_set_bitmap, to_unset_bitmap);

	/* *INDENT-OFF* */
	clib_bitmap_foreach (j, to_set_bitmap, ({
	      vec_add1 (to_set, j);
	      vec_add1 (to_set_results, tm->results[j]);
	}));
	/* *INDENT-ON* */
	/* *INDENT-OFF* */
	clib_bitmap_foreach (j, to_unset_bitmap, ({
	      vec_add1 (to_unset, j);
	      vec_add1 (to_unset_results, 0xdeadbeef);
	}));
	/* *INDENT-ON* */

	if (vec_len (to_set) > 0)
	  {
	    t[0] = clib_cpu_time_now ();
	    test_vhash_op (tm, to_set, to_set_results, vec_len (to_set), SET);
	    t[1] = clib_cpu_time_now ();
	    tm->set_stats.n_clocks += t[1] - t[0];
	    tm->set_stats.n_vectors += vec_len (to_set);
	    tm->set_stats.n_calls += 1;
	    is_set_bitmap = clib_bitmap_or (is_set_bitmap, to_set_bitmap);
	  }

	t[0] = clib_cpu_time_now ();
	test_vhash_op (tm, tm->vhash_get_key_indices,
		       tm->vhash_get_results,
		       vec_len (tm->vhash_get_key_indices), GET);
	t[1] = clib_cpu_time_now ();
	tm->get_stats.n_clocks += t[1] - t[0];
	tm->get_stats.n_vectors += vec_len (tm->vhash_get_key_indices);
	tm->get_stats.n_calls += 1;

	for (j = 0; j < vec_len (tm->vhash_get_results); j++)
	  {
	    u32 r0 = tm->vhash_get_results[j];
	    u32 r1 = tm->results[j];
	    if (clib_bitmap_get (is_set_bitmap, j))
	      {
		if (r0 != r1)
		  os_panic ();
	      }
	    else
	      {
		if (r0 != ~0)
		  os_panic ();
	      }
	  }

	if (vh->n_elts != clib_bitmap_count_set_bits (is_set_bitmap))
	  os_panic ();

	if (vec_len (to_unset) > 0)
	  {
	    t[0] = clib_cpu_time_now ();
	    test_vhash_op (tm, to_unset, to_unset_results,
			   vec_len (to_unset), UNSET);
	    t[1] = clib_cpu_time_now ();
	    tm->unset_stats.n_clocks += t[1] - t[0];
	    tm->unset_stats.n_vectors += vec_len (to_unset);
	    tm->unset_stats.n_calls += 1;
	    is_set_bitmap =
	      clib_bitmap_andnot (is_set_bitmap, to_unset_bitmap);
	  }

	t[0] = clib_cpu_time_now ();
	test_vhash_op (tm, tm->vhash_get_key_indices,
		       tm->vhash_get_results,
		       vec_len (tm->vhash_get_key_indices), GET);
	t[1] = clib_cpu_time_now ();
	tm->get_stats.n_clocks += t[1] - t[0];
	tm->get_stats.n_vectors += vec_len (tm->vhash_get_key_indices);
	tm->get_stats.n_calls += 1;

	for (j = 0; j < vec_len (tm->vhash_get_results); j++)
	  {
	    u32 r0 = tm->vhash_get_results[j];
	    u32 r1 = tm->results[j];
	    if (clib_bitmap_get (is_set_bitmap, j))
	      {
		if (r0 != r1)
		  os_panic ();
	      }
	    else
	      {
		if (r0 != ~0)
		  os_panic ();
	      }
	  }

	if (vh->n_elts != clib_bitmap_count_set_bits (is_set_bitmap))
	  os_panic ();
      }

    vhash_resize (vh, tm->log2_size + 1);

    test_vhash_op (tm, tm->vhash_get_key_indices,
		   tm->vhash_get_results,
		   vec_len (tm->vhash_get_key_indices), GET);

    for (j = 0; j < vec_len (tm->vhash_get_results); j++)
      {
	u32 r0 = tm->vhash_get_results[j];
	u32 r1 = tm->results[j];
	if (clib_bitmap_get (is_set_bitmap, j))
	  {
	    if (r0 != r1)
	      os_panic ();
	  }
	else
	  {
	    if (r0 != ~0)
	      os_panic ();
	  }
      }

    if (vh->n_elts != clib_bitmap_count_set_bits (is_set_bitmap))
      os_panic ();
  }

  {
    clib_time_t ct;

    clib_time_init (&ct);

    clib_warning ("%.4e clocks/get %.4e gets/call %.4e gets/sec",
		  (f64) tm->get_stats.n_clocks /
		  (f64) tm->get_stats.n_vectors,
		  (f64) tm->get_stats.n_vectors / (f64) tm->get_stats.n_calls,
		  (f64) tm->get_stats.n_vectors /
		  (f64) (tm->get_stats.n_clocks * ct.seconds_per_clock));
    if (tm->set_stats.n_calls > 0)
      clib_warning ("%.4e clocks/set %.4e sets/call %.4e sets/sec",
		    (f64) tm->set_stats.n_clocks /
		    (f64) tm->set_stats.n_vectors,
		    (f64) tm->set_stats.n_vectors /
		    (f64) tm->set_stats.n_calls,
		    (f64) tm->set_stats.n_vectors /
		    (f64) (tm->set_stats.n_clocks * ct.seconds_per_clock));
    if (tm->unset_stats.n_calls > 0)
      clib_warning ("%.4e clocks/unset %.4e unsets/call %.4e unsets/sec",
		    (f64) tm->unset_stats.n_clocks /
		    (f64) tm->unset_stats.n_vectors,
		    (f64) tm->unset_stats.n_vectors /
		    (f64) tm->unset_stats.n_calls,
		    (f64) tm->unset_stats.n_vectors /
		    (f64) (tm->unset_stats.n_clocks * ct.seconds_per_clock));
  }

done:
  if (error)
    clib_error_report (error);
  return 0;
}

#endif /* CLIB_HAVE_VEC128 */

#ifndef CLIB_HAVE_VEC128
int
test_vhash_main (unformat_input_t * input)
{
  clib_error ("compiled without vector support");
  return 0;
}
#endif

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int r;

  clib_mem_init (0, 64ULL << 20);

  unformat_init_command_line (&i, argv);
  r = test_vhash_main (&i);
  unformat_free (&i);
  return r;
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
