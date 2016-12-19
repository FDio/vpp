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
#include <vppinfra/bitmap.h>
#include <vppinfra/os.h>
#include <vppinfra/qhash.h>
#include <vppinfra/random.h>
#include <vppinfra/time.h>

typedef struct
{
  u32 n_iter, seed, n_keys, n_hash_keys, verbose;

  u32 max_vector;

  uword *hash;

  uword *keys_in_hash_bitmap;

  u32 *qhash;

  uword *keys;

  uword *lookup_keys;
  uword *lookup_key_indices;
  u32 *lookup_results;

  u32 *get_multiple_results;

  clib_time_t time;

  f64 overflow_fraction, ave_elts;
  f64 get_time, hash_get_time;
  f64 set_time, set_count;
  f64 unset_time, unset_count;
  f64 hash_set_time, hash_unset_time;
} test_qhash_main_t;

clib_error_t *
test_qhash_main (unformat_input_t * input)
{
  clib_error_t *error = 0;
  test_qhash_main_t _tm, *tm = &_tm;
  uword i, iter;

  memset (tm, 0, sizeof (tm[0]));
  tm->n_iter = 10;
  tm->seed = 1;
  tm->n_keys = 10;
  tm->max_vector = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "iter %d", &tm->n_iter))
	;
      else if (unformat (input, "seed %d", &tm->seed))
	;
      else if (unformat (input, "keys %d", &tm->n_keys))
	;
      else if (unformat (input, "size %d", &tm->n_hash_keys))
	;
      else if (unformat (input, "vector %d", &tm->max_vector))
	;
      else if (unformat (input, "verbose"))
	tm->verbose = 1;
      else
	{
	  error = clib_error_create ("unknown input `%U'\n",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (!tm->seed)
    tm->seed = random_default_seed ();

  clib_time_init (&tm->time);

  clib_warning ("iter %d, seed %u, keys %d, max vector %d, ",
		tm->n_iter, tm->seed, tm->n_keys, tm->max_vector);

  vec_resize (tm->keys, tm->n_keys);
  vec_resize (tm->get_multiple_results, tm->n_keys);
  for (i = 0; i < vec_len (tm->keys); i++)
    tm->keys[i] = random_uword (&tm->seed);

  if (!tm->n_hash_keys)
    tm->n_hash_keys = 2 * max_pow2 (tm->n_keys);
  tm->n_hash_keys = clib_max (tm->n_keys, tm->n_hash_keys);
  qhash_resize (tm->qhash, tm->n_hash_keys);

  {
    qhash_t *h = qhash_header (tm->qhash);
    int i;
    for (i = 0; i < ARRAY_LEN (h->hash_seeds); i++)
      h->hash_seeds[i] = random_uword (&tm->seed);
  }

  vec_resize (tm->lookup_keys, tm->max_vector);
  vec_resize (tm->lookup_key_indices, tm->max_vector);
  vec_resize (tm->lookup_results, tm->max_vector);

  for (iter = 0; iter < tm->n_iter; iter++)
    {
      uword *p, j, n, is_set;

      n = tm->max_vector;

      is_set = random_u32 (&tm->seed) & 1;
      is_set |= hash_elts (tm->hash) < (tm->n_keys / 4);
      if (hash_elts (tm->hash) > (3 * tm->n_keys) / 4)
	is_set = 0;

      _vec_len (tm->lookup_keys) = n;
      _vec_len (tm->lookup_key_indices) = n;
      j = 0;
      while (j < n)
	{
	  i = random_u32 (&tm->seed) % vec_len (tm->keys);
	  if (clib_bitmap_get (tm->keys_in_hash_bitmap, i) != is_set)
	    {
	      f64 t[2];
	      tm->lookup_key_indices[j] = i;
	      tm->lookup_keys[j] = tm->keys[i];
	      t[0] = clib_time_now (&tm->time);
	      if (is_set)
		hash_set (tm->hash, tm->keys[i], i);
	      else
		hash_unset (tm->hash, tm->keys[i]);
	      t[1] = clib_time_now (&tm->time);
	      if (is_set)
		tm->hash_set_time += t[1] - t[0];
	      else
		tm->hash_unset_time += t[1] - t[0];
	      tm->keys_in_hash_bitmap
		= clib_bitmap_set (tm->keys_in_hash_bitmap, i, is_set);
	      j++;
	    }
	}

      {
	f64 t[2];

	if (is_set)
	  {
	    t[0] = clib_time_now (&tm->time);
	    qhash_set_multiple (tm->qhash,
				tm->lookup_keys,
				vec_len (tm->lookup_keys),
				tm->lookup_results);
	    t[1] = clib_time_now (&tm->time);
	    tm->set_time += t[1] - t[0];
	    tm->set_count += vec_len (tm->lookup_keys);
	    for (i = 0; i < vec_len (tm->lookup_keys); i++)
	      {
		uword r = tm->lookup_results[i];
		*vec_elt_at_index (tm->qhash, r) = tm->lookup_key_indices[i];
	      }
	  }
	else
	  {
	    t[0] = clib_time_now (&tm->time);
	    qhash_unset_multiple (tm->qhash,
				  tm->lookup_keys,
				  vec_len (tm->lookup_keys),
				  tm->lookup_results);
	    t[1] = clib_time_now (&tm->time);
	    tm->unset_time += t[1] - t[0];
	    tm->unset_count += vec_len (tm->lookup_keys);

	    for (i = 0; i < vec_len (tm->lookup_keys); i++)
	      {
		uword r = tm->lookup_results[i];
		*vec_elt_at_index (tm->qhash, r) = ~0;
	      }
	  }
      }

      if (qhash_elts (tm->qhash) != hash_elts (tm->hash))
	os_panic ();

      {
	qhash_t *h;
	uword i, k, l, count;

	h = qhash_header (tm->qhash);

	for (i = k = 0; k < vec_len (h->hash_key_valid_bitmap); k++)
	  i += count_set_bits (h->hash_key_valid_bitmap[k]);
	k = hash_elts (h->overflow_hash);
	l = qhash_elts (tm->qhash);
	if (i + k != l)
	  os_panic ();

	count = hash_elts (h->overflow_hash);
	for (i = 0; i < (1 << h->log2_hash_size); i++)
	  count += tm->qhash[i] != ~0;
	if (count != qhash_elts (tm->qhash))
	  os_panic ();

	{
	  u32 *tmp = 0;

	  /* *INDENT-OFF* */
	  hash_foreach (k, l, h->overflow_hash, ({
	    j = qhash_hash_mix (h, k) / QHASH_KEYS_PER_BUCKET;
	    vec_validate (tmp, j);
	    tmp[j] += 1;
	  }));
	  /* *INDENT-ON* */

	  for (k = 0; k < vec_len (tmp); k++)
	    {
	      if (k >= vec_len (h->overflow_counts))
		os_panic ();
	      if (h->overflow_counts[k] != tmp[k])
		os_panic ();
	    }
	  for (; k < vec_len (h->overflow_counts); k++)
	    if (h->overflow_counts[k] != 0)
	      os_panic ();

	  vec_free (tmp);
	}
      }

      {
	f64 t[2];

	t[0] = clib_time_now (&tm->time);
	qhash_get_multiple (tm->qhash, tm->keys, vec_len (tm->keys),
			    tm->get_multiple_results);
	t[1] = clib_time_now (&tm->time);
	tm->get_time += t[1] - t[0];

	for (i = 0; i < vec_len (tm->keys); i++)
	  {
	    u32 r;

	    t[0] = clib_time_now (&tm->time);
	    p = hash_get (tm->hash, tm->keys[i]);
	    t[1] = clib_time_now (&tm->time);
	    tm->hash_get_time += t[1] - t[0];

	    r = qhash_get (tm->qhash, tm->keys[i]);
	    if (p)
	      {
		if (p[0] != i)
		  os_panic ();
		if (*vec_elt_at_index (tm->qhash, r) != i)
		  os_panic ();
	      }
	    else
	      {
		if (r != ~0)
		  os_panic ();
	      }
	    if (r != tm->get_multiple_results[i])
	      os_panic ();
	  }
      }

      tm->overflow_fraction +=
	((f64) qhash_n_overflow (tm->qhash) / qhash_elts (tm->qhash));
      tm->ave_elts += qhash_elts (tm->qhash);
    }

  fformat (stderr, "%d iter %.6e overflow, %.4f ave. elts\n",
	   tm->n_iter,
	   tm->overflow_fraction / tm->n_iter, tm->ave_elts / tm->n_iter);

  tm->get_time /= tm->n_iter * vec_len (tm->keys);
  tm->hash_get_time /= tm->n_iter * vec_len (tm->keys);

  tm->set_time /= tm->set_count;
  tm->unset_time /= tm->unset_count;
  tm->hash_set_time /= tm->set_count;
  tm->hash_unset_time /= tm->unset_count;

  fformat (stderr,
	   "get/set/unset clocks %.2e %.2e %.2e clib %.2e %.2e %.2e ratio %.2f %.2f %.2f\n",
	   tm->get_time * tm->time.clocks_per_second,
	   tm->set_time * tm->time.clocks_per_second,
	   tm->unset_time * tm->time.clocks_per_second,
	   tm->hash_get_time * tm->time.clocks_per_second,
	   tm->hash_set_time * tm->time.clocks_per_second,
	   tm->hash_unset_time * tm->time.clocks_per_second,
	   tm->hash_get_time / tm->get_time, tm->hash_set_time / tm->set_time,
	   tm->hash_unset_time / tm->unset_time);


done:
  return error;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  clib_error_t *error;

  unformat_init_command_line (&i, argv);
  error = test_qhash_main (&i);
  unformat_free (&i);
  if (error)
    {
      clib_error_report (error);
      return 1;
    }
  else
    return 0;
}
#endif /* CLIB_UNIX */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
