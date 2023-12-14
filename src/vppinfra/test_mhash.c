/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Yandex LLC.
 */

#ifdef CLIB_LINUX_KERNEL
#include <linux/unistd.h>
#endif

#ifdef CLIB_UNIX
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <vppinfra/time.h>
#endif

#include <vppinfra/random.h>
#include <vppinfra/mem.h>
#include <vppinfra/hash.h>
#include <vppinfra/mhash.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>

static int verbose;
#define if_verbose(format, args...)                                           \
  if (verbose)                                                                \
    {                                                                         \
      clib_warning (format, ##args);                                          \
    }

typedef struct
{
  int n_iterations;

  int n_iterations_per_print;

  /* Number of pairs to insert into mhash. */
  int n_pairs;

  /* True to validate correctness of mhash functions. */
  int n_iterations_per_validate;

  /* Verbosity level for mhash formats. */
  int verbose;

  /* Random number seed. */
  u32 seed;
} mhash_test_t;

static clib_error_t *
mhash_next_test (mhash_t *h)
{
  hash_next_t hn = { 0 };
  hash_pair_t *p0, *p1;
  clib_error_t *error = 0;

  hash_foreach_pair (p0, h->hash, {
    p1 = hash_next (h->hash, &hn);
    error = CLIB_ERROR_ASSERT (p0 == p1);
    if (error)
      break;
  });

  if (!error)
    error = CLIB_ERROR_ASSERT (!hash_next (h->hash, &hn));

  return error;
}

static clib_error_t *
test_word_key (mhash_test_t *ht)
{
  mhash_t _h = { 0 }, *h = &_h;
  word i, j;

  word *keys = 0, *vals = 0;
  uword *is_inserted = 0;

  clib_error_t *error = 0;

  vec_resize (keys, ht->n_pairs);
  vec_resize (vals, vec_len (keys));

  mhash_init (h, sizeof (vals[0]), sizeof (keys[0]));
  /* borrow 0 elt to make index keys non-zero */
  vec_validate (h->key_vector_or_heap, 0);

  {
    uword *unique = 0;
    u32 k;

    for (i = 0; i < vec_len (keys); i++)
      {
	do
	  {
	    k = random_u32 (&ht->seed) & 0xfffff;
	  }
	while (clib_bitmap_get (unique, k));
	unique = clib_bitmap_ori (unique, k);
	keys[i] = k;
	vals[i] = i;
      }

    clib_bitmap_free (unique);
  }

  for (i = 0; i < ht->n_iterations; i++)
    {
      u32 vi = random_u32 (&ht->seed) % vec_len (keys);

      if (clib_bitmap_get (is_inserted, vi))
	{
	  mhash_unset (h, &keys[vi], 0);
	  mhash_unset (h, &keys[vi], 0);
	}
      else
	{
	  mhash_set (h, &keys[vi], vals[vi], 0);
	  mhash_set (h, &keys[vi], vals[vi], 0);
	}

      is_inserted = clib_bitmap_xori (is_inserted, vi);

      if (ht->n_iterations_per_print > 0 &&
	  ((i + 1) % ht->n_iterations_per_print) == 0)
	if_verbose ("iteration %d\n  %U", i + 1, format_mhash, h, ht->verbose);

      if (ht->n_iterations_per_validate == 0 ||
	  (i + 1) % ht->n_iterations_per_validate)
	continue;

      {
	uword ki, *k, *v;

	mhash_foreach (k, v, h, {
	  ki = v[0];
	  ASSERT (keys[ki] == k[0]);
	});
      }

      if ((error = hash_validate (h->hash)))
	goto done;

      for (j = 0; j < vec_len (keys); j++)
	{
	  uword *v;
	  v = mhash_get (h, &keys[j]);
	  if ((error = CLIB_ERROR_ASSERT (clib_bitmap_get (is_inserted, j) ==
					  (v != 0))))
	    goto done;
	  if (v)
	    {
	      if ((error = CLIB_ERROR_ASSERT (v[0] == vals[j])))
		goto done;
	    }
	}
    }

  if ((error = mhash_next_test (h)))
    goto done;

  if_verbose ("%U", format_mhash, h, ht->verbose);

  for (i = 0; i < vec_len (keys); i++)
    {
      if (!clib_bitmap_get (is_inserted, i))
	continue;

      mhash_unset (h, &keys[i], 0);
      mhash_unset (h, &keys[i], 0);
      is_inserted = clib_bitmap_xori (is_inserted, i);

      if (ht->n_iterations_per_validate == 0 ||
	  (i + 1) % ht->n_iterations_per_validate)
	continue;

      if ((error = hash_validate (h->hash)))
	goto done;

      for (j = 0; j < vec_len (keys); j++)
	{
	  uword *v;
	  v = mhash_get (h, &keys[j]);
	  if ((error = CLIB_ERROR_ASSERT (clib_bitmap_get (is_inserted, j) ==
					  (v != 0))))
	    goto done;
	  if (v)
	    {
	      if ((error = CLIB_ERROR_ASSERT (v[0] == vals[j])))
		goto done;
	    }
	}
    }

done:
  mhash_free (h);
  vec_free (keys);
  vec_free (vals);
  clib_bitmap_free (is_inserted);

  if (verbose)
    fformat (stderr, "%U\n", format_clib_mem_usage, /* verbose */ 0);

  return error;
}

static u8 *
test2_format (u8 *s, va_list *args)
{
  void *CLIB_UNUSED (user_arg) = va_arg (*args, void *);
  void *v = va_arg (*args, void *);
  hash_pair_t *p = va_arg (*args, hash_pair_t *);
  hash_t *h = hash_header (v);
  mhash_t *mh = uword_to_pointer (h->user, mhash_t *);

  return format (s, "0x%8U <- %U", format_hex_bytes, &p->value[0],
		 hash_value_bytes (h), format_mhash_key, mh, (u32) p->key);
}

static clib_error_t *
test_string_key (mhash_test_t *ht, uword is_c_string)
{
  mhash_t _h = { 0 }, *h = &_h;
  word i, j;

  u8 **keys = 0;
  word *vals = 0;
  uword *is_inserted = 0;

  clib_error_t *error = 0;

  vec_resize (keys, ht->n_pairs);
  vec_resize (vals, vec_len (keys));

  if (is_c_string)
    mhash_init_c_string (h, sizeof (vals[0]));
  else
    mhash_init_vec_string (h, sizeof (vals[0]));
  hash_set_pair_format (h->hash, test2_format, 0);

  for (i = 0; i < vec_len (keys); i++)
    {
      keys[i] = random_string (&ht->seed, 5 + (random_u32 (&ht->seed) & 0xf));
      keys[i] = format (keys[i], "%x", i);
      if (is_c_string)
	vec_terminate_c_string (keys[i]);
      vals[i] = random_u32 (&ht->seed);
    }

  for (i = 0; i < ht->n_iterations; i++)
    {
      u32 vi = random_u32 (&ht->seed) % vec_len (keys);

      if (clib_bitmap_get (is_inserted, vi))
	{
	  mhash_unset (h, keys[vi], 0);
	  mhash_unset (h, keys[vi], 0);
	}
      else
	{
	  mhash_set (h, keys[vi], vals[vi], 0);
	  mhash_set (h, keys[vi], vals[vi], 0);
	}

      is_inserted = clib_bitmap_xori (is_inserted, vi);

      if (ht->n_iterations_per_print > 0 &&
	  ((i + 1) % ht->n_iterations_per_print) == 0)
	if_verbose ("iteration %d\n  %U", i + 1, format_mhash, h, ht->verbose);

      if (ht->n_iterations_per_validate == 0 ||
	  (i + 1) % ht->n_iterations_per_validate)
	continue;

      if ((error = hash_validate (h->hash)))
	goto done;

      for (j = 0; j < vec_len (keys); j++)
	{
	  uword *v;
	  v = mhash_get (h, keys[j]);
	  if ((error = CLIB_ERROR_ASSERT (clib_bitmap_get (is_inserted, j) ==
					  (v != 0))))
	    goto done;
	  if (v)
	    {
	      if ((error = CLIB_ERROR_ASSERT (v[0] == vals[j])))
		goto done;
	    }
	}
    }

  if ((error = mhash_next_test (h)))
    goto done;

  if_verbose ("%U", format_mhash, h, ht->verbose);

  for (i = 0; i < vec_len (keys); i++)
    {
      if (!clib_bitmap_get (is_inserted, i))
	continue;

      mhash_unset (h, keys[i], 0);
      mhash_unset (h, keys[i], 0);
      is_inserted = clib_bitmap_xori (is_inserted, i);

      if (ht->n_iterations_per_validate == 0 ||
	  (i + 1) % ht->n_iterations_per_validate)
	continue;

      if ((error = hash_validate (h->hash)))
	goto done;

      for (j = 0; j < vec_len (keys); j++)
	{
	  uword *v;
	  v = mhash_get (h, keys[j]);
	  if ((error = CLIB_ERROR_ASSERT (clib_bitmap_get (is_inserted, j) ==
					  (v != 0))))
	    goto done;
	  if (v)
	    {
	      if ((error = CLIB_ERROR_ASSERT (v[0] == vals[j])))
		goto done;
	    }
	}
    }

done:
  mhash_free (h);
  vec_free (vals);
  clib_bitmap_free (is_inserted);

  for (i = 0; i < vec_len (keys); i++)
    vec_free (keys[i]);
  vec_free (keys);

  if (verbose)
    fformat (stderr, "%U\n", format_clib_mem_usage, /* verbose */ 0);

  return error;
}

int
test_mhash_main (unformat_input_t *input)
{
  mhash_test_t _ht = { 0 }, *ht = &_ht;
  clib_error_t *error;

  ht->n_iterations = 100;
  ht->n_pairs = 10;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0 == unformat (input, "iter %d", &ht->n_iterations) &&
	  0 == unformat (input, "print %d", &ht->n_iterations_per_print) &&
	  0 == unformat (input, "elts %d", &ht->n_pairs) &&
	  0 == unformat (input, "seed %d", &ht->seed) &&
	  0 == unformat (input, "verbose %=", &ht->verbose, 1) &&
	  0 == unformat (input, "valid %d", &ht->n_iterations_per_validate))
	{
	  clib_warning ("unknown input `%U'", format_unformat_error, input);
	  return 1;
	}
    }

  if (!ht->seed)
    ht->seed = random_default_seed ();

  if_verbose ("testing %d iterations, seed %d", ht->n_iterations, ht->seed);

  error = test_word_key (ht);
  if (error)
    clib_error_report (error);

  error = test_string_key (ht, 0);
  if (error)
    clib_error_report (error);

  error = test_string_key (ht, 1);
  if (error)
    clib_error_report (error);

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  clib_mem_init (0, 3ULL << 30);

  verbose = (argc > 1);
  unformat_init_command_line (&i, argv);
  ret = test_mhash_main (&i);
  unformat_free (&i);

  return ret;
}
#endif /* CLIB_UNIX */
