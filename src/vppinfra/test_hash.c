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
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

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
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>

static int verbose;
#define if_verbose(format,args...) \
  if (verbose) { clib_warning(format, ## args); }

typedef struct
{
  int n_iterations;

  int n_iterations_per_print;

  /* Number of pairs to insert into hash. */
  int n_pairs;

  /* True to validate correctness of hash functions. */
  int n_iterations_per_validate;

  /* Non-zero if hash table size is to be fixed. */
  int fixed_hash_size;

  /* Verbosity level for hash formats. */
  int verbose;

  /* Random number seed. */
  u32 seed;
} hash_test_t;

static clib_error_t *
hash_next_test (word * h)
{
  hash_next_t hn = { 0 };
  hash_pair_t *p0, *p1;
  clib_error_t *error = 0;

  /* *INDENT-OFF* */
  hash_foreach_pair (p0, h, {
    p1 = hash_next (h, &hn);
    error = CLIB_ERROR_ASSERT (p0 == p1);
    if (error)
      break;
  });
  /* *INDENT-ON* */

  if (!error)
    error = CLIB_ERROR_ASSERT (!hash_next (h, &hn));

  return error;
}

static u8 *
test1_format (u8 * s, va_list * args)
{
  void *CLIB_UNUSED (user_arg) = va_arg (*args, void *);
  void *v = va_arg (*args, void *);
  hash_pair_t *p = va_arg (*args, hash_pair_t *);
  hash_t *h = hash_header (v);

  return format (s, "0x%8U -> 0x%8U",
		 format_hex_bytes, &p->key, sizeof (p->key),
		 format_hex_bytes, &p->value[0], hash_value_bytes (h));
}

static clib_error_t *
test_word_key (hash_test_t * ht)
{
  word *h = 0;
  word i, j;

  word *keys = 0, *vals = 0;
  uword *is_inserted = 0;

  clib_error_t *error = 0;

  vec_resize (keys, ht->n_pairs);
  vec_resize (vals, vec_len (keys));

  h = hash_create (ht->fixed_hash_size, sizeof (vals[0]));

  hash_set_pair_format (h, test1_format, 0);
  if (ht->fixed_hash_size)
    hash_set_flags (h, HASH_FLAG_NO_AUTO_GROW | HASH_FLAG_NO_AUTO_SHRINK);

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
	hash_unset (h, keys[vi]);
      else
	hash_set (h, keys[vi], vals[vi]);

      is_inserted = clib_bitmap_xori (is_inserted, vi);

      if (ht->n_iterations_per_print > 0
	  && ((i + 1) % ht->n_iterations_per_print) == 0)
	if_verbose ("iteration %d\n  %U", i + 1, format_hash, h, ht->verbose);

      if (ht->n_iterations_per_validate == 0
	  || (i + 1) % ht->n_iterations_per_validate)
	continue;

      {
	hash_pair_t *p;
	uword ki;

	  /* *INDENT-OFF* */
	  hash_foreach_pair (p, h, {
	      ki = p->value[0];
	      ASSERT (keys[ki] == p->key);
	  });
	  /* *INDENT-ON* */
      }

      clib_mem_validate ();

      if ((error = hash_validate (h)))
	goto done;

      for (j = 0; j < vec_len (keys); j++)
	{
	  uword *v;
	  v = hash_get (h, keys[j]);
	  if ((error =
	       CLIB_ERROR_ASSERT (clib_bitmap_get (is_inserted, j) ==
				  (v != 0))))
	    goto done;
	  if (v)
	    {
	      if ((error = CLIB_ERROR_ASSERT (v[0] == vals[j])))
		goto done;
	    }
	}
    }

  if ((error = hash_next_test (h)))
    goto done;

  if_verbose ("%U", format_hash, h, ht->verbose);

  for (i = 0; i < vec_len (keys); i++)
    {
      if (!clib_bitmap_get (is_inserted, i))
	continue;

      hash_unset (h, keys[i]);
      is_inserted = clib_bitmap_xori (is_inserted, i);

      if (ht->n_iterations_per_validate == 0
	  || (i + 1) % ht->n_iterations_per_validate)
	continue;

      clib_mem_validate ();

      if ((error = hash_validate (h)))
	goto done;

      for (j = 0; j < vec_len (keys); j++)
	{
	  uword *v;
	  v = hash_get (h, keys[j]);
	  if ((error =
	       CLIB_ERROR_ASSERT (clib_bitmap_get (is_inserted, j) ==
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
  hash_free (h);
  vec_free (keys);
  vec_free (vals);
  clib_bitmap_free (is_inserted);

  if (verbose)
    fformat (stderr, "%U\n", format_clib_mem_usage, /* verbose */ 0);

  return error;
}

static u8 *
test2_format (u8 * s, va_list * args)
{
  void *CLIB_UNUSED (user_arg) = va_arg (*args, void *);
  void *v = va_arg (*args, void *);
  hash_pair_t *p = va_arg (*args, hash_pair_t *);
  hash_t *h = hash_header (v);

  return format (s, "0x%8U <- %v",
		 format_hex_bytes, &p->value[0], hash_value_bytes (h),
		 p->key);
}

static clib_error_t *
test_string_key (hash_test_t * ht)
{
  word i, j;

  u8 **keys = 0;
  word *vals = 0;
  uword *is_inserted = 0;

  word *h = 0;

  clib_error_t *error = 0;

  vec_resize (keys, ht->n_pairs);
  vec_resize (vals, vec_len (keys));

  h =
    hash_create_vec (ht->fixed_hash_size, sizeof (keys[0][0]),
		     sizeof (uword));
  hash_set_pair_format (h, test2_format, 0);
  if (ht->fixed_hash_size)
    hash_set_flags (h, HASH_FLAG_NO_AUTO_SHRINK | HASH_FLAG_NO_AUTO_GROW);

  for (i = 0; i < vec_len (keys); i++)
    {
      keys[i] = random_string (&ht->seed, 5 + (random_u32 (&ht->seed) & 0xf));
      keys[i] = format (keys[i], "%x", i);
      vals[i] = random_u32 (&ht->seed);
    }

  for (i = 0; i < ht->n_iterations; i++)
    {
      u32 vi = random_u32 (&ht->seed) % vec_len (keys);

      if (clib_bitmap_get (is_inserted, vi))
	hash_unset_mem (h, keys[vi]);
      else
	hash_set_mem (h, keys[vi], vals[vi]);

      is_inserted = clib_bitmap_xori (is_inserted, vi);

      if (ht->n_iterations_per_print > 0
	  && ((i + 1) % ht->n_iterations_per_print) == 0)
	if_verbose ("iteration %d\n  %U", i + 1, format_hash, h, ht->verbose);

      if (ht->n_iterations_per_validate == 0
	  || (i + 1) % ht->n_iterations_per_validate)
	continue;

      clib_mem_validate ();

      if ((error = hash_validate (h)))
	goto done;

      for (j = 0; j < vec_len (keys); j++)
	{
	  uword *v;
	  v = hash_get_mem (h, keys[j]);
	  if ((error =
	       CLIB_ERROR_ASSERT (clib_bitmap_get (is_inserted, j) ==
				  (v != 0))))
	    goto done;
	  if (v)
	    {
	      if ((error = CLIB_ERROR_ASSERT (v[0] == vals[j])))
		goto done;
	    }
	}
    }

  if ((error = hash_next_test (h)))
    goto done;

  if_verbose ("%U", format_hash, h, ht->verbose);

  for (i = 0; i < vec_len (keys); i++)
    {
      if (!clib_bitmap_get (is_inserted, i))
	continue;

      hash_unset_mem (h, keys[i]);
      is_inserted = clib_bitmap_xori (is_inserted, i);

      if (ht->n_iterations_per_validate == 0
	  || (i + 1) % ht->n_iterations_per_validate)
	continue;

      clib_mem_validate ();

      if ((error = hash_validate (h)))
	goto done;

      for (j = 0; j < vec_len (keys); j++)
	{
	  uword *v;
	  v = hash_get_mem (h, keys[j]);
	  if ((error =
	       CLIB_ERROR_ASSERT (clib_bitmap_get (is_inserted, j) ==
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
  hash_free (h);
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
test_hash_main (unformat_input_t * input)
{
  hash_test_t _ht = { 0 }, *ht = &_ht;
  clib_error_t *error;

  ht->n_iterations = 100;
  ht->n_pairs = 10;
  ht->fixed_hash_size = 0;	/* zero means non-fixed size */

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0 == unformat (input, "iter %d", &ht->n_iterations)
	  && 0 == unformat (input, "print %d", &ht->n_iterations_per_print)
	  && 0 == unformat (input, "elts %d", &ht->n_pairs)
	  && 0 == unformat (input, "size %d", &ht->fixed_hash_size)
	  && 0 == unformat (input, "seed %d", &ht->seed)
	  && 0 == unformat (input, "verbose %=", &ht->verbose, 1)
	  && 0 == unformat (input, "valid %d",
			    &ht->n_iterations_per_validate))
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

  error = test_string_key (ht);
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

  verbose = (argc > 1);
  unformat_init_command_line (&i, argv);
  ret = test_hash_main (&i);
  unformat_free (&i);

  return ret;
}
#endif /* CLIB_UNIX */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
