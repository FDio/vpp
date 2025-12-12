/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2005 Eliot Dresselhaus
 */

#include <vppinfra/fifo.h>
#include <vppinfra/random.h>

typedef struct
{
  int a, b, c;
} A;

always_inline void
A_set (A * a, int k)
{
  a->a = 1 * k;
  a->b = 2 * k;
  a->c = 3 * k;
}

always_inline int
A_is_valid (A * a, int k)
{
  return a->a == 1 * k && a->b == 2 * k && a->c == 3 * k;
}

int
test_fifo_main (unformat_input_t * input)
{
  u32 n_added, n_removed, i, j, n_iter, seed, verbose;
  A *as = 0, *a;

  n_iter = 1000;
  seed = random_default_seed ();
  verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "iter %d", &n_iter))
	;
      else if (unformat (input, "seed %d", &seed))
	;
      else if (unformat (input, "verbose %=", &verbose, 1))
	;
      else
	{
	  clib_warning ("unknown input `%U'\n", format_unformat_error, input);
	  return 1;
	}
    }

  if (verbose)
    clib_warning ("iter %d seed %d\n", n_iter, seed);

  n_added = n_removed = 0;
  for (i = 0; i < n_iter; i++)
    {
      if (clib_fifo_elts (as) > 0 && (random_u32 (&seed) & 1))
	{
	  A tmp;
	  clib_fifo_sub1 (as, tmp);
	  ASSERT (A_is_valid (&tmp, n_removed));
	  n_removed++;
	}
      else
	{
	  clib_fifo_add2 (as, a);
	  A_set (a, n_added);
	  n_added++;
	}

      ASSERT (clib_fifo_elts (as) == n_added - n_removed);

      j = 0;
      clib_fifo_foreach (a, as, {
	ASSERT (A_is_valid (a, n_removed + j));
	j++;
      });

      ASSERT (j == clib_fifo_elts (as));
    }

  clib_fifo_free (as);

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int r;

  unformat_init_command_line (&i, argv);
  r = test_fifo_main (&i);
  unformat_free (&i);

  return r;
}
#endif
