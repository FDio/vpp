/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus
 */

#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>

static u32 outcome_frequencies[] = {
  8, 5, 9, 2, 7, 5,
};


int
test_chisquare (void)
{
  u64 *values = 0;
  int i;
  f64 d, delta_d;

  vec_validate (values, 5);

  for (i = 0; i < 6; i++)
    values[i] = (u64) outcome_frequencies[i];

  d = clib_chisquare (values);

  delta_d = d - 5.333;

  if (delta_d < 0.0)
    delta_d = -delta_d;

  if (delta_d < 0.001)
    {
      fformat (stdout, "chisquare OK...\n");
      return 0;
    }
  else
    {
      fformat (stdout, "chisquare BAD, d = %.3f\n", d);
      return -1;
    }
}

static u32 known_random_sequence[] = {
  0x00000000, 0x3c6ef35f, 0x47502932, 0xd1ccf6e9,
  0xaaf95334, 0x6252e503, 0x9f2ec686, 0x57fe6c2d,
  0xa3d95fa8, 0x81fdbee7, 0x94f0af1a, 0xcbf633b1,
};


int
test_random_main (unformat_input_t * input)
{
  uword n_iterations;
  uword i, repeat_count;
  uword *bitmap = 0;
  uword print;
  u32 seed;
  u32 *seedp = &seed;
  u64 *counts = 0;
  f64 d;

  /* first, check known sequence from Numerical Recipes in C, 2nd ed.
     page 284 */
  seed = known_random_sequence[0];
  for (i = 0; i < ARRAY_LEN (known_random_sequence) - 1; i++)
    {
      u32 rv;
      rv = random_u32 (seedp);
      if (rv != known_random_sequence[i + 1])
	{
	  fformat (stderr, "known sequence check FAILS at index %d", i + 1);
	  break;
	}
    }

  clib_warning ("known sequence check passes");

  n_iterations = 1000;
  seed = 0;
  print = 1 << 24;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0 == unformat (input, "iter %d", &n_iterations)
	  && 0 == unformat (input, "print %d", &print)
	  && 0 == unformat (input, "seed %d", &seed))
	clib_error ("unknown input `%U'", format_unformat_error, input);
    }

  if (!seed)
    seed = random_default_seed ();

  if (n_iterations == 0)
    n_iterations = random_u32_max ();

  clib_warning ("%d iterations, seed %d\n", n_iterations, seed);

  repeat_count = 0;
  for (i = 0; i < n_iterations; i++)
    {
      uword r = random_u32 (&seed);
      uword b, ri, rj;

      ri = r / BITS (bitmap[0]);
      rj = (uword) 1 << (r % BITS (bitmap[0]));

      vec_validate (bitmap, ri);
      b = bitmap[ri];

      if (b & rj)
	goto repeat;
      b |= rj;
      bitmap[ri] = b;

      if (0 == (i & (print - 1)))
	fformat (stderr, "0x%08x iterations %d repeats\n", i, repeat_count);
      continue;

    repeat:
      fformat (stderr, "repeat found at iteration  %d/%d\n", i, n_iterations);
      repeat_count++;
      continue;
    }

  if (test_chisquare ())
    return (-1);

  /* Simple randomness tests based on X2 stats */
  vec_validate (counts, 255);

  for (i = 0; i < 1000000; i++)
    {
      u32 random_index;
      u32 r = random_u32 (&seed);

      random_index = r & 0xFF;

      counts[random_index]++;
    }

  d = clib_chisquare (counts);

  fformat (stdout, "%d random octets, chisquare stat d = %.3f\n", i, d);

  vec_free (counts);

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  clib_mem_init (0, 3ULL << 30);

  unformat_init_command_line (&i, argv);
  ret = test_random_main (&i);
  unformat_free (&i);

  return ret;
}
#endif /* CLIB_UNIX */
