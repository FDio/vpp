/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2005 Eliot Dresselhaus
 */

#include <vppinfra/random_buffer.h>

/* Fill random buffer. */
__clib_export void
clib_random_buffer_fill (clib_random_buffer_t * b, uword n_words)
{
  uword *w, n = n_words;

  if (n < 256)
    n = 256;

  n = round_pow2 (n, 2 << ISAAC_LOG2_SIZE);

  vec_add2 (b->buffer, w, n);
  do
    {
      isaac2 (b->ctx, w);
      w += 2 * ISAAC_SIZE;
      n -= 2 * ISAAC_SIZE;
    }
  while (n > 0);
}

__clib_export void
clib_random_buffer_init (clib_random_buffer_t * b, uword seed)
{
  uword i, j;

  clib_memset (b, 0, sizeof (b[0]));

  /* Seed ISAAC. */
  for (i = 0; i < ARRAY_LEN (b->ctx); i++)
    {
      uword s[ISAAC_SIZE];

      for (j = 0; j < ARRAY_LEN (s); j++)
	s[j] = ARRAY_LEN (b->ctx) * (seed + j) + i;

      isaac_init (&b->ctx[i], s);
    }
}
