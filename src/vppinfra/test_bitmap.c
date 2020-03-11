/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#ifdef CLIB_LINUX_KERNEL
#include <linux/unistd.h>
#endif

#ifdef CLIB_UNIX
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#endif

#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/error.h>
#include <vppinfra/random.h>
#include <vppinfra/time.h>

#include <vppinfra/bitmap.h>

#define if_verbose(format,args...) \
  if (g_verbose) { clib_warning(format, ## args); }

#ifdef CLIB_UNIX
u32 g_seed = 0xdeadcafe;
uword g_verbose = 1;
#endif

static u32
my_random_u32 (u32 * seed_return)
{
  /* Unlikely mask value to XOR into seed.
     Otherwise small seed values would give
     non-random seeming smallish numbers. */
  const u32 mask = 0x12345678;
  u32 seed, a, b, result;

  seed = *seed_return;
  seed ^= mask;

  a = seed / 127773;
  b = seed % 127773;
  seed = 16807 * b - 2836 * a;

  if ((i32) seed < 0)
    seed += ((u32) 1 << 31) - 1;

  result = seed;

  *seed_return = seed ^ mask;

  return result;
}

static void
test_bitmap_next_on_interval_fns (uword iterations, uword nbits)
{
  uword *bitmap;
  uword bit;
  uword first; /* first bit to search */
  uword l;     /* first not searched bit */
  uword rv;

  clib_bitmap_alloc (bitmap, nbits);

  for (int i = 0; i < iterations; i++)
    {
      l     = my_random_u32 (&g_seed) % nbits + 1; /* [1, nbits] */
      first = my_random_u32 (&g_seed) % l;         /* [0, l) resp. [0, l - 1] */
      bit   = my_random_u32 (&g_seed) % nbits;     /* [0, nbits - 1] */

      /* clear all bitmap bits */
      clib_bitmap_set_region (bitmap, 0, 0, nbits);

      /* set the random bit */
      clib_bitmap_set_no_check (bitmap, bit, 1);

      rv = clib_bitmap_next_set_on_interval (bitmap, first, l);

      if (bit >= first && bit < l)
        ASSERT (rv == bit);
      else
        ASSERT (rv == ~0);


      /* set all bitmap bits */
      clib_bitmap_set_region (bitmap, 0, 1, nbits);

      /* clear the random bit */
      clib_bitmap_set_no_check (bitmap, bit, 0);

      rv = clib_bitmap_next_clear_on_interval (bitmap, first, l);

      if (bit >= first && bit < l)
        ASSERT (rv == bit);
      else
        ASSERT (rv == ~0);
    }

  clib_bitmap_free (bitmap);
}

int
test_bitmap_main (unformat_input_t * input)
{
  uword iter = 1000;
  uword help = 0;
  uword maxbits = 1000;
  uword nbits;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0 == unformat (input, "iter %d", &iter)
	  && 0 == unformat (input, "seed %d", &g_seed)
	  && 0 == unformat (input, "verbose %d", &g_verbose)
	  && 0 == unformat (input, "maxbits %d", &maxbits)
	  && 0 == unformat (input, "help %=", &help, 1))
	{
	  clib_error ("unknown input `%U'", format_unformat_error, input);
	  goto usage;
	}
    }

  if (help)
    goto usage;

  nbits = my_random_u32 (&g_seed) % (maxbits - 1) + 2; /* [2, maxbits] */

  if_verbose ("maxbits: %lu\n", maxbits);
  if_verbose ("randomized bitmap size: %lu\n", nbits);

  test_bitmap_next_on_interval_fns (iter, nbits);

  return 0;

usage:
  fformat (stdout, "Usage: test_bitmap iter <N> seed <N> verbose <N> "
	   "maxbits <N>\n");
  if (help)
    return 0;

  return -1;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  clib_mem_init (0, 3ULL << 30);

  unformat_init_command_line (&i, argv);
  ret = test_bitmap_main (&i);
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
