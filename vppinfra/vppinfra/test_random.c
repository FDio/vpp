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

#include <vppinfra/format.h>
#include <vppinfra/bitmap.h>

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


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
