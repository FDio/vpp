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
  Copyright (c) 2005 Eliot Dresselhaus

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
#include <vppinfra/hash.h>
#include <vppinfra/random.h>
#include <vppinfra/random_isaac.h>

static int verbose;
#define if_verbose(format,args...) \
  if (verbose) { clib_warning(format, ## args); }

int
test_isaac_main (unformat_input_t * input)
{
  uword n_iterations, seed;
  uword i, repeat_count;
  uword *hash = 0;
  uword print;
  isaac_t ctx;
  uword results[ISAAC_SIZE] = { 0 };
  uword n_results;

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

  results[0] = seed;

  if (n_iterations == 0)
    n_iterations = ~0;

  if_verbose ("%d iterations, seed %d\n", n_iterations, seed);

  repeat_count = 0;
  isaac_init (&ctx, results);
  isaac (&ctx, results);
  n_results = 0;
  for (i = 0; i < n_iterations; i++)
    {
      uword r = results[n_results++];

      if (!hash)
	hash = hash_create (0, /* value bytes */ 0);

      if (hash_get (hash, r))
	goto repeat;

      hash_set1 (hash, r);

      if (n_results >= ARRAY_LEN (results))
	{
	  isaac (&ctx, results);
	  n_results = 0;
	}

      if (verbose && 0 == (i & (print - 1)))
	fformat (stderr, "0x%08x iterations %d repeats\n", i, repeat_count);

      if (hash_elts (hash) > 0x100000)
	hash_free (hash);

      continue;

    repeat:
      fformat (stderr, "repeat found at iteration  %d/%d\n", i, n_iterations);
      repeat_count++;
      continue;
    }

  return repeat_count > 0 ? 1 : 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  verbose = (argc > 1);
  unformat_init_command_line (&i, argv);
  ret = test_isaac_main (&i);
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
