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

#include <vppinfra/phash.h>
#include <vppinfra/format.h>
#include <vppinfra/random.h>

static int verbose;
#define if_verbose(format,args...) \
  if (verbose) { clib_warning(format, ## args); }

int
test_phash_main (unformat_input_t * input)
{
  phash_main_t _pm = { 0 }, *pm = &_pm;
  int n_keys, random_keys;
  u32 seed;
  clib_error_t *error;

  random_keys = 1;
  n_keys = 1000;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0 == unformat (input, "keys %d", &n_keys)
	  && 0 == unformat (input, "verbose %=", &verbose, 1)
	  && 0 == unformat (input, "random-keys %=", &random_keys, 1)
	  && 0 == unformat (input, "sequential-keys %=", &random_keys, 0)
	  && 0 == unformat (input, "seed %d", &pm->random_seed)
	  && 0 == unformat (input, "64-bit %|", &pm->flags, PHASH_FLAG_MIX64)
	  && 0 == unformat (input, "32-bit %|", &pm->flags, PHASH_FLAG_MIX32)
	  && 0 == unformat (input, "fast %|", &pm->flags,
			    PHASH_FLAG_FAST_MODE)
	  && 0 == unformat (input, "slow %|", &pm->flags,
			    PHASH_FLAG_SLOW_MODE)
	  && 0 == unformat (input, "minimal %|", &pm->flags,
			    PHASH_FLAG_MINIMAL)
	  && 0 == unformat (input, "non-minimal %|", &pm->flags,
			    PHASH_FLAG_NON_MINIMAL))
	clib_error ("unknown input `%U'", format_unformat_error, input);
    }

  if (!pm->random_seed)
    pm->random_seed = random_default_seed ();

  if_verbose
    ("%d %d-bit keys, random seed %d, %s mode, looking for %sminimal hash",
     n_keys, (pm->flags & PHASH_FLAG_MIX64) ? 64 : 32, pm->random_seed,
     (pm->flags & PHASH_FLAG_FAST_MODE) ? "fast" : "slow",
     (pm->flags & PHASH_FLAG_MINIMAL) ? "" : "non-");

  seed = pm->random_seed;

  /* Initialize random keys. */
  {
    phash_key_t *k;

    vec_resize (pm->keys, n_keys);
    vec_foreach (k, pm->keys)
    {
      k->key = k - pm->keys;
      if (random_keys)
	{
	  if (pm->flags & PHASH_FLAG_MIX64)
	    k->key = random_u64 (&seed);
	  else
	    k->key = random_u32 (&seed);
	}
    }
  }

  error = phash_find_perfect_hash (pm);
  if (error)
    {
      clib_error_report (error);
      return 1;
    }
  else
    {
      if_verbose ("(%d,%d) (a,b) bits, %d seeds tried, %d tree walks",
		  pm->a_bits, pm->b_bits,
		  pm->n_seed_trials, pm->n_perfect_calls);

      error = phash_validate (pm);
      if (error)
	{
	  clib_error_report (error);
	  return 1;
	}
    }

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int res;

  verbose = (argc > 1);
  unformat_init_command_line (&i, argv);
  res = test_phash_main (&i);
  unformat_free (&i);
  return res;
}
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
