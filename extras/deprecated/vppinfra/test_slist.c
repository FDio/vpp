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

#ifdef CLIB_UNIX
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#endif

#include <vppinfra/slist.h>

typedef struct
{
  u32 *random_pool;
  u32 seed;
  u32 iter;
  u32 verbose;
  f64 branching_factor;
  clib_slist_t slist;
} test_main_t;

test_main_t test_main;

#define foreach_simple_test                     \
_(2)                                            \
_(4)                                            \
_(3)                                            \
_(1)


void
run_test (test_main_t * tm)
{
  int i;
  u32 *tv;
  u32 ncompares;
  u64 total_compares = 0;

  if (1)
    {
      /*
       * Add a bunch of random numbers to the skip-list,
       * sorting them.
       */
      for (i = 0; i < tm->iter; i++)
	{
	  pool_get (tm->random_pool, tv);
	  *tv = random_u32 (&tm->seed);
	  clib_slist_add (&tm->slist, tv, tv - tm->random_pool);
	}
      /* make sure we can find each one */
      for (i = 0; i < tm->iter; i++)
	{
	  u32 search_result;
	  tv = pool_elt_at_index (tm->random_pool, i);

	  search_result = clib_slist_search (&tm->slist, tv, &ncompares);
	  ASSERT (search_result == i);

	  total_compares += ncompares;
	}

      fformat (stdout, "%.2f avg compares/search\n",
	       (f64) total_compares / (f64) i);

      fformat (stdout, "%U\n", format_slist, &tm->slist,
	       tm->iter < 1000 /* verbose */ );

      /* delete half of them */
      for (i = tm->iter / 2; i < tm->iter; i++)
	{
	  tv = pool_elt_at_index (tm->random_pool, i);
	  (void) clib_slist_del (&tm->slist, tv);
	}

      /* make sure we can find the set we should find, and no others */
      for (i = 0; i < tm->iter; i++)
	{
	  u32 search_result;
	  tv = pool_elt_at_index (tm->random_pool, i);

	  search_result = clib_slist_search (&tm->slist, tv, &ncompares);
	  if (i >= tm->iter / 2)
	    ASSERT (search_result == (u32) ~ 0);
	  else
	    ASSERT (search_result == i);

	}

      fformat (stdout, "%U\n", format_slist, &tm->slist,
	       tm->iter < 1000 /* verbose */ );

      /* delete the rest */
      for (i = 0; i < tm->iter; i++)
	{
	  tv = pool_elt_at_index (tm->random_pool, i);

	  (void) clib_slist_del (&tm->slist, tv);
	}

      fformat (stdout, "%U\n", format_slist, &tm->slist,
	       tm->iter < 1000 /* verbose */ );
    }
  else
    {

#define _(n)                                                            \
    do {                                                                \
      pool_get (tm->random_pool, tv);                                   \
      *tv = n;                                                          \
      clib_slist_add (&tm->slist, tv, tv - tm->random_pool);            \
      fformat(stdout, "%U\n", format_slist, &tm->slist, 1 /* verbose */); \
    } while (0);
      foreach_simple_test;
#undef _
    }

  return;
}

word
test_compare (void *key, u32 elt_index)
{
  u32 *k = (u32 *) key;
  u32 elt = test_main.random_pool[elt_index];

  if (*k < elt)
    return -1;
  if (*k > elt)
    return 1;
  return 0;
}

u8 *
test_format (u8 * s, va_list * args)
{
  u32 elt_index = va_arg (*args, u32);
  u32 elt = test_main.random_pool[elt_index];

  return format (s, "%u", elt);
}

void
initialize_slist (test_main_t * tm)
{
  clib_slist_init (&tm->slist, tm->branching_factor,
		   test_compare, test_format);
}

int
test_slist_main (unformat_input_t * input)
{
  test_main_t *tm = &test_main;
  u32 tmp;

  tm->seed = 0xbabeb00b;
  tm->iter = 100000;
  tm->verbose = 1;
  tm->branching_factor = 1.0 / 5.0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "seed %d", &tm->seed))
	continue;
      else if (unformat (input, "iter %d", &tm->iter))
	continue;
      else if (unformat (input, "verbose"))
	tm->verbose = 1;
      else if (unformat (input, "branch %d", &tmp))
	{
	  if (tmp > 0)
	    tm->branching_factor = 1.0 / (f64) tmp;
	  else
	    fformat (stderr, "warning: branch = 0, ignored\n");
	}
      else
	{
	  clib_error ("unknown input `%U'", format_unformat_error, input);
	  goto usage;
	}
    }
  initialize_slist (tm);
  run_test (tm);

  return 0;

usage:
  fformat (stderr, "usage: test_slist seed <seed> iter <iter> [verbose]\n");
  return 1;

}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  clib_mem_init (0, (u64) 4 << 30);

  unformat_init_command_line (&i, argv);
  ret = test_slist_main (&i);
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
