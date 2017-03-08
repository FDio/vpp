/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <vppinfra/time.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>
#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>

#include <vppinfra/time.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>

#include <vppinfra/cuckoo_8_8.h>
#include <vppinfra/cuckoo_template.h>
#include <vppinfra/cuckoo_template.c>

typedef struct
{
  u64 seed;
  u32 nbuckets;
  u32 nitems;
  u32 search_iter;
  int careful_delete_tests;
  int verbose;
  int non_random_keys;
  uword *key_hash;
  u64 *keys;
    CVT (clib_cuckoo) hash;
  clib_time_t clib_time;

  unformat_input_t *input;

} test_main_t;

test_main_t test_main;

uword
vl (void *v)
{
  return vec_len (v);
}

void
do_search (test_main_t * tm, CVT (clib_cuckoo) * h)
{
  int i, j;
  CVT (clib_cuckoo_kv) kv;
  for (j = 0; j < tm->search_iter; j++)
    {
      for (i = 0; i < tm->nitems; i++)
	{
	  kv.key = tm->keys[i];
	  if (CV (clib_cuckoo_search) (h, &kv, &kv) < 0)
	    if (CV (clib_cuckoo_search) (h, &kv, &kv) < 0)
	      clib_warning ("[%d] search for key %llu failed unexpectedly\n",
			    i, tm->keys[i]);
	  if (kv.value != (u64) (i + 1))
	    clib_warning
	      ("[%d] search for key %llu returned %llu, not %llu\n", i,
	       tm->keys[i], kv.value, (u64) (i + 1));
	}
    }
}

static void
cb (CVT (clib_cuckoo) * h, void *ctx)
{
  fformat (stdout, "Garbage callback called...");
  if (clib_cpu_time_now () % 3)
    {
      fformat (stdout, "collecting garbage...\n");
      CV (clib_cuckoo_garbage_collect) (h);
    }
  else
    {
      fformat (stdout, "ignoring for now...\n");
    }
}

static clib_error_t *
test_cuckoo (test_main_t * tm)
{
  int i;
  uword *p;
  uword total_searches;
  f64 before, delta;
  CVT (clib_cuckoo) * h;
  CVT (clib_cuckoo_kv) kv;

  h = &tm->hash;

  CV (clib_cuckoo_init) (h, "test", tm->nbuckets, cb, NULL);

  fformat (stdout, "Pick %lld unique %s keys...\n", tm->nitems,
	   tm->non_random_keys ? "non-random" : "random");

  for (i = 0; i < tm->nitems; i++)
    {
      u64 rndkey;

      if (tm->non_random_keys == 0)
	{

	again:
	  rndkey = random_u64 (&tm->seed);

	  p = hash_get (tm->key_hash, rndkey);
	  if (p)
	    goto again;
	}
      else
	rndkey = (u64) (i + 1) << 16;

      hash_set (tm->key_hash, rndkey, i + 1);
      vec_add1 (tm->keys, rndkey);
    }

  fformat (stdout, "Add items...\n");
  for (i = 0; i < tm->nitems; i++)
    {
      kv.key = tm->keys[i];
      kv.value = i + 1;

      CV (clib_cuckoo_add_del) (h, &kv, 1 /* is_add */ );

      if (tm->verbose > 1)
	{
	  fformat (stdout, "--------------------\n");
	  fformat (stdout, "After adding key %llu value %lld...\n",
		   tm->keys[i], (u64) (i + 1));
	  fformat (stdout, "%U", CV (format_cuckoo), h,
		   2 /* very verbose */ );
	}

      CVT (clib_cuckoo_kv) kv2;
      int rv = CV (clib_cuckoo_search) (h, &kv, &kv2);
      ASSERT (CLIB_CUCKOO_ERROR_SUCCESS == rv);
    }

  fformat (stdout, "%U", CV (format_cuckoo), h, 0 /* very verbose */ );

  fformat (stdout, "Search for items %d times...\n", tm->search_iter);

  before = clib_time_now (&tm->clib_time);

  do_search (tm, h);

  delta = clib_time_now (&tm->clib_time) - before;
  total_searches = (uword) tm->search_iter * (uword) tm->nitems;

  if (delta > 0)
    fformat (stdout, "%.f searches per second\n",
	     ((f64) total_searches) / delta);

  fformat (stdout, "%lld searches in %.6f seconds\n", total_searches, delta);

#if 0
  int j;
  fformat (stdout, "Standard E-hash search for items %d times...\n",
	   tm->search_iter);

  before = clib_time_now (&tm->clib_time);

  for (j = 0; j < tm->search_iter; j++)
    {
      for (i = 0; i < tm->nitems; i++)
	{
	  p = hash_get (tm->key_hash, tm->keys[i]);
	  if (p == 0 || p[0] != (uword) (i + 1))
	    clib_warning ("ugh, couldn't find %lld\n", tm->keys[i]);
	}
    }

  delta = clib_time_now (&tm->clib_time) - before;
  total_searches = (uword) tm->search_iter * (uword) tm->nitems;

  fformat (stdout, "%lld searches in %.6f seconds\n", total_searches, delta);

  if (delta > 0)
    fformat (stdout, "%.f searches per second\n",
	     ((f64) total_searches) / delta);

#endif
  fformat (stdout, "Delete items...\n");

  for (i = 0; i < tm->nitems; i++)
    {
      int j;
      int rv;

      kv.key = tm->keys[i];
      kv.value = (u64) (i + 1);
      rv = CV (clib_cuckoo_add_del) (h, &kv, 0 /* is_add */ );

      if (rv < 0)
	clib_warning ("delete key %lld not ok but should be", tm->keys[i]);

      if (tm->careful_delete_tests)
	{
	  for (j = 0; j < tm->nitems; j++)
	    {
	      kv.key = tm->keys[j];
	      rv = CV (clib_cuckoo_search) (h, &kv, &kv);
	      if (j <= i && rv >= 0)
		{
		  clib_warning
		    ("i %d j %d search ok but should not be, value %lld", i,
		     j, kv.value);
		}
	      if (j > i && rv < 0)
		{
		  clib_warning ("i %d j %d search not ok but should be", i,
				j);
		}
	    }
	}
    }

  fformat (stdout, "After deletions, should be empty...\n");

  fformat (stdout, "%U", CV (format_cuckoo), h, 0 /* very verbose */ );
  return 0;
}

clib_error_t *
test_cuckoo_main (test_main_t * tm)
{
  unformat_input_t *i = tm->input;
  clib_error_t *error;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "seed %u", &tm->seed))
	;
      else if (unformat (i, "nbuckets %d", &tm->nbuckets))
	;
      else if (unformat (i, "non-random-keys"))
	tm->non_random_keys = 1;
      else if (unformat (i, "nitems %d", &tm->nitems))
	;
      else if (unformat (i, "careful %d", &tm->careful_delete_tests))
	;
      else if (unformat (i, "verbose %d", &tm->verbose))
	;
      else if (unformat (i, "search %d", &tm->search_iter))
	;
      else if (unformat (i, "verbose"))
	tm->verbose = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, i);
    }

  error = test_cuckoo (tm);

  return error;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  clib_error_t *error;
  test_main_t *tm = &test_main;

  clib_mem_init (0, 3ULL << 30);

  tm->input = &i;
  tm->seed = 0xdeaddabe;

  tm->nbuckets = 2;
  tm->nitems = 100000;
  tm->verbose = 1;
  tm->search_iter = 10000;
  tm->careful_delete_tests = 0;
  tm->key_hash = hash_create (0, sizeof (uword));
  clib_time_init (&tm->clib_time);

  unformat_init_command_line (&i, argv);
  error = test_cuckoo_main (tm);
  unformat_free (&i);

  if (error)
    {
      clib_error_report (error);
      return 1;
    }
  return 0;
}
#endif /* CLIB_UNIX */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
