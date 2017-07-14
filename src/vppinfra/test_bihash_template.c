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
#include <vppinfra/time.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>

#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_template.h>

#include <vppinfra/bihash_template.c>

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
    BVT (clib_bihash) hash;
  clib_time_t clib_time;

  unformat_input_t *input;

} test_main_t;

test_main_t test_main;

uword
vl (void *v)
{
  return vec_len (v);
}

static clib_error_t *
test_bihash_vec64 (test_main_t * tm)
{
  u32 user_buckets = 1228800;
  u32 user_memory_size = 209715200;
  BVT (clib_bihash_kv) kv;
  int i, j;
  f64 before;
  f64 *cum_times = 0;
  BVT (clib_bihash) * h;

  h = &tm->hash;

  BV (clib_bihash_init) (h, "test", user_buckets, user_memory_size);

  before = clib_time_now (&tm->clib_time);

  for (j = 0; j < 10; j++)
    {
      for (i = 1; i <= j * 1000 + 1; i++)
	{
	  kv.key = i;
	  kv.value = 1;

	  BV (clib_bihash_add_del) (h, &kv, 1 /* is_add */ );
	}

      vec_add1 (cum_times, clib_time_now (&tm->clib_time) - before);
    }

  for (j = 0; j < vec_len (cum_times); j++)
    fformat (stdout, "Cum time for %d: %.4f (us)\n", (j + 1) * 1000,
	     cum_times[j] * 1e6);

  return 0;
}

static clib_error_t *
test_bihash (test_main_t * tm)
{
  int i, j;
  uword *p;
  uword total_searches;
  f64 before, delta;
  BVT (clib_bihash) * h;
  BVT (clib_bihash_kv) kv;

  h = &tm->hash;

  BV (clib_bihash_init) (h, "test", tm->nbuckets, 3ULL << 30);

  fformat (stdout, "Pick %lld unique %s keys...\n",
	   tm->nitems, tm->non_random_keys ? "non-random" : "random");

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

      BV (clib_bihash_add_del) (h, &kv, 1 /* is_add */ );

      if (tm->verbose > 1)
	{
	  fformat (stdout, "--------------------\n");
	  fformat (stdout, "After adding key %llu value %lld...\n",
		   tm->keys[i], (u64) (i + 1));
	  fformat (stdout, "%U", BV (format_bihash), h,
		   2 /* very verbose */ );
	}
    }

  fformat (stdout, "%U", BV (format_bihash), h, 0 /* very verbose */ );

  fformat (stdout, "Search for items %d times...\n", tm->search_iter);

  before = clib_time_now (&tm->clib_time);

  for (j = 0; j < tm->search_iter; j++)
    {
      for (i = 0; i < tm->nitems; i++)
	{
	  kv.key = tm->keys[i];
	  if (BV (clib_bihash_search) (h, &kv, &kv) < 0)
	    if (BV (clib_bihash_search) (h, &kv, &kv) < 0)
	      clib_warning ("[%d] search for key %lld failed unexpectedly\n",
			    i, tm->keys[i]);
	  if (kv.value != (u64) (i + 1))
	    clib_warning
	      ("[%d] search for key %lld returned %lld, not %lld\n", i,
	       tm->keys, kv.value, (u64) (i + 1));
	}
    }

  delta = clib_time_now (&tm->clib_time) - before;
  total_searches = (uword) tm->search_iter * (uword) tm->nitems;

  if (delta > 0)
    fformat (stdout, "%.f searches per second\n",
	     ((f64) total_searches) / delta);

  fformat (stdout, "%lld searches in %.6f seconds\n", total_searches, delta);

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

  fformat (stdout, "Delete items...\n");

  for (i = 0; i < tm->nitems; i++)
    {
      int j;
      int rv;

      kv.key = tm->keys[i];
      kv.value = (u64) (i + 1);
      rv = BV (clib_bihash_add_del) (h, &kv, 0 /* is_add */ );

      if (rv < 0)
	clib_warning ("delete key %lld not ok but should be", tm->keys[i]);

      if (tm->careful_delete_tests)
	{
	  for (j = 0; j < tm->nitems; j++)
	    {
	      kv.key = tm->keys[j];
	      rv = BV (clib_bihash_search) (h, &kv, &kv);
	      if (j <= i && rv >= 0)
		{
		  clib_warning
		    ("i %d j %d search ok but should not be, value %lld",
		     i, j, kv.value);
		}
	      if (j > i && rv < 0)
		{
		  clib_warning ("i %d j %d search not ok but should be",
				i, j);
		}
	    }
	}
    }

  fformat (stdout, "After deletions, should be empty...\n");

  fformat (stdout, "%U", BV (format_bihash), h, 0 /* very verbose */ );
  return 0;
}

clib_error_t *
test_bihash_cache (test_main_t * tm)
{
  u32 lru;
  BVT (clib_bihash_bucket) _b, *b = &_b;

  BV (clib_bihash_reset_cache) (b);

  fformat (stdout, "Initial LRU config: %U\n", BV (format_bihash_lru), b);

  BV (clib_bihash_update_lru_not_inline) (b, 3);

  fformat (stdout, "use slot 3, LRU config: %U\n", BV (format_bihash_lru), b);

  BV (clib_bihash_update_lru) (b, 1);

  fformat (stdout, "use slot 1 LRU config: %U\n", BV (format_bihash_lru), b);

  lru = BV (clib_bihash_get_lru) (b);

  fformat (stdout, "least-recently-used is %d\n", lru);

  BV (clib_bihash_update_lru) (b, 4);

  fformat (stdout, "use slot 4 LRU config: %U\n", BV (format_bihash_lru), b);

  lru = BV (clib_bihash_get_lru) (b);

  fformat (stdout, "least-recently-used is %d\n", lru);

  return 0;
}

clib_error_t *
test_bihash_main (test_main_t * tm)
{
  unformat_input_t *i = tm->input;
  clib_error_t *error;
  int which = 0;

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
      else if (unformat (i, "vec64"))
	which = 1;
      else if (unformat (i, "cache"))
	which = 2;

      else if (unformat (i, "verbose"))
	tm->verbose = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, i);
    }

  switch (which)
    {
    case 0:
      error = test_bihash (tm);
      break;

    case 1:
      error = test_bihash_vec64 (tm);
      break;

    case 2:
      error = test_bihash_cache (tm);
      break;

    default:
      return clib_error_return (0, "no such test?");
    }

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
  tm->nitems = 5;
  tm->verbose = 1;
  tm->search_iter = 1;
  tm->careful_delete_tests = 0;
  tm->key_hash = hash_create (0, sizeof (uword));
  clib_time_init (&tm->clib_time);

  unformat_init_command_line (&i, argv);
  error = test_bihash_main (tm);
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
