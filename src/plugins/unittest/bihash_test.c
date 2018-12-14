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
#include <vlib/vlib.h>
#include <vppinfra/time.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>
#include <sys/resource.h>
#include <stdio.h>
#include <pthread.h>

#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_template.h>

#include <vppinfra/bihash_template.c>

typedef struct
{
  volatile u32 thread_barrier;
  volatile u32 threads_running;
  volatile u64 sequence_number;
  u64 seed;
  u32 nbuckets;
  u32 nitems;
  u32 ncycles;
  u32 report_every_n;
  u32 search_iter;
  int careful_delete_tests;
  int verbose;
  int non_random_keys;
  u32 nthreads;
  uword *key_hash;
  u64 *keys;
  uword hash_memory_size;
    BVT (clib_bihash) hash;
  clib_time_t clib_time;
  void *global_heap;

  unformat_input_t *input;

  /* convenience */
  vlib_main_t *vlib_main;
} bihash_test_main_t;

static bihash_test_main_t bihash_test_main;

static clib_error_t *
test_bihash_vec64 (bihash_test_main_t * tm)
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

void *
test_bihash_thread_fn (void *arg)
{
  BVT (clib_bihash) * h;
  BVT (clib_bihash_kv) kv;
  bihash_test_main_t *tm = &bihash_test_main;
  int i, j;
  u32 my_thread_index = (uword) arg;

  while (tm->thread_barrier)
    ;

  h = &tm->hash;

  for (i = 0; i < tm->ncycles; i++)
    {
      for (j = 0; j < tm->nitems; j++)
	{
	  kv.key = ((u64) my_thread_index << 32) | (u64) j;
	  kv.value = ((u64) my_thread_index << 32) | (u64) j;
	  (void) __atomic_add_fetch (&tm->sequence_number, 1,
				     __ATOMIC_ACQUIRE);
	  BV (clib_bihash_add_del) (h, &kv, 1 /* is_add */ );
	}
      for (j = 0; j < tm->nitems; j++)
	{
	  kv.key = ((u64) my_thread_index << 32) | (u64) j;
	  kv.value = ((u64) my_thread_index << 32) | (u64) j;
	  (void) __atomic_add_fetch (&tm->sequence_number, 1,
				     __ATOMIC_ACQUIRE);
	  BV (clib_bihash_add_del) (h, &kv, 0 /* is_add */ );
	}
    }

  (void) __atomic_sub_fetch (&tm->threads_running, 1, __ATOMIC_ACQUIRE);
  pthread_exit (0);
  return (0);			/* not so much */
}

static clib_error_t *
test_bihash_threads (bihash_test_main_t * tm)
{
  int i;
  pthread_t handle;
  BVT (clib_bihash) * h;
  int rv;
  f64 before, after, delta;

  h = &tm->hash;

  BV (clib_bihash_init) (h, "test", tm->nbuckets, tm->hash_memory_size);

  tm->thread_barrier = 1;

  /* Start the worker threads */
  for (i = 0; i < tm->nthreads; i++)
    {
      rv = pthread_create (&handle, NULL, test_bihash_thread_fn,
			   (void *) (uword) i);
      if (rv)
	{
	  clib_unix_warning ("pthread_create returned %d", rv);
	}
    }
  tm->threads_running = i;
  tm->sequence_number = 0;
  CLIB_MEMORY_BARRIER ();

  /* start the workers */
  before = vlib_time_now (tm->vlib_main);
  tm->thread_barrier = 0;

  while (tm->threads_running > 0)
    CLIB_PAUSE ();

  after = vlib_time_now (tm->vlib_main);
  delta = after - before;

  clib_warning ("%lld items in %.2f seconds, %.2f items/sec",
		(u64) tm->nthreads * (u64) tm->nitems, delta,
		delta >
		0.0 ? ((f64) ((u64) tm->nthreads * (u64) tm->nitems)) /
		delta : 0.0);

  BV (clib_bihash_free) (h);
  return 0;
}

/*
 * Callback to blow up spectacularly if anthing remains in the table
 */
static void
count_items (BVT (clib_bihash_kv) * kvp, void *notused)
{
  _clib_error (CLIB_ERROR_ABORT, 0, 0,
	       "bihash test FAILED, items left in table!");
}

static clib_error_t *
test_bihash (bihash_test_main_t * tm)
{
  int i, j;
  uword *p;
  uword total_searches;
  f64 before, delta;
  BVT (clib_bihash) * h;
  BVT (clib_bihash_kv) kv;
  u32 acycle;

  h = &tm->hash;

  BV (clib_bihash_init) (h, "test", tm->nbuckets, tm->hash_memory_size);

  for (acycle = 0; acycle < tm->ncycles; acycle++)
    {
      if ((acycle % tm->report_every_n) == 0)
	{
	  fformat (stdout, "Cycle %lld out of %lld...\n",
		   acycle, tm->ncycles);

	  fformat (stdout, "Pick %lld unique %s keys...\n",
		   tm->nitems, tm->non_random_keys ? "non-random" : "random");
	}

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
	  rndkey += acycle;

	  hash_set (tm->key_hash, rndkey, i + 1);
	  vec_add1 (tm->keys, rndkey);
	}


      if ((acycle % tm->report_every_n) == 0)
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

      if ((acycle % tm->report_every_n) == 0)
	{
	  fformat (stdout, "%U", BV (format_bihash), h,
		   0 /* very verbose */ );

	  fformat (stdout, "Search for items %d times...\n", tm->search_iter);
	}

      before = clib_time_now (&tm->clib_time);

      for (j = 0; j < tm->search_iter; j++)
	{
	  for (i = 0; i < tm->nitems; i++)
	    {
	      kv.key = tm->keys[i];
	      if (BV (clib_bihash_search) (h, &kv, &kv) < 0)
		if (BV (clib_bihash_search) (h, &kv, &kv) < 0)
		  clib_warning
		    ("[%d] search for key %lld failed unexpectedly\n", i,
		     tm->keys[i]);
	      if (kv.value != (u64) (i + 1))
		clib_warning
		  ("[%d] search for key %lld returned %lld, not %lld\n", i,
		   tm->keys, kv.value, (u64) (i + 1));
	    }
	}

      if ((acycle % tm->report_every_n) == 0)
	{
	  delta = clib_time_now (&tm->clib_time) - before;
	  total_searches = (uword) tm->search_iter * (uword) tm->nitems;

	  if (delta > 0)
	    fformat (stdout, "%.f searches per second\n",
		     ((f64) total_searches) / delta);

	  fformat (stdout, "%lld searches in %.6f seconds\n", total_searches,
		   delta);

	  fformat (stdout, "Standard E-hash search for items %d times...\n",
		   tm->search_iter);
	}

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

      if ((acycle % tm->report_every_n) == 0)
	{
	  fformat (stdout, "%lld searches in %.6f seconds\n",
		   total_searches, delta);

	  if (delta > 0)
	    fformat (stdout, "%.f searches per second\n",
		     ((f64) total_searches) / delta);
	  fformat (stdout, "Delete items...\n");
	}

      for (i = 0; i < tm->nitems; i++)
	{
	  int j;
	  int rv;

	  kv.key = tm->keys[i];
	  kv.value = (u64) (i + 1);
	  rv = BV (clib_bihash_add_del) (h, &kv, 0 /* is_add */ );

	  if (rv < 0)
	    clib_warning ("delete key %lld not ok but should be",
			  tm->keys[i]);

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
      if ((acycle % tm->report_every_n) == 0)
	{
	  struct rusage r_usage;
	  getrusage (RUSAGE_SELF, &r_usage);
	  fformat (stdout, "Kernel RSS: %ld bytes\n", r_usage.ru_maxrss);
	  fformat (stdout, "%U\n", BV (format_bihash), h, 0 /* verbose */ );
	}

      /* Clean up side-bet hash table and random key vector */
      hash_free (tm->key_hash);
      vec_reset_length (tm->keys);
      /* Recreate hash table if we're going to need it again */
      if (acycle != (tm->ncycles - 1))
	tm->key_hash = hash_create (tm->nitems, sizeof (uword));
    }

  fformat (stdout, "End of run, should be empty...\n");

  fformat (stdout, "%U", BV (format_bihash), h, 0 /* very verbose */ );

  /* ASSERTs if any items remain */
  BV (clib_bihash_foreach_key_value_pair) (h, count_items, 0);

  BV (clib_bihash_free) (h);

  vec_free (tm->keys);
  hash_free (tm->key_hash);

  return 0;
}

static clib_error_t *
test_bihash_command_fn (vlib_main_t * vm,
			unformat_input_t * input, vlib_cli_command_t * cmd)
{
  bihash_test_main_t *tm = &bihash_test_main;
  clib_error_t *error;
  int which = 0;

  tm->hash_memory_size = 32ULL << 20;
  tm->nbuckets = 32000;
  tm->nitems = 100000;
  tm->ncycles = 10;
  tm->report_every_n = 50000;
  tm->seed = 0x1badf00d;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "seed %u", &tm->seed))
	;

      else if (unformat (input, "nbuckets %d", &tm->nbuckets))
	;
      else if (unformat (input, "non-random-keys"))
	tm->non_random_keys = 1;
      else if (unformat (input, "nitems %d", &tm->nitems))
	;
      else if (unformat (input, "ncycles %d", &tm->ncycles))
	;
      else if (unformat (input, "careful %d", &tm->careful_delete_tests))
	;
      else if (unformat (input, "verbose %d", &tm->verbose))
	;
      else if (unformat (input, "search %d", &tm->search_iter))
	;
      else if (unformat (input, "report-every %d", &tm->report_every_n))
	;
      else if (unformat (input, "memory-size %U",
			 unformat_memory_size, &tm->hash_memory_size))
	;
      else if (unformat (input, "vec64"))
	which = 1;
      else if (unformat (input, "threads %u", &tm->nthreads))
	which = 2;
      else if (unformat (input, "verbose"))
	tm->verbose = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  /* Preallocate hash table, key vector */
  tm->key_hash = hash_create (tm->nitems, sizeof (uword));
  vec_validate (tm->keys, tm->nitems - 1);
  _vec_len (tm->keys) = 0;

  switch (which)
    {
    case 0:
      error = test_bihash (tm);
      break;

    case 1:
      error = test_bihash_vec64 (tm);
      break;

    case 2:
      error = test_bihash_threads (tm);
      break;

    default:
      return clib_error_return (0, "no such test?");
    }

  return error;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_bihash_command, static) =
{
  .path = "test bihash",
  .short_help = "test bihash",
  .function = test_bihash_command_fn,
};
/* *INDENT-ON* */

static clib_error_t *
bihash_test_init (vlib_main_t * vm)
{
  bihash_test_main_t *tm = &bihash_test_main;

  tm->vlib_main = vm;
  return (0);
}

VLIB_INIT_FUNCTION (bihash_test_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
