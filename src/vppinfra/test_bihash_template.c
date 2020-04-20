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
  u32 noverwritten;
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

#if BIHASH_32_64_SVM
  BV (clib_bihash_master_init_svm) (h, "test", user_buckets,
				    0x30000000 /* base_addr */ ,
				    user_memory_size);
#else
  BV (clib_bihash_init) (h, "test", user_buckets, user_memory_size);
#endif

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

static int
stale_cb (BVT (clib_bihash_kv) * kv, void *ctx)
{
  test_main_t *tm = ctx;

  tm->noverwritten++;

  return 1;
}

static clib_error_t *
test_bihash_stale_overwrite (test_main_t * tm)
{
  BVT (clib_bihash) * h;
  BVT (clib_bihash_kv) kv;
  int i;
  tm->noverwritten = 0;

  h = &tm->hash;

#if BIHASH_32_64_SVM
  BV (clib_bihash_master_init_svm) (h, "test", tm->nbuckets,
				    0x30000000 /* base_addr */ ,
				    tm->hash_memory_size);
#else
  BV (clib_bihash_init) (h, "test", tm->nbuckets, tm->hash_memory_size);
#endif

  fformat (stdout, "Add %d items to %d buckets\n", tm->nitems, tm->nbuckets);

  for (i = 0; i < tm->nitems; i++)
    {
      kv.key = i;
      kv.value = 1;

      BV (clib_bihash_add_or_overwrite_stale) (h, &kv, stale_cb, tm);
    }

  fformat (stdout, "%d items overwritten\n", tm->noverwritten);
  fformat (stdout, "%U", BV (format_bihash), h, 0);

  return 0;
}

void *
test_bihash_thread_fn (void *arg)
{
  BVT (clib_bihash) * h;
  BVT (clib_bihash_kv) kv;
  test_main_t *tm = &test_main;

  int i, j;

  u32 my_thread_index = (u32) (u64) arg;
  __os_thread_index = my_thread_index;
  clib_mem_set_per_cpu_heap (tm->global_heap);

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
  while (1)
    {
      struct timespec ts, tsrem;
      ts.tv_sec = 1;
      ts.tv_nsec = 0;

      while (nanosleep (&ts, &tsrem) < 0)
	ts = tsrem;
    }
  return (0);			/* not so much */
}

static clib_error_t *
test_bihash_threads (test_main_t * tm)
{
  int i;
  pthread_t handle;
  BVT (clib_bihash) * h;
  int rv;

  h = &tm->hash;

#if BIHASH_32_64_SVM
  BV (clib_bihash_master_init_svm) (h, "test", tm->nbuckets,
				    0x30000000 /* base_addr */ ,
				    tm->hash_memory_size);
#else
  BV (clib_bihash_init) (h, "test", tm->nbuckets, tm->hash_memory_size);
#endif

  tm->thread_barrier = 1;

  /* Start the worker threads */
  for (i = 0; i < tm->nthreads; i++)
    {
      rv = pthread_create (&handle, NULL, test_bihash_thread_fn,
			   (void *) (u64) i);
      if (rv)
	{
	  clib_unix_warning ("pthread_create returned %d", rv);
	}
    }
  tm->threads_running = i;
  tm->sequence_number = 0;
  CLIB_MEMORY_BARRIER ();

  /* start the workers */
  tm->thread_barrier = 0;

  while (tm->threads_running)
    {
      struct timespec ts, tsrem;
      ts.tv_sec = 0;
      ts.tv_nsec = 20 * 1000 * 1000;	/* sleep for 20ms at a time */

      while (nanosleep (&ts, &tsrem) < 0)
	ts = tsrem;
    }

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
  u32 acycle;

  h = &tm->hash;

#if BIHASH_32_64_SVM
  BV (clib_bihash_master_init_svm) (h, "test", tm->nbuckets,
				    0x30000000 /* base_addr */ ,
				    tm->hash_memory_size);
#else
  BV (clib_bihash_init) (h, "test", tm->nbuckets, tm->hash_memory_size);
#endif

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
	      /* Prefetch buckets 8 iterations ahead */
	      if (1 && (i < (tm->nitems - 8)))
		{
		  BVT (clib_bihash_kv) pref_kv;
		  u64 pref_hash;
		  pref_kv.key = tm->keys[i + 8];
		  pref_hash = BV (clib_bihash_hash) (&pref_kv);
		  BV (clib_bihash_prefetch_bucket) (h, pref_hash);
		}

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
	    fformat (stdout,
		     "%.f searches per second, %.2f nsec per search\n",
		     ((f64) total_searches) / delta,
		     1e9 * (delta / ((f64) total_searches)));

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
		  /* Prefetch buckets 8 iterations ahead */
		  if (1 && (j < (tm->nitems - 8)))
		    {
		      BVT (clib_bihash_kv) pref_kv;
		      u64 pref_hash;
		      pref_kv.key = tm->keys[j + 8];
		      pref_hash = BV (clib_bihash_hash) (&pref_kv);
		      BV (clib_bihash_prefetch_bucket) (h, pref_hash);
		    }

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

  BV (clib_bihash_free) (h);

  return 0;
}

clib_error_t *
test_bihash_main (test_main_t * tm)
{
  unformat_input_t *i = tm->input;
  clib_error_t *error;
  int which = 0;

  tm->report_every_n = 1;
  tm->hash_memory_size = 1ULL << 30;

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
      else if (unformat (i, "ncycles %d", &tm->ncycles))
	;
      else if (unformat (i, "careful %d", &tm->careful_delete_tests))
	;
      else if (unformat (i, "verbose %d", &tm->verbose))
	;
      else if (unformat (i, "search %d", &tm->search_iter))
	;
      else if (unformat (i, "report-every %d", &tm->report_every_n))
	;
      else if (unformat (i, "memory-size %U",
			 unformat_memory_size, &tm->hash_memory_size))
	;
      else if (unformat (i, "vec64"))
	which = 1;
      else if (unformat (i, "threads %u", &tm->nthreads))
	which = 2;
      else if (unformat (i, "verbose"))
	tm->verbose = 1;
      else if (unformat (i, "stale-overwrite"))
	which = 3;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, i);
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

    case 3:
      error = test_bihash_stale_overwrite (tm);
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

  clib_mem_init (0, 4095ULL << 20);

  tm->global_heap = clib_mem_get_per_cpu_heap ();

  tm->input = &i;
  tm->seed = 0xdeaddabe;

  tm->nbuckets = 2;
  tm->nitems = 5;
  tm->ncycles = 1;
  tm->verbose = 1;
  tm->search_iter = 1;
  tm->careful_delete_tests = 0;
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
