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

__thread int thread_id = 0;

#include <vppinfra/time.h>
#include <vppinfra/cache.h>
#include <vppinfra/error.h>
#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/pool.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/cache.h>

#define os_get_cpu_number() (thread_id)

#include <vppinfra/cuckoo_8_8.h>
#include <vppinfra/cuckoo_template.h>
#include <vppinfra/cuckoo_template.c>

#include <vppinfra/bihash_8_8.h>
#include <vppinfra/bihash_template.h>
#include <vppinfra/bihash_template.c>

#include <pthread.h>

#define MAX_THREADS 255

typedef struct
{
  void *tm;
  int thread_idx;
  u64 nlookups;
} thread_data_t;

typedef struct
{
  u64 deadline;
  u64 seed;
  u32 nbuckets;
  u32 nitems;
  u32 runtime;
  int verbose;
  int non_random_keys;
  int nthreads;
  int search_iter;
  uword *key_hash;
  u64 *keys;
    CVT (clib_cuckoo) ch;
    BVT (clib_bihash) bh;
  clib_time_t clib_time;
  u64 *key_add_del_sequence;
  u8 *key_op_sequence;
  u64 *key_search_sequence[MAX_THREADS];
  unformat_input_t *input;
  u64 nadds;
  u64 ndels;
  pthread_t bwriter_thread;
  pthread_t breader_threads[MAX_THREADS];
  pthread_t cwriter_thread;
  pthread_t creader_threads[MAX_THREADS];
  thread_data_t wthread_data;
  thread_data_t rthread_data[MAX_THREADS];
} test_main_t;

test_main_t test_main;

uword
vl (void *v)
{
  return vec_len (v);
}

#define w_thread(x, guts)                                               \
  void *x##writer_thread (void *v)                                      \
  {                                                                     \
    test_main_t *tm = v;                                                \
    uword counter = 0;                                                  \
    u64 nadds = 0;                                                      \
    u64 ndels = 0;                                                      \
    u64 deadline = tm->deadline;                                        \
    do                                                                  \
      {                                                                 \
        for (counter = 0; counter < vec_len (tm->key_add_del_sequence); \
             ++counter)                                                 \
          {                                                             \
            u64 idx = tm->key_add_del_sequence[counter];                \
            u8 op = tm->key_op_sequence[counter];                       \
            if (op)                                                     \
              {                                                         \
                ++nadds;                                                \
              }                                                         \
            else                                                        \
              {                                                         \
                ++ndels;                                                \
              }                                                         \
            guts;                                                       \
            if (clib_cpu_time_now () > deadline)                        \
              {                                                         \
                break;                                                  \
              }                                                         \
          }                                                             \
      }                                                                 \
    while (clib_cpu_time_now () < deadline);                            \
    tm->nadds = nadds;                                                  \
    tm->ndels = ndels;                                                  \
    return NULL;                                                        \
  }

/* *INDENT-OFF* */
w_thread (b, {
  BVT (clib_bihash_kv) kv;
  kv.key = tm->keys[idx];
  kv.value = *hash_get (tm->key_hash, kv.key);
  BV (clib_bihash_add_del) (&tm->bh, &kv, op);
});
/* *INDENT-ON* */

/* *INDENT-OFF* */
w_thread (c, {
  CVT (clib_cuckoo_kv) kv;
  kv.key = tm->keys[idx];
  kv.value = *hash_get (tm->key_hash, kv.key);
  CV (clib_cuckoo_add_del) (&tm->ch, &kv, op);
});
/* *INDENT-ON* */

#define r_thread(x, guts)                                      \
  void *x##reader_thread (void *v)                             \
  {                                                            \
    thread_data_t *data = v;                                   \
    thread_id = data->thread_idx;                              \
    test_main_t *tm = data->tm;                                \
    uword thread_idx = data->thread_idx;                       \
    u64 *idx;                                                  \
    uword nlookups = 0;                                        \
    u64 deadline = tm->deadline;                               \
    do                                                         \
      {                                                        \
        vec_foreach (idx, tm->key_search_sequence[thread_idx]) \
        {                                                      \
          guts;                                                \
          ++nlookups;                                          \
          if (clib_cpu_time_now () > deadline)                 \
            {                                                  \
              break;                                           \
            }                                                  \
        }                                                      \
      }                                                        \
    while (clib_cpu_time_now () < deadline);                   \
    data->nlookups = nlookups;                                 \
    return NULL;                                               \
  }

/* *INDENT-OFF* */
r_thread (c, {
  CVT (clib_cuckoo_kv) kv;
  kv.key = tm->keys[*idx];
  kv.value = *hash_get (tm->key_hash, kv.key);
  CV (clib_cuckoo_search) (&tm->ch, &kv, &kv);
});
/* *INDENT-ON* */

/* *INDENT-OFF* */
r_thread (b, {
  BVT (clib_bihash_kv) kv;
  kv.key = tm->keys[*idx];
  kv.value = *hash_get (tm->key_hash, kv.key);
  BV (clib_bihash_search) (&tm->bh, &kv, &kv);
});
/* *INDENT-ON* */

#define run_threads(x)                                                        \
  do                                                                          \
    {                                                                         \
                                                                              \
      before = clib_time_now (&tm->clib_time);                                \
      tm->deadline = clib_cpu_time_now () +                                   \
                     tm->runtime * tm->clib_time.clocks_per_second;           \
      fformat (stdout, #x "-> Start threads..., runtime is %llu second(s)\n", \
               (long long unsigned)tm->runtime);                              \
                                                                              \
      /*                                                                      \
      fformat (stdout, #x "-> Writer thread only...\n");                      \
      if (0 !=                                                                \
          pthread_create (&tm->x##writer_thread, NULL, x##writer_thread, tm)) \
        {                                                                     \
          perror ("pthread_create()");                                        \
          abort ();                                                           \
        }                                                                     \
                                                                              \
      if (0 != pthread_join (tm->x##writer_thread, NULL))                     \
        {                                                                     \
          perror ("pthread_join()");                                          \
          abort ();                                                           \
        }                                                                     \
                                                                              \
      delta = clib_time_now (&tm->clib_time) - before;                        \
      fformat (stdout, #x "-> %wu adds, %wu dels in %.6f seconds\n",          \
               tm->nadds, tm->ndels, delta);                                  \
      tm->nadds = 0;                                                          \
      tm->ndels = 0;                                                          \
      */                                                                      \
                                                                              \
      fformat (stdout, #x "-> Writer + %d readers\n", tm->nthreads);          \
      before = clib_time_now (&tm->clib_time);                                \
      tm->deadline = clib_cpu_time_now () +                                   \
                     tm->runtime * tm->clib_time.clocks_per_second;           \
      if (0 !=                                                                \
          pthread_create (&tm->x##writer_thread, NULL, x##writer_thread, tm)) \
        {                                                                     \
          perror ("pthread_create()");                                        \
          abort ();                                                           \
        }                                                                     \
                                                                              \
      for (i = 0; i < tm->nthreads; i++)                                      \
        {                                                                     \
          tm->rthread_data[i].nlookups = 0;                                   \
          if (0 != pthread_create (&tm->x##reader_threads[i], NULL,           \
                                   x##reader_thread, &tm->rthread_data[i]))   \
            {                                                                 \
              perror ("pthread_create()");                                    \
              abort ();                                                       \
            }                                                                 \
        }                                                                     \
                                                                              \
      if (0 != pthread_join (tm->x##writer_thread, NULL))                     \
        {                                                                     \
          perror ("pthread_join()");                                          \
          abort ();                                                           \
        }                                                                     \
                                                                              \
      for (i = 0; i < tm->nthreads; i++)                                      \
        {                                                                     \
          if (0 != pthread_join (tm->x##reader_threads[i], NULL))             \
            {                                                                 \
              perror ("pthread_join()");                                      \
              abort ();                                                       \
            }                                                                 \
        }                                                                     \
                                                                              \
      delta = clib_time_now (&tm->clib_time) - before;                        \
                                                                              \
      total_searches = 0;                                                     \
      for (i = 0; i < tm->nthreads; ++i)                                      \
        {                                                                     \
          u64 nlookups = tm->rthread_data[i].nlookups;                        \
          fformat (stdout, #x "-> Thread #%d: %u searches\n", i, nlookups);   \
          total_searches += nlookups;                                         \
        }                                                                     \
                                                                              \
      if (delta > 0)                                                          \
        {                                                                     \
          ops = (tm->nadds + tm->ndels) / (f64)delta;                         \
          fformat (stdout, #x "-> %.f add/dels per second\n", ops);           \
          sps = ((f64)total_searches) / delta;                                \
          fformat (stdout, #x "-> %.f searches per second\n", sps);           \
        }                                                                     \
                                                                              \
      fformat (stdout,                                                        \
               #x "-> %wu adds, %wu dels, %lld searches in %.6f seconds\n",   \
               tm->nadds, tm->ndels, total_searches, delta);                  \
    }                                                                         \
  while (0);

static void
cb (CVT (clib_cuckoo) * h, void *ctx)
{
  fformat (stdout, "Garbage callback called...\n");
}

static clib_error_t *
test_cuckoo_bihash (test_main_t * tm)
{
  int i;
  uword *p;
  uword total_searches;
  f64 before, delta;
  f64 ops = 0, sps = 0;
  f64 bops = 0, bsps = 0;
  f64 cops = 0, csps = 0;
  CVT (clib_cuckoo) * ch;
  BVT (clib_bihash) * bh;

  ch = &tm->ch;
  bh = &tm->bh;

  CV (clib_cuckoo_init) (ch, "test", 1, cb, NULL);
  BV (clib_bihash_init) (bh, (char *) "test", tm->nbuckets, 256 << 20);

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

      int j;
      for (j = 0; j < tm->nthreads; ++j)
	{
	  u64 *x = tm->key_search_sequence[j];
	  vec_add1 (x, random_u64 (&tm->seed) % tm->nitems);
	  tm->key_search_sequence[j] = x;
	}
      vec_add1 (tm->key_add_del_sequence,
		random_u64 (&tm->seed) % tm->nitems);
      vec_add1 (tm->key_op_sequence, (rndkey % 10 < 8) ? 1 : 0);
    }

  int thread_counter = 0;
  tm->wthread_data.tm = tm;
  tm->wthread_data.thread_idx = thread_counter;
  for (i = 0; i < tm->nthreads; ++i)
    {
      tm->rthread_data[i].tm = tm;
      tm->rthread_data[i].thread_idx = thread_counter;
      tm->rthread_data[i].nlookups = 0;
      ++thread_counter;
    }

  int iter;
  for (iter = 0; iter < tm->search_iter; ++iter)
    {
      fformat (stdout, "Bihash test #%d\n", iter);
      run_threads (b);
      bops = ops;
      bsps = sps;
      fformat (stdout, "%U", BV (format_bihash), bh, 0);
      fformat (stdout, "Cuckoo test #%d\n", iter);
      run_threads (c);
      cops = ops;
      csps = sps;
      fformat (stdout, "%U", CV (format_cuckoo), ch, 0);
      fformat (stdout,
	       "Bihash add/del speed is %.2f%% of cuckoo add/del speed\n",
	       bops / cops * 100);
      fformat (stdout,
	       "Bihash search speed is %.2f%% of cuckoo search speed\n",
	       bsps / csps * 100);
    }
  return 0;
}

clib_error_t *
test_cuckoo_bihash_main (test_main_t * tm)
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
      else if (unformat (i, "search_iter %d", &tm->search_iter))
	;
      else if (unformat (i, "verbose %d", &tm->verbose))
	;
      else if (unformat (i, "runtime %d", &tm->runtime))
	;
      else if (unformat (i, "nthreads %d", &tm->nthreads))
	;
      else if (unformat (i, "verbose"))
	tm->verbose = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, i);
    }

  error = test_cuckoo_bihash (tm);

  return error;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  clib_error_t *error;
  test_main_t *tm = &test_main;
  memset (&test_main, 0, sizeof (test_main));

  clib_mem_init (0, 3ULL << 30);

  tm->input = &i;
  tm->seed = 0xdeaddabe;

  tm->nbuckets = 2;
  tm->nitems = 5;
  tm->verbose = 1;
  tm->nthreads = 1;
  clib_time_init (&tm->clib_time);
  tm->runtime = 1;
  tm->search_iter = 1;
  tm->key_hash = hash_create (0, sizeof (uword));

  unformat_init_command_line (&i, argv);
  error = test_cuckoo_bihash_main (tm);
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
