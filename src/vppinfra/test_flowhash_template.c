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

#include <vppinfra/heap.h>
#include <vppinfra/format.h>
#include <vppinfra/random.h>
#include <vppinfra/hash.h>

#include <vppinfra/flowhash_8_8.h>

/* Not actually tested here. But included for compilation purposes. */
#include <vppinfra/flowhash_24_16.h>

typedef struct
{
  u64 seed;
  u32 fixed_entries;
  u32 collision_buckets;
  u32 nitems;
  u32 iterations;
  u32 prefetch;
  int non_random_keys;
  uword *key_hash;
  flowhash_lkey_8_8_t *keys;
  flowhash_8_8_t *hash;
  clib_time_t clib_time;
  unformat_input_t *input;
} test_main_t;

test_main_t test_main;

static clib_error_t *
test_flowhash (test_main_t * tm)
{
  f64 before, delta;
  u64 total;
  u32 overflow;
  int i, j;
  uword *p;
  tm->hash = flowhash_alloc_8_8 (tm->fixed_entries, tm->collision_buckets);
  if (tm->hash == NULL)
    return clib_error_return (0, "Could not alloc hash");

  fformat (stdout, "Allocated hash memory size: %llu\n",
	   flowhash_memory_size (tm->hash));

  fformat (stdout, "Pick %lld unique %s keys...\n",
	   tm->nitems, tm->non_random_keys ? "non-random" : "random");

  for (i = 0; i < tm->nitems; i++)
    {
      flowhash_lkey_8_8_t rndkey;
      if (tm->non_random_keys == 0)
	{
	again:
	  rndkey.as_u64[0] = random_u64 (&tm->seed);
	  if ((p = hash_get (tm->key_hash, rndkey.as_u64[0])))
	    goto again;
	}
      else
	rndkey.as_u64[0] = (u64) (i + 1) << 16;

      hash_set (tm->key_hash, rndkey.as_u64[0], i + 1);
      vec_add1 (tm->keys, rndkey);
    }

  hash_free (tm->key_hash);

  /* Additions */
  overflow = 0;
  before = clib_time_now (&tm->clib_time);
  fformat (stdout, "Adding %u items...\n", tm->nitems);
  for (i = 0; i < tm->nitems; i++)
    {
      u32 hash = flowhash_hash_8_8 (&tm->keys[i]);
      u32 ei;
      flowhash_get_8_8 (tm->hash, &tm->keys[i], hash, 1, &ei);
      if (flowhash_is_overflow (ei))
	overflow++;

      /* Set value (No matter if success) */
      flowhash_value (tm->hash, ei)->as_u64[0] = i + 1;

      /* Save value until time > 1 */
      flowhash_timeout (tm->hash, ei) = 1;
    }

  delta = clib_time_now (&tm->clib_time) - before;
  total = tm->nitems;
  fformat (stdout, "%lld additions in %.6f seconds\n", total, delta);
  if (delta > 0)
    fformat (stdout, "%.f additions per second\n", ((f64) total) / delta);

  fformat (stdout, "%u elements in table\n", flowhash_elts_8_8 (tm->hash, 1));
  fformat (stdout, "Flowhash counters:\n");
  fformat (stdout, "  collision-lookup: %lu\n",
	   tm->hash->collision_lookup_counter);
  fformat (stdout, "  not-enough-buckets: %lu\n",
	   tm->hash->not_enough_buckets_counter);
  fformat (stdout, "  overflows: %lu\n", overflow);

  /* Lookups (very similar to additions) */
  overflow = 0;
  before = clib_time_now (&tm->clib_time);
  fformat (stdout, "Looking up %u items %u times...\n", tm->nitems,
	   tm->iterations);

  for (j = 0; j < tm->iterations; j++)
    {
      i = 0;
      if (tm->prefetch)
	for (; i < tm->nitems - tm->prefetch; i++)
	  {
	    u32 ei;
	    u32 hash = flowhash_hash_8_8 (&tm->keys[i + tm->prefetch]);
	    flowhash_prefetch (tm->hash, hash);
	    hash = flowhash_hash_8_8 (&tm->keys[i]);
	    flowhash_get_8_8 (tm->hash, &tm->keys[i], hash, 1, &ei);
	    if (flowhash_is_overflow (ei))
	      overflow++;
	    else if (flowhash_timeout (tm->hash, ei) != 1)
	      clib_warning ("Key not found: %lld\n", tm->keys[i].as_u64[0]);
	    else if (flowhash_value (tm->hash, ei)->as_u64[0] != i + 1)
	      clib_warning ("Value mismatch for key %lld\n",
			    tm->keys[i].as_u64[0]);
	  }

      for (; i < tm->nitems; i++)
	{
	  u32 ei;
	  u32 hash = flowhash_hash_8_8 (&tm->keys[i]);
	  flowhash_get_8_8 (tm->hash, &tm->keys[i], hash, 1, &ei);
	  if (flowhash_is_overflow (ei))
	    overflow++;
	  else if (flowhash_timeout (tm->hash, ei) != 1)
	    clib_warning ("Key not found: %lld\n", tm->keys[i].as_u64[0]);
	  else if (flowhash_value (tm->hash, ei)->as_u64[0] != i + 1)
	    clib_warning ("Value mismatch for key %lld\n",
			  tm->keys[i].as_u64[0]);
	}
    }

  delta = clib_time_now (&tm->clib_time) - before;
  total = tm->nitems * tm->iterations;
  fformat (stdout, "%lld lookups in %.6f seconds\n", total, delta);
  if (delta > 0)
    fformat (stdout, "%.f lookups per second\n", ((f64) total) / delta);

  /* Delete */
  for (i = 0; i < tm->nitems; i++)
    {
      u32 hash = flowhash_hash_8_8 (&tm->keys[i]);
      u32 ei;
      flowhash_get_8_8 (tm->hash, &tm->keys[i], hash, 1, &ei);
      flowhash_timeout (tm->hash, ei) = 0;
    }

  fformat (stdout, "%u elements in table\n", flowhash_elts_8_8 (tm->hash, 1));

  vec_free (tm->keys);
  flowhash_free_8_8 (tm->hash);

  return NULL;
}

clib_error_t *
test_flowhash_main (test_main_t * tm)
{
  unformat_input_t *i = tm->input;
  clib_error_t *error;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "seed %u", &tm->seed))
	;
      else if (unformat (i, "fixed-entries %d", &tm->fixed_entries))
	;
      else if (unformat (i, "collision-buckets %d", &tm->collision_buckets))
	;
      else if (unformat (i, "non-random-keys"))
	tm->non_random_keys = 1;
      else if (unformat (i, "nitems %d", &tm->nitems))
	;
      else if (unformat (i, "prefetch %d", &tm->prefetch))
	;
      else if (unformat (i, "iterations %d", &tm->iterations))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, i);
    }

  error = test_flowhash (tm);
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

  tm->fixed_entries = 8 << 20;
  tm->collision_buckets = 1 << 20;
  tm->seed = 0xdeadf00l;
  tm->iterations = 1;
  tm->input = &i;
  tm->nitems = 1000;
  tm->non_random_keys = 0;
  tm->key_hash = hash_create (0, sizeof (uword));
  tm->prefetch = 0;
  clib_time_init (&tm->clib_time);

  unformat_init_command_line (&i, argv);
  error = test_flowhash_main (tm);
  unformat_free (&i);

  if (error)
    {
      clib_error_report (error);
      return 1;
    }
  return 0;

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
