/*
  Copyright (c) 2013 Cisco and/or its affiliates.

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

#include <vppinfra/pfhash.h>
#include <vppinfra/format.h>
#include <vppinfra/random.h>

#if defined(CLIB_HAVE_VEC128) && ! defined (__ALTIVEC__)

int verbose = 0;

always_inline u8 *
random_aligned_string (u32 * seed, uword len)
{
  u8 *alphabet = (u8 *) "abcdefghijklmnopqrstuvwxyz";
  u8 *s = 0;
  word i;

  vec_resize_aligned (s, len, 16);
  for (i = 0; i < len; i++)
    s[i] = alphabet[random_u32 (seed) % 26];

  return s;
}

void exit (int);

int
test_pfhash_main (unformat_input_t * input)
{
  u32 seed = 0xdeaddabe;
  int i, iter;
  u32 nkeys = 4;
  u32 niter = 1;
  u32 nbuckets = 1;
  u32 bucket;
  u32 sizes[3] = { 16, 8, 4 }, this_size, size;
  u8 **keys = 0;
  pfhash_t _rec, *p = &_rec;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "seed %d", &seed))
	;
      else if (unformat (input, "niter %d", &niter))
	;
      else if (unformat (input, "nkeys %d", &nkeys))
	;
      else if (unformat (input, "nbuckets %d", &nbuckets))
	;
      else if (unformat (input, "verbose %d", &verbose))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else
	clib_error ("unknown input `%U'", format_unformat_error, input);
    }

  vec_validate (keys, nkeys - 1);

  for (i = 0; i < nkeys; i++)
    {
      int j, k;

    again:
      keys[i] = random_aligned_string (&seed, 16);
      for (j = 0; j < (i - 1); j++)
	{
	  /* Make sure we don't have a dup key in the min key size */
	  for (k = 0; k < 4; k++)
	    {
	      if (keys[i][k] != keys[j][k])
		goto check_next_key;
	    }
	  vec_free (keys[i]);
	  goto again;
	check_next_key:
	  ;
	}
    }

  /* test 8 byte key, 8 byte value case separately */

  for (size = 8; size < 9; size++)
    {
      this_size = 8;

      fformat (stdout, "%d-byte key 8 byte value test\n", this_size);

      pfhash_init (p, "test", 8 /* key size */ , 8 /* value size */ ,
		   nbuckets + 1);

      for (iter = 0; iter < niter; iter++)
	{
	  bucket = 0;
	  for (i = 0; i < nkeys; i++)
	    {
	      bucket = (i % nbuckets) + 1;
	      pfhash_set (p, bucket, keys[i],
			  (void *) (u64) 0x100000000ULL + i + 1);
	    }

	  for (i = 0; i < nkeys; i++)
	    {
	      bucket = (i % nbuckets) + 1;
	      if (pfhash_get (p, bucket, keys[i])
		  != (u64) 0x100000000ULL + i + 1)
		{
		  clib_warning ("key %d bucket %d lookup FAIL\n", i, bucket);
		  (void) pfhash_get (p, bucket, keys[i]);
		}
	    }

	  /* test inline functions */
	  for (i = 0; i < nkeys; i++)
	    {
	      u32 bucket_contents;
	      u64 value = 0xdeadbeef;
	      bucket = (i % nbuckets) + 1;

	      pfhash_prefetch_bucket (p, bucket);
	      bucket_contents = pfhash_read_bucket_prefetch_kv (p, bucket);

	      value = pfhash_search_kv_8v8 (p, bucket_contents,
					    (u64 *) keys[i]);
	      if (value != (u64) 0x100000000ULL + i + 1)
		clib_warning ("key %d bucket %d lookup FAIL\n", i, bucket);
	    }

	  if (verbose)
	    fformat (stdout, "%U\n", format_pfhash, p, verbose > 1);

	  for (i = 0; i < nkeys; i++)
	    {
	      bucket = (i % nbuckets) + 1;
	      pfhash_unset (p, bucket, keys[i]);
	    }

	  for (i = 0; i < nkeys; i++)
	    {
	      bucket = (i % nbuckets) + 1;
	      if (pfhash_get (p, bucket, keys[i]) != (u64) ~ 0)
		{
		  clib_warning ("key %d bucket %d lookup FAIL\n", i, bucket);
		  (void) pfhash_get (p, bucket, keys[i]);
		}
	    }
	  /* test inline functions */
	  for (i = 0; i < nkeys; i++)
	    {
	      u32 bucket_contents;
	      u64 value = 0xdeadbeef;
	      bucket = (i % nbuckets) + 1;

	      pfhash_prefetch_bucket (p, bucket);
	      bucket_contents = pfhash_read_bucket_prefetch_kv (p, bucket);

	      value = pfhash_search_kv_8v8 (p, bucket_contents,
					    (u64 *) keys[i]);

	      if (value != (u64) ~ 0)
		clib_warning ("key %d bucket %d lookup FAIL\n", i, bucket);
	    }
	}
      pfhash_free (p);
    }

  /* test other cases */

  for (size = 0; size < ARRAY_LEN (sizes); size++)
    {
      this_size = sizes[size];

      fformat (stdout, "%d-byte key test\n", this_size);

      pfhash_init (p, "test", this_size, 4 /* value size */ , nbuckets + 1);

      for (iter = 0; iter < niter; iter++)
	{
	  bucket = 0;
	  for (i = 0; i < nkeys; i++)
	    {
	      bucket = (i % nbuckets) + 1;
	      pfhash_set (p, bucket, keys[i], (void *) (u64) i + 1);
	    }

	  for (i = 0; i < nkeys; i++)
	    {
	      bucket = (i % nbuckets) + 1;
	      if (pfhash_get (p, bucket, keys[i]) != i + 1)
		{
		  clib_warning ("key %d bucket %d lookup FAIL\n", i, bucket);
		  (void) pfhash_get (p, bucket, keys[i]);
		}
	    }

	  /* test inline functions */
	  for (i = 0; i < nkeys; i++)
	    {
	      u32 bucket_contents;
	      u32 value = 0xdeadbeef;
	      bucket = (i % nbuckets) + 1;

	      pfhash_prefetch_bucket (p, bucket);
	      bucket_contents = pfhash_read_bucket_prefetch_kv (p, bucket);
	      switch (p->key_size)
		{
		case 16:
		  value =
		    pfhash_search_kv_16 (p, bucket_contents,
					 (u32x4 *) keys[i]);
		  break;
		case 8:
		  value =
		    pfhash_search_kv_8 (p, bucket_contents, (u64 *) keys[i]);
		  break;
		case 4:
		  value =
		    pfhash_search_kv_4 (p, bucket_contents, (u32 *) keys[i]);
		  break;
		}

	      if (value != (i + 1))
		clib_warning ("key %d bucket %d lookup FAIL\n", i, bucket);
	    }

	  if (verbose)
	    fformat (stdout, "%U\n", format_pfhash, p, verbose > 1);

	  for (i = 0; i < nkeys; i++)
	    {
	      bucket = (i % nbuckets) + 1;
	      pfhash_unset (p, bucket, keys[i]);
	    }

	  for (i = 0; i < nkeys; i++)
	    {
	      bucket = (i % nbuckets) + 1;
	      if (pfhash_get (p, bucket, keys[i]) != (u64) ~ 0)
		{
		  clib_warning ("key %d bucket %d lookup FAIL\n", i, bucket);
		  (void) pfhash_get (p, bucket, keys[i]);
		}
	    }
	  /* test inline functions */
	  for (i = 0; i < nkeys; i++)
	    {
	      u32 bucket_contents;
	      u32 value = 0xdeadbeef;
	      bucket = (i % nbuckets) + 1;

	      pfhash_prefetch_bucket (p, bucket);
	      bucket_contents = pfhash_read_bucket_prefetch_kv (p, bucket);
	      switch (p->key_size)
		{
		case 16:
		  value =
		    pfhash_search_kv_16 (p, bucket_contents,
					 (u32x4 *) keys[i]);
		  break;
		case 8:
		  value =
		    pfhash_search_kv_8 (p, bucket_contents, (u64 *) keys[i]);
		  break;
		case 4:
		  value =
		    pfhash_search_kv_4 (p, bucket_contents, (u32 *) keys[i]);
		  break;
		}
	      if (value != (u32) ~ 0)
		clib_warning ("key %d bucket %d lookup FAIL\n", i, bucket);
	    }
	}
      pfhash_free (p);
    }

  exit (0);
}
#else
int
test_pfhash_main (unformat_input_t * input)
{
  clib_warning ("MMX unit not available");
  return 0;
}
#endif

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  unformat_init_command_line (&i, argv);
  ret = test_pfhash_main (&i);
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
