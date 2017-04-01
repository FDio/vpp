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

#include <vppinfra/elog.h>
#include <vppinfra/error.h>
#include <vppinfra/format.h>
#include <vppinfra/random.h>
#include <vppinfra/serialize.h>
#include <vppinfra/unix.h>

int
test_elog_main (unformat_input_t * input)
{
  clib_error_t *error = 0;
  u32 i, n_iter, seed, max_events;
  elog_main_t _em, *em = &_em;
  u32 verbose;
  f64 min_sample_time;
  char *dump_file, *load_file, *merge_file, **merge_files;
  u8 *tag, **tags;
  f64 align_tweak;
  f64 *align_tweaks;

  n_iter = 100;
  max_events = 100000;
  seed = 1;
  verbose = 0;
  dump_file = 0;
  load_file = 0;
  merge_files = 0;
  tags = 0;
  align_tweaks = 0;
  min_sample_time = 2;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "iter %d", &n_iter))
	;
      else if (unformat (input, "seed %d", &seed))
	;
      else if (unformat (input, "dump %s", &dump_file))
	;
      else if (unformat (input, "load %s", &load_file))
	;
      else if (unformat (input, "tag %s", &tag))
	vec_add1 (tags, tag);
      else if (unformat (input, "merge %s", &merge_file))
	vec_add1 (merge_files, merge_file);

      else if (unformat (input, "verbose %=", &verbose, 1))
	;
      else if (unformat (input, "max-events %d", &max_events))
	;
      else if (unformat (input, "sample-time %f", &min_sample_time))
	;
      else if (unformat (input, "align-tweak %f", &align_tweak))
	vec_add1 (align_tweaks, align_tweak);
      else
	{
	  error = clib_error_create ("unknown input `%U'\n",
				     format_unformat_error, input);
	  goto done;
	}
    }

#ifdef CLIB_UNIX
  if (load_file)
    {
      if ((error = elog_read_file (em, load_file)))
	goto done;
    }

  else if (merge_files)
    {
      uword i;
      elog_main_t *ems;
      vec_clone (ems, merge_files);

      /* Supply default tags as needed */
      if (vec_len (tags) < vec_len (ems))
	{
	  for (i = vec_len (tags); i < vec_len (ems); i++)
	    vec_add1 (tags, format (0, "F%d%c", i, 0));
	}

      elog_init (em, max_events);
      for (i = 0; i < vec_len (ems); i++)
	{
	  if ((error =
	       elog_read_file (i == 0 ? em : &ems[i], merge_files[i])))
	    goto done;
	  if (i > 0)
	    {
	      align_tweak = 0.0;
	      if (i <= vec_len (align_tweaks))
		align_tweak = align_tweaks[i - 1];
	      elog_merge (em, tags[0], &ems[i], tags[i], align_tweak);
	      tags[0] = 0;
	    }
	}
    }

  else
#endif /* CLIB_UNIX */
    {
      f64 t[2];

      elog_init (em, max_events);
      elog_enable_disable (em, 1);
      t[0] = unix_time_now ();

      for (i = 0; i < n_iter; i++)
	{
	  u32 j, n, sum;

	  n = 1 + (random_u32 (&seed) % 128);
	  sum = 0;
	  for (j = 0; j < n; j++)
	    sum += random_u32 (&seed);

	  {
	    ELOG_TYPE_XF (e);
	    ELOG (em, e, sum);
	  }

	  {
	    ELOG_TYPE_XF (e);
	    ELOG (em, e, sum + 1);
	  }

	  {
	    struct
	    {
	      u32 string_index;
	      f32 f;
	    } *d;
	    ELOG_TYPE_DECLARE (e) =
	    {
	      .format = "fumble %s %.9f",.format_args =
		"t4f4",.n_enum_strings = 4,.enum_strings =
	      {
	    "string0", "string1", "string2", "string3",},};

	    d = ELOG_DATA (em, e);

	    d->string_index = sum & 3;
	    d->f = (sum & 0xff) / 128.;
	  }

	  {
	    ELOG_TYPE_DECLARE (e) =
	    {
	    .format = "bar %d.%d.%d.%d",.format_args = "i1i1i1i1",};
	    ELOG_TRACK (my_track);
	    u8 *d = ELOG_TRACK_DATA (em, e, my_track);
	    d[0] = i + 0;
	    d[1] = i + 1;
	    d[2] = i + 2;
	    d[3] = i + 3;
	  }

	  {
	    ELOG_TYPE_DECLARE (e) =
	    {
	    .format = "bar `%s'",.format_args = "s20",};
	    struct
	    {
	      char s[20];
	    } *d;
	    u8 *v;

	    d = ELOG_DATA (em, e);
	    v = format (0, "foo %d%c", i, 0);
	    clib_memcpy (d->s, v, clib_min (vec_len (v), sizeof (d->s)));
	  }

	  {
	    ELOG_TYPE_DECLARE (e) =
	    {
	    .format = "bar `%s'",.format_args = "T4",};
	    struct
	    {
	      u32 offset;
	    } *d;

	    d = ELOG_DATA (em, e);
	    d->offset = elog_string (em, "string table %d", i);
	  }
	}

      do
	{
	  t[1] = unix_time_now ();
	}
      while (t[1] - t[0] < min_sample_time);
    }

#ifdef CLIB_UNIX
  if (dump_file)
    {
      if ((error =
	   elog_write_file (em, dump_file, 0 /* do not flush ring */ )))
	goto done;
    }
#endif

  if (verbose)
    {
      elog_event_t *e, *es;
      es = elog_get_events (em);
      vec_foreach (e, es)
      {
	clib_warning ("%18.9f: %12U %U\n", e->time,
		      format_elog_track, em, e, format_elog_event, em, e);
      }
    }

done:
  if (error)
    clib_error_report (error);
  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int r;

  clib_mem_init (0, 3ULL << 30);

  unformat_init_command_line (&i, argv);
  r = test_elog_main (&i);
  unformat_free (&i);
  return r;
}
#endif

/**
 * @brief GDB callable function: vl - Return vector length of vector
 *
 * @param *p - void - address of vector
 *
 * @return length - u32
 *
 */
u32
vl (void *p)
{
  return vec_len (p);
}

/**
 * @brief GDB callable function: pe - call pool_elts - number of elements in a pool
 *
 * @param *v - void - address of pool
 *
 * @return number - uword
 *
 */
#include <vppinfra/pool.h>
uword
pe (void *v)
{
  return (pool_elts (v));
}

#include <vppinfra/hash.h>
uword
he (void *v)
{
  return (hash_elts (v));
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
