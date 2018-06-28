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
  Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus

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

#ifdef CLIB_LINUX_KERNEL
#include <linux/unistd.h>
#endif

#ifdef CLIB_UNIX
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>		/* scanf */
#endif

#include <vppinfra/mheap.h>
#include <vppinfra/format.h>
#include <vppinfra/random.h>
#include <vppinfra/time.h>

static int verbose = 0;
#define if_verbose(format,args...) \
  if (verbose) { clib_warning(format, ## args); }

int
test1 (void)
{
  clib_time_t clib_time;
  void *h_mem = clib_mem_alloc (2ULL << 30);
  void *h;
  uword *objects = 0;
  int i;
  f64 before, after;

  clib_time_init (&clib_time);

  vec_validate (objects, 2000000 - 1);

  h = mheap_alloc (h_mem, (uword) (2 << 30));

  before = clib_time_now (&clib_time);

  for (i = 0; i < vec_len (objects); i++)
    {
      h = mheap_get_aligned (h, 24 /* size */ ,
			     64 /* align */ ,
			     16 /* align at offset */ , &objects[i]);
    }

  after = clib_time_now (&clib_time);

  fformat (stdout, "alloc: %u objects in %.2f seconds, %.2f objects/second\n",
	   vec_len (objects), (after - before),
	   ((f64) vec_len (objects)) / (after - before));

  return 0;
}


int
test_mheap_main (unformat_input_t * input)
{
  int i, j, k, n_iterations;
  void *h, *h_mem;
  uword *objects = 0;
  u32 objects_used, really_verbose, n_objects, max_object_size;
  u32 check_mask, seed, trace, use_vm;
  u32 print_every = 0;
  u32 *data;
  mheap_t *mh;

  /* Validation flags. */
  check_mask = 0;
#define CHECK_VALIDITY 1
#define CHECK_DATA     2
#define CHECK_ALIGN    4
#define TEST1	       8

  n_iterations = 10;
  seed = 0;
  max_object_size = 100;
  n_objects = 1000;
  trace = 0;
  really_verbose = 0;
  use_vm = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (0 == unformat (input, "iter %d", &n_iterations)
	  && 0 == unformat (input, "count %d", &n_objects)
	  && 0 == unformat (input, "size %d", &max_object_size)
	  && 0 == unformat (input, "seed %d", &seed)
	  && 0 == unformat (input, "print %d", &print_every)
	  && 0 == unformat (input, "validdata %|",
			    &check_mask, CHECK_DATA | CHECK_VALIDITY)
	  && 0 == unformat (input, "valid %|",
			    &check_mask, CHECK_VALIDITY)
	  && 0 == unformat (input, "verbose %=", &really_verbose, 1)
	  && 0 == unformat (input, "trace %=", &trace, 1)
	  && 0 == unformat (input, "vm %=", &use_vm, 1)
	  && 0 == unformat (input, "align %|", &check_mask, CHECK_ALIGN)
	  && 0 == unformat (input, "test1 %|", &check_mask, TEST1))
	{
	  clib_warning ("unknown input `%U'", format_unformat_error, input);
	  return 1;
	}
    }

  /* Zero seed means use default. */
  if (!seed)
    seed = random_default_seed ();

  if (check_mask & TEST1)
    {
      return test1 ();
    }

  if_verbose
    ("testing %d iterations, %d %saligned objects, max. size %d, seed %d",
     n_iterations, n_objects, (check_mask & CHECK_ALIGN) ? "randomly " : "un",
     max_object_size, seed);

  vec_resize (objects, n_objects);
  if (vec_bytes (objects) > 0)	/* stupid warning be gone */
    memset (objects, ~0, vec_bytes (objects));
  objects_used = 0;

  /* Allocate initial heap. */
  {
    uword size =
      max_pow2 (2 * n_objects * max_object_size * sizeof (data[0]));

    h_mem = clib_mem_alloc (size);
    if (!h_mem)
      return 0;

    h = mheap_alloc (h_mem, size);
  }

  if (trace)
    mheap_trace (h, trace);

  mh = mheap_header (h);

  if (use_vm)
    mh->flags &= ~MHEAP_FLAG_DISABLE_VM;
  else
    mh->flags |= MHEAP_FLAG_DISABLE_VM;

  if (check_mask & CHECK_VALIDITY)
    mh->flags |= MHEAP_FLAG_VALIDATE;

  for (i = 0; i < n_iterations; i++)
    {
      while (1)
	{
	  j = random_u32 (&seed) % vec_len (objects);
	  if (objects[j] != ~0 || i + objects_used < n_iterations)
	    break;
	}

      if (objects[j] != ~0)
	{
	  mheap_put (h, objects[j]);
	  objects_used--;
	  objects[j] = ~0;
	}
      else
	{
	  uword size, align, align_offset;

	  size = (random_u32 (&seed) % max_object_size) * sizeof (data[0]);
	  align = align_offset = 0;
	  if (check_mask & CHECK_ALIGN)
	    {
	      align = 1 << (random_u32 (&seed) % 10);
	      align_offset = round_pow2 (random_u32 (&seed) & (align - 1),
					 sizeof (u32));
	    }

	  h = mheap_get_aligned (h, size, align, align_offset, &objects[j]);

	  if (align > 0)
	    ASSERT (0 == ((objects[j] + align_offset) & (align - 1)));

	  ASSERT (objects[j] != ~0);
	  objects_used++;

	  /* Set newly allocated object with test data. */
	  if (check_mask & CHECK_DATA)
	    {
	      uword len;

	      data = (void *) h + objects[j];
	      len = mheap_len (h, data);

	      ASSERT (size <= mheap_data_bytes (h, objects[j]));

	      data[0] = len;
	      for (k = 1; k < len; k++)
		data[k] = objects[j] + k;
	    }
	}

      /* Verify that all used objects have correct test data. */
      if (check_mask & 2)
	{
	  for (j = 0; j < vec_len (objects); j++)
	    if (objects[j] != ~0)
	      {
		u32 *data = h + objects[j];
		uword len = data[0];
		for (k = 1; k < len; k++)
		  ASSERT (data[k] == objects[j] + k);
	      }
	}
      if (print_every != 0 && i > 0 && (i % print_every) == 0)
	fformat (stderr, "iteration %d: %U\n", i, format_mheap, h,
		 really_verbose);
    }

  if (verbose)
    fformat (stderr, "%U\n", format_mheap, h, really_verbose);
  mheap_free (h);
  clib_mem_free (h_mem);
  vec_free (objects);

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  clib_mem_init (0, 3ULL << 30);

  verbose = (argc > 1);
  unformat_init_command_line (&i, argv);
  ret = test_mheap_main (&i);
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
