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

#include <unistd.h>
#include <stdlib.h>

#include <vppinfra/mem.h>
#include <vppinfra/heap.h>
#include <vppinfra/format.h>

static int verbose;
#define if_verbose(format,args...) \
  if (verbose) { clib_warning(format, ## args); }

u32
vl (void *p)
{
  return (vec_len (p));
}

int
main (int argc, char *argv[])
{
  word i, j, k, n, check_mask;
  u32 seed;
  u32 *h = 0;
  uword *objects = 0;
  uword *handles = 0;
  uword objects_used;
  uword align, fixed_size;

  clib_mem_init (0, 10 << 20);

  n = 10;
  seed = (u32) getpid ();
  check_mask = 0;
  fixed_size = 0;

  if (argc > 1)
    {
      n = atoi (argv[1]);
      verbose = 1;
    }
  if (argc > 2)
    {
      word i = atoi (argv[2]);
      if (i)
	seed = i;
    }
  if (argc > 3)
    check_mask = atoi (argv[3]);

  align = 0;
  if (argc > 4)
    align = 1 << atoi (argv[4]);

  if_verbose ("testing %wd iterations seed %wd\n", n, seed);

  if (verbose)
    fformat (stderr, "%U\n", format_clib_mem_usage, /* verbose */ 0);

  vec_resize (objects, 1000);
  if (vec_bytes (objects) > 0)	/* stupid warning be gone */
    clib_memset (objects, ~0, vec_bytes (objects));
  vec_resize (handles, vec_len (objects));

  objects_used = 0;

  if (fixed_size)
    {
      uword max_len = 1024 * 1024;
      void *memory = clib_mem_alloc (max_len * sizeof (h[0]));
      h = heap_create_from_memory (memory, max_len, sizeof (h[0]));
    }

  for (i = 0; i < n; i++)
    {
      while (1)
	{
	  j = random_u32 (&seed) % vec_len (objects);
	  if (objects[j] != ~0 || i + objects_used < n)
	    break;
	}

      if (objects[j] != ~0)
	{
	  heap_dealloc (h, handles[j]);
	  objects_used--;
	  objects[j] = ~0;
	}
      else
	{
	  u32 *data;
	  uword size;

	  size = 1 + (random_u32 (&seed) % 100);
	  objects[j] = heap_alloc_aligned (h, size, align, handles[j]);
	  objects_used++;

	  if (align)
	    ASSERT (0 == (objects[j] & (align - 1)));
	  ASSERT (objects[j] < vec_len (h));
	  ASSERT (size <= heap_len (h, handles[j]));

	  /* Set newly allocated object with test data. */
	  if (check_mask & 2)
	    {
	      data = h + objects[j];

	      for (k = 0; k < size; k++)
		data[k] = objects[j] + k;
	    }
	}

      if (check_mask & 1)
	heap_validate (h);

      if (check_mask & 4)
	{
	  /* Duplicate heap at each iteration. */
	  u32 *h1 = heap_dup (h);
	  heap_free (h);
	  h = h1;
	}

      /* Verify that all used objects have correct test data. */
      if (check_mask & 2)
	{
	  for (j = 0; j < vec_len (objects); j++)
	    if (objects[j] != ~0)
	      {
		u32 *data = h + objects[j];
		for (k = 0; k < heap_len (h, handles[j]); k++)
		  ASSERT (data[k] == objects[j] + k);
	      }
	}
    }

  if (verbose)
    fformat (stderr, "%U\n", format_heap, h, 1);

  {
    u32 *h1 = heap_dup (h);
    if (verbose)
      fformat (stderr, "%U\n", format_heap, h1, 1);
    heap_free (h1);
  }

  heap_free (h);
  if (verbose)
    fformat (stderr, "%U\n", format_heap, h, 1);
  // ASSERT (objects_used == 0);

  vec_free (objects);
  vec_free (handles);

  if (fixed_size)
    vec_free_h (h, sizeof (heap_header_t));

  if (verbose)
    fformat (stderr, "%U\n", format_clib_mem_usage, /* verbose */ 0);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
