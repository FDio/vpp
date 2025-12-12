/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus
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
  uword align;

  clib_mem_init (0, 10 << 20);

  n = 10;
  seed = (u32) getpid ();
  check_mask = 0;

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

  if (verbose)
    fformat (stderr, "%U\n", format_clib_mem_usage, /* verbose */ 0);

  return 0;
}
