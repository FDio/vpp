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

static void
test_heap_dup_typed (void)
{
#define test_heap_dup_type(type)                                               \
  do                                                                          \
    {                                                                         \
      type *original = 0, *copy;                                               \
      uword handle, offset;                                                   \
      ALWAYS_ASSERT (heap_dup (original) == 0);                                \
      heap_new (original);                                                    \
      copy = heap_dup (original);                                             \
      ALWAYS_ASSERT (copy && copy != original && vec_len (copy) == 0);          \
      ALWAYS_ASSERT (heap_header (copy)->elt_bytes == sizeof (type));          \
      heap_free (original);                                                   \
      offset = heap_alloc (copy, 100, handle);                                 \
      ALWAYS_ASSERT (offset == 0 && vec_len (copy) == 100);                     \
      for (uword i = 0; i < 100; i++)                                          \
        copy[i] = (type) (~(type) 0 - i);                                      \
      original = heap_dup (copy);                                             \
      ALWAYS_ASSERT (original != copy && vec_len (original) == 100);           \
      ALWAYS_ASSERT (heap_header (original)->elt_bytes == sizeof (type));      \
      ALWAYS_ASSERT (vec_max_bytes (original) >= 100 * sizeof (type));          \
      ALWAYS_ASSERT (vec_is_equal (original, copy));                           \
      original[99] = 0;                                                       \
      ALWAYS_ASSERT (copy[99] == (type) (~(type) 0 - 99));                      \
      heap_free (original);                                                   \
      for (uword i = 0; i < 100; i++)                                          \
        ALWAYS_ASSERT (copy[i] == (type) (~(type) 0 - i));                      \
      heap_dealloc (copy, handle);                                            \
      original = heap_dup (copy);                                             \
      ALWAYS_ASSERT (vec_len (original) == 100 && heap_elts (original) == 0);    \
      heap_free (copy);                                                       \
      offset = heap_alloc (original, 100, handle);                             \
      ALWAYS_ASSERT (offset == 0 && heap_len (original, handle) == 100);        \
      heap_free (original);                                                   \
    }                                                                         \
  while (0)

  test_heap_dup_type (u8);
  test_heap_dup_type (u32);
  test_heap_dup_type (u64);
#undef test_heap_dup_type
}

static void
test_heap_dup_metadata (void)
{
  u8 *original = 0, *copy;
  heap_header_t *original_header, *copy_header;
  uword handles[4], handle, offset, free_count;

  for (uword i = 0; i < ARRAY_LEN (handles); i++)
    {
      offset = heap_alloc (original, 16, handles[i]);
      ALWAYS_ASSERT (offset == 16 * i);
    }
  clib_memset (original, 0xa5, vec_len (original));
  heap_dealloc (original, handles[1]);
  heap_dealloc (original, handles[2]);
  copy = heap_dup (original);
  original_header = heap_header (original);
  copy_header = heap_header (copy);

  ALWAYS_ASSERT (vec_is_equal (original, copy));
  ALWAYS_ASSERT (original_header->elts != copy_header->elts);
  ALWAYS_ASSERT (vec_is_equal (original_header->elts, copy_header->elts));
  ALWAYS_ASSERT (vec_len (original_header->free_elts) > 0);
  ALWAYS_ASSERT (original_header->free_elts != copy_header->free_elts);
  ALWAYS_ASSERT (vec_is_equal (original_header->free_elts, copy_header->free_elts));
  ALWAYS_ASSERT (original_header->free_lists != copy_header->free_lists);
  ALWAYS_ASSERT (vec_len (original_header->free_lists) == vec_len (copy_header->free_lists));
  free_count = 0;
  for (uword i = 0; i < vec_len (original_header->free_lists); i++)
    {
      ALWAYS_ASSERT (vec_is_equal (original_header->free_lists[i], copy_header->free_lists[i]));
      if (vec_len (original_header->free_lists[i]))
	{
	  ALWAYS_ASSERT (original_header->free_lists[i] != copy_header->free_lists[i]);
	  free_count += vec_len (original_header->free_lists[i]);
	}
    }
  ALWAYS_ASSERT (free_count > 0);
  ALWAYS_ASSERT (vec_len (original_header->small_free_elt_free_index) > 0);
  ALWAYS_ASSERT (original_header->small_free_elt_free_index !=
		 copy_header->small_free_elt_free_index);
  ALWAYS_ASSERT (vec_is_equal (original_header->small_free_elt_free_index,
			      copy_header->small_free_elt_free_index));
  if (CLIB_DEBUG > 0)
    {
      ALWAYS_ASSERT (vec_len (original_header->used_elt_bitmap) > 0);
      ALWAYS_ASSERT (original_header->used_elt_bitmap != copy_header->used_elt_bitmap);
      ALWAYS_ASSERT (vec_is_equal (original_header->used_elt_bitmap, copy_header->used_elt_bitmap));
    }

  copy[48] = 0x5a;
  ALWAYS_ASSERT (original[48] == 0xa5);
  offset = heap_alloc (copy, 8, handle);
  ALWAYS_ASSERT (offset >= 16 && offset + 8 <= 48);
  heap_dealloc (copy, handles[0]);
  ALWAYS_ASSERT (heap_elts (original) == 2);
  ALWAYS_ASSERT (!heap_is_free_handle (original, handles[0]));
  ALWAYS_ASSERT (vec_len (original_header->free_elts) == 2);
  ALWAYS_ASSERT (heap_len (original, handles[0]) == 16);
  ALWAYS_ASSERT (heap_len (original, handles[3]) == 16);
  if (CLIB_DEBUG > 0)
    {
      heap_validate (original);
      heap_validate (copy);
    }
  heap_free (original);
  ALWAYS_ASSERT (copy[48] == 0x5a && heap_len (copy, handle) == 8);
  heap_dealloc (copy, handle);
  heap_dealloc (copy, handles[3]);
  ALWAYS_ASSERT (heap_elts (copy) == 0);
  heap_free (copy);
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

  test_heap_dup_typed ();
  test_heap_dup_metadata ();
  fformat (stdout, "heap duplication tests passed\n");

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
