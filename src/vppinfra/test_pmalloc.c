/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vppinfra/format.h>
#include <vppinfra/pmalloc.h>
#include <vppinfra/random.h>

typedef struct
{
  uword baseva;
  uword size;
  uword *vas;
  u32 nitems;
  u32 item_size;
  u32 align;
  int max_numa;
  u32 arena_pages;
  u32 arena_numa;
  u32 arena_items;
  u32 arena_log2_pg_sz;
  int verbose;
  clib_pmalloc_main_t pmalloc_main;
} test_main_t;

test_main_t test_main;

clib_error_t *
test_palloc (test_main_t * tm)
{
  clib_pmalloc_main_t *pm = &tm->pmalloc_main;
  void *arena;
  int i;
  uword *va;

  if (clib_pmalloc_init (pm, 0, 0) != 0)
    return clib_error_return (0, "pmalloc init failure");

  fformat (stdout, "Allocate %d items...\n", tm->nitems);

  for (i = 0; i < tm->nitems; i++)
    {
      u32 size = tm->item_size ? tm->item_size : 64 + 64 * (i % 8);
      u32 align = tm->align ? tm->align : 64 << (i % 5);
      u32 numa = i % (tm->max_numa + 1);
      va = clib_pmalloc_alloc_aligned_on_numa (pm, size, align, numa);

      if (va == 0)
	clib_error ("Failed to alloc %u byte chunk with align %u on numa %u,"
		    "\nerror: %U", size, align, numa, format_clib_error,
		    clib_pmalloc_last_error (pm));

      if ((pointer_to_uword (va) & (align - 1)) != 0)
	clib_error (0, "Alignment error: %p not aligned with %u", va, align);

      vec_add1 (tm->vas, pointer_to_uword (va));
    }
  fformat (stdout, "%U\n", format_pmalloc, pm, tm->verbose);

  /* alloc from arena */
  if (tm->arena_items)
    {
      fformat (stdout, "Allocate %d items from arena ...\n", tm->arena_items);
      arena = clib_pmalloc_create_shared_arena (pm, "test arena",
						tm->arena_pages << 21,
						tm->arena_log2_pg_sz,
						tm->arena_numa);
      if (arena == 0)
	clib_error ("Failed to alloc shared arena: %U", format_clib_error,
		    clib_pmalloc_last_error (pm));

      for (i = 0; i < tm->arena_items; i++)
	{
	  u32 size = tm->item_size ? tm->item_size : 64 + 64 * (i % 8);
	  u32 align = tm->align ? tm->align : 64 << (i % 5);
	  va = clib_pmalloc_alloc_from_arena (pm, arena, size, align);
	  vec_add1 (tm->vas, pointer_to_uword (va));
	}
      fformat (stdout, "\n%U\n", format_pmalloc, pm, tm->verbose);
    }


  fformat (stdout, "Freeing %d items ...\n", vec_len (tm->vas));
  for (i = 0; i < vec_len (tm->vas); i++)
    clib_pmalloc_free (pm, (void *) tm->vas[i]);

  fformat (stdout, "\n%U\n", format_pmalloc, pm, tm->verbose);
  return 0;
}

clib_error_t *
test_palloc_main (unformat_input_t * i)
{
  test_main_t *tm = &test_main;
  clib_error_t *error;

  tm->nitems = 5;
  tm->arena_pages = 2;
  tm->arena_numa = CLIB_PMALLOC_NUMA_LOCAL;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "nitems %u", &tm->nitems))
	;
      else if (unformat (i, "max-numa %u", &tm->max_numa))
	;
      else if (unformat (i, "item-size %u", &tm->item_size))
	;
      else if (unformat (i, "align %u", &tm->align))
	;
      else if (unformat (i, "verbose %d", &tm->verbose))
	;
      else if (unformat (i, "arena-pages %u", &tm->arena_pages))
	;
      else if (unformat (i, "arena-numa %u", &tm->arena_numa))
	;
      else if (unformat (i, "arena-items %u", &tm->arena_items))
	;
      else if (unformat (i, "arena-log2-page-size %u", &tm->arena_log2_pg_sz))
	;
      else if (unformat (i, "verbose"))
	tm->verbose = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, i);
    }

  error = test_palloc (tm);

  return error;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int rv = 0;
  clib_error_t *error;

  clib_mem_init (0, 3ULL << 30);

  unformat_init_command_line (&i, argv);
  error = test_palloc_main (&i);
  if (error)
    {
      clib_error_report (error);
      rv = 1;
    }
  unformat_free (&i);

  return rv;
}
#endif /* CLIB_UNIX */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
