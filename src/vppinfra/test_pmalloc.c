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
  u32 seed;
  uword baseva;
  uword size;
  uword *vas;
  u8 *item_in_table;
  u32 nitems;
  u32 item_size;
  u32 align;
  int max_numa;
  int verbose;
} test_main_t;

test_main_t test_main;

clib_error_t *
test_valloc (test_main_t * tm)
{
  int i, h;
  h = clib_pmalloc_init ("foo", 32);
  uword *va;

  if (h < 0)
    return clib_error_return (0, "pmalloc init failure");

  fformat (stdout, "Allocate %d items...\n", tm->nitems);

  for (i = 0; i < tm->nitems; i++)
    {
      u32 size = tm->item_size ? tm->item_size : 64 + 64 * (i % 8);
      u32 align = tm->align ? tm->align : 64 << (i % 5);
      u32 numa = i % (tm->max_numa + 1);
      va = clib_pmalloc_alloc_aligned_on_numa (h, size, align, numa);

      if (va == 0)
	clib_error ("Failed to alloc %u byte chunk with align %u on numa %u",
		    size, align, numa);


      if ((pointer_to_uword (va) & (align - 1)) != 0)
	clib_error (0, "Alignment error: %p not aligned with %u", va, align);

      vec_add1 (tm->vas, pointer_to_uword (va));
      vec_add1 (tm->item_in_table, 1);
    }
  fformat (stdout, "%U\n", format_pmalloc, h, 1 /* verbose */ );

  for (i = 0; i < tm->nitems; i++)
    {
      if (tm->item_in_table[i])
	clib_pmalloc_free (h, (void *) tm->vas[i]);
    }

  fformat (stdout, "%U\n", format_pmalloc, h, 1 /* verbose */ );
  return 0;
}

clib_error_t *
test_valloc_main (unformat_input_t * i)
{
  test_main_t *tm = &test_main;
  clib_error_t *error;

  tm->seed = 0xdeaddabe;
  tm->nitems = 5;
  tm->item_size = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "seed %u", &tm->seed))
	;
      else if (unformat (i, "nitems %u", &tm->nitems))
	;
      else if (unformat (i, "max-numa %u", &tm->max_numa))
	;
      else if (unformat (i, "item-size %u", &tm->item_size))
	;
      else if (unformat (i, "align %u", &tm->align))
	;
      else if (unformat (i, "verbose %d", &tm->verbose))
	;
      else if (unformat (i, "verbose"))
	tm->verbose = 1;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, i);
    }

  error = test_valloc (tm);

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
  error = test_valloc_main (&i);
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
