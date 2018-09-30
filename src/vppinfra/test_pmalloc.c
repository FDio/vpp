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
  u32 niter;
  u32 item_size;
  u32 align;
  int check_every_add_del;
  int verbose;
} test_main_t;

test_main_t test_main;

clib_error_t *
test_valloc (test_main_t * tm)
{
  int i, h, index;
  h = clib_pmalloc_init ("foo", 32);
  uword *va;

  if (h < 0)
    return clib_error_return (0, "pmalloc init failure");

  fformat (stdout, "Allocate %d items...\n", tm->nitems);

  for (i = 0; i < tm->nitems; i++)
    {
      u32 size = tm->item_size ? tm->item_size : 64 + 64 * (i % 8);
      u32 align = tm->align ? tm->align : 64 << (i % 5);
      va = clib_pmalloc_alloc_aligned (h, size, align);

      if ((pointer_to_uword (va) & (align - 1)) != 0)
	clib_error (0, "Alignment error: %p not aligned with %u", va, align);

      vec_add1 (tm->vas, pointer_to_uword (va));
      vec_add1 (tm->item_in_table, 1);
    }
  fformat (stdout, "%U\n", format_pmalloc, h, 1 /* verbose */ );

  fformat (stdout, "Perform %d random add/delete operations...\n", tm->niter);

  for (i = 0; i < tm->niter; i++)
    {
      index = random_u32 (&tm->seed) % tm->nitems;
      /* Swap state of random entry */
      if (tm->item_in_table[index])
	{
	  if (0)
	    fformat (stdout, "free [%d] %llx\n", index, tm->vas[index]);
	  clib_pmalloc_free (h, (void *) tm->vas[index]);
	  tm->item_in_table[index] = 0;
	  tm->vas[index] = ~0;
	}
      else
	{
	  va = clib_pmalloc_alloc_aligned (h, 1024, 64);
	  tm->vas[index] = pointer_to_uword (va);
	  tm->item_in_table[index] = 1;
	  if (0)
	    fformat (stdout, "alloc [%d] %llx\n", index, tm->vas[index]);
	}
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
  tm->niter = 100;
  tm->item_size = 0;

  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "seed %u", &tm->seed))
	;
      else if (unformat (i, "nitems %u", &tm->nitems))
	;
      else if (unformat (i, "niter %u", &tm->niter))
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
