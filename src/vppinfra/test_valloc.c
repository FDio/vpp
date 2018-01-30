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

#include <vppinfra/valloc.h>

u32
vl (void *p)
{
  return vec_len (p);
}

/*
 * GDB callable function: pe - call pool_elts - number of elements in a pool
 */
uword
pe (void *v)
{
  return (pool_elts (v));
}

typedef struct
{
  u32 seed;
  uword baseva;
  uword size;
  uword *basevas;
  u8 *item_in_table;
  u32 nitems;
  u32 niter;
  u32 item_size;
  int check_every_add_del;
  clib_valloc_main_t valloc_main;
  int verbose;
} test_main_t;

test_main_t test_main;

clib_error_t *
test_valloc (test_main_t * tm)
{
  clib_valloc_chunk_t _ip, *ip = &_ip;
  uword baseva;
  uword *p;
  int i, j, index;
  u32 currently_in_table;
  u32 found;

  ip->baseva = 0x20000000;
  ip->size = 1024;

  clib_valloc_init (&tm->valloc_main, ip, 1 /* lock */ );

  ip->baseva = 0x20000000 + 1024;
  ip->size = 1024 * 1024 * 1024 - 1024;
  clib_valloc_add_chunk (&tm->valloc_main, ip);

  fformat (stdout, "Allocate %d items...\n", tm->nitems);
  for (i = 0; i < tm->nitems; i++)
    {
      baseva = clib_valloc_alloc (&tm->valloc_main, 1024,
				  1 /* fail:os_out_of_memory */ );
      vec_add1 (tm->basevas, baseva);
      vec_add1 (tm->item_in_table, 1);
    }

  fformat (stdout, "Perform %d random add/delete operations...\n", tm->niter);

  for (i = 0; i < tm->niter; i++)
    {
      index = random_u32 (&tm->seed) % tm->nitems;
      /* Swap state of random entry */
      if (tm->item_in_table[index])
	{
	  if (0)
	    fformat (stdout, "free [%d] %llx\n", index, tm->basevas[index]);
	  clib_valloc_free (&tm->valloc_main, tm->basevas[index]);
	  tm->item_in_table[index] = 0;
	  tm->basevas[index] = ~0;
	}
      else
	{
	  baseva = clib_valloc_alloc (&tm->valloc_main, 1024,
				      1 /* fail:os_out_of_memory */ );
	  tm->basevas[index] = baseva;
	  tm->item_in_table[index] = 1;
	  if (0)
	    fformat (stdout, "alloc [%d] %llx\n", index, tm->basevas[index]);
	}

      /* Check our work... */
      if (tm->check_every_add_del)
	{
	  for (j = 0; j < tm->nitems; j++)
	    {
	      if (tm->item_in_table[j])
		{
		  p = hash_get ((&tm->valloc_main)->chunk_index_by_baseva,
				tm->basevas[j]);
		  if (p)
		    {
		      ip =
			pool_elt_at_index ((&tm->valloc_main)->chunks, p[0]);
		      ASSERT (ip->baseva == tm->basevas[j]);
		      ASSERT (ip->flags & CLIB_VALLOC_BUSY);
		    }
		}
	      else
		{
		  p = hash_get ((&tm->valloc_main)->chunk_index_by_baseva,
				tm->basevas[j]);
		  /* Have to check, it's OK for the block to have been fused */
		  if (p)
		    {
		      ip =
			pool_elt_at_index ((&tm->valloc_main)->chunks, p[0]);
		      if ((ip->flags & CLIB_VALLOC_BUSY))
			{
			  fformat (stdout, "BUG: baseva %llx chunk %d busy\n",
				   tm->basevas[j], p[0]);
			  fformat (stdout, "%U\n", format_valloc,
				   &tm->valloc_main, 1 /* verbose */ );
			  ASSERT ((ip->flags & CLIB_VALLOC_BUSY) == 0);
			}
		    }
		}
	    }
	}
    }

  currently_in_table = 0;

  for (i = 0; i < tm->nitems; i++)
    {
      currently_in_table += tm->item_in_table[i];
    }

  fformat (stdout, "Check that %d items in table can be found...\n",
	   currently_in_table);

  found = 0;

  for (i = 0; i < tm->nitems; i++)
    {
      if (tm->item_in_table[i])
	{
	  p = hash_get ((&tm->valloc_main)->chunk_index_by_baseva,
			tm->basevas[i]);
	  if (p)
	    {
	      ip = pool_elt_at_index ((&tm->valloc_main)->chunks, p[0]);
	      ASSERT (ip->baseva == tm->basevas[i]);
	      ASSERT (ip->flags & CLIB_VALLOC_BUSY);
	    }
	  found++;
	}
      else
	{
	  p = hash_get ((&tm->valloc_main)->chunk_index_by_baseva,
			tm->basevas[i]);
	  /* Have to check, it's OK for the block to have been fused */
	  if (p)
	    {
	      ip = pool_elt_at_index ((&tm->valloc_main)->chunks, p[0]);
	      if ((ip->flags & CLIB_VALLOC_BUSY))
		{
		  fformat (stdout, "BUG: baseva %llx chunk %d busy\n",
			   tm->basevas[i], p[0]);
		  fformat (stdout, "%U\n", format_valloc,
			   &tm->valloc_main, 1 /* verbose */ );
		  ASSERT ((ip->flags & CLIB_VALLOC_BUSY) == 0);
		}
	    }
	}
    }

  fformat (stdout, "Found %d items in table...\n", found);

  for (i = 0; i < tm->nitems; i++)
    {
      if (tm->item_in_table[i])
	clib_valloc_free (&tm->valloc_main, tm->basevas[i]);
    }

  fformat (stdout, "%U", format_valloc, &tm->valloc_main, 1 /* verbose */ );

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
  tm->item_size = 1024;

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
      else if (unformat (i, "check-every-add-del"))
	tm->check_every_add_del = 1;
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
