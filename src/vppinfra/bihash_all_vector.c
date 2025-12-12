/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#include <vppinfra/mem.h>

/* Vector of all bihashes */
__clib_export void **clib_all_bihashes;
static clib_mem_heap_t *clib_all_bihash_heap;

__clib_export clib_mem_heap_t *
clib_all_bihash_set_heap (void)
{
  if (PREDICT_FALSE (clib_all_bihash_heap == 0))
    clib_all_bihash_heap = clib_mem_get_heap ();

  return clib_mem_set_heap (clib_all_bihash_heap);
}

/*
 * Leave it to Beaver to change the size of a bihash
 * by making a clone in a stack local and then copying it...
 */
__clib_export void
clib_bihash_copied (void *dst, void *src)
{
  int i;

  for (i = 0; i < vec_len (clib_all_bihashes); i++)
    {
      if (clib_all_bihashes[i] == src)
	{
	  clib_all_bihashes[i] = dst;
	  return;
	}
    }
  clib_warning ("Couldn't find bihash copy source %llx!", src);
}
