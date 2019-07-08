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

#include <vppinfra/mem.h>

/* Vector of all bihashes */
void **clib_all_bihashes;
static void **clib_all_bihash_heap;

void *
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
void
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


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
