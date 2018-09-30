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

#ifndef included_palloc_h
#define included_palloc_h
#include <vppinfra/format.h>

#define CLIB_PMALLOC_NUMA_LOCAL 0xffffffff

int clib_pmalloc_init (char *name, uword max_pages);
void *clib_pmalloc_alloc_aligned_on_numa (int handle, uword size,
					  uword align, u32 numa_node);
void clib_pmalloc_free (int handle, void *va);

always_inline void *
clib_pmalloc_alloc_aligned (int handle, uword size, uword align)
{
  return clib_pmalloc_alloc_aligned_on_numa (handle, size, align,
					     CLIB_PMALLOC_NUMA_LOCAL);
}

format_function_t format_pmalloc;

#endif /* included_palloc_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
