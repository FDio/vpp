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

#define PMALLOC_LOG2_BLOCK_SZ          6
#define PMALLOC_BLOCK_SZ               (1 << 6)

#define CLIB_PMALLOC_NUMA_LOCAL 0xffffffff

typedef struct
{
  u32 start, prev, next;
  u32 size:31;
  u32 used:1;
} clib_pmalloc_chunk_t;

STATIC_ASSERT_SIZEOF (clib_pmalloc_chunk_t, 16);

typedef struct
{
  uword pa;
  u32 numa_node;
  clib_pmalloc_chunk_t *chunks;
  u32 first_chunk_index;
  u32 n_free_chunks;
  u32 n_free_blocks;
} clib_pmalloc_page_t;

typedef struct
{
  int fd;
  u8 *start;
  uword pagesize;
  u32 max_pages;

  clib_pmalloc_page_t *pages;

  uword *chunk_index_by_va;

} clib_pmalloc_main_t;


int clib_pmalloc_init (clib_pmalloc_main_t * pm, char *name, uword max_pages);
void *clib_pmalloc_alloc_aligned_on_numa (clib_pmalloc_main_t * pm,
					  uword size, uword align,
					  u32 numa_node);
void clib_pmalloc_free (clib_pmalloc_main_t * pm, void *va);

always_inline void *
clib_pmalloc_alloc_aligned (clib_pmalloc_main_t * pm, uword size, uword align)
{
  return clib_pmalloc_alloc_aligned_on_numa (pm, size, align,
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
