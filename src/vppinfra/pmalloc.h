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
#include <vppinfra/pool.h>

#define PMALLOC_LOG2_BLOCK_SZ          CLIB_LOG2_CACHE_LINE_BYTES
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
  u32 index;
  u32 arena_index;
  uword pa;
  clib_pmalloc_chunk_t *chunks;
  u32 first_chunk_index;
  u32 n_free_chunks;
  u32 n_free_blocks;
} clib_pmalloc_page_t;

typedef struct
{
  u32 index;
  u32 flags;
#define CLIB_PMALLOC_ARENA_F_SHARED_MEM (1 << 0)
  int fd;
  u32 numa_node;
  u32 first_page_index;
  u32 log2_subpage_sz;
  u32 subpages_per_page;
  u32 n_pages;
  u8 *name;
  u32 *page_indices;
} clib_pmalloc_arena_t;

typedef struct
{
  /* flags */
  u32 flags;
#define CLIB_PMALLOC_F_NO_PAGEMAP (1 << 0)

  /* base VA address */
  u8 *base;

  /* default page size - typically 2M */
  u32 def_log2_page_sz;

  /* system page size - typically 4K */
  u32 sys_log2_page_sz;

  /* maximum number of pages, limited by VA preallocation size */
  u32 max_pages;

  /* vector of pages - each page have own alloc pool and it can be split
     into subpages (i.e. 2M page build out of 512 4K pages) */
  clib_pmalloc_page_t *pages;

  /* hash used to find chunk index out of VA, chunk index is defined
     per page */
  uword *chunk_index_by_va;

  /* alloc arenas are group of pages which share same attributes
     shared arenas are represented by FD and they are not grovable
     private arenas are growable */
  clib_pmalloc_arena_t *arenas;

  /* vector of per numa node alloc arena indices
     each numa node have own default privat alloc arena */
  u32 *default_arena_for_numa_node;

  /* VA to PA lookup table */
  uword *lookup_table;

  /* lookup page size - equals to smalles subpage used */
  u32 lookup_log2_page_sz;

  /* last error */
  clib_error_t *error;
} clib_pmalloc_main_t;


int clib_pmalloc_init (clib_pmalloc_main_t * pm, uword size);
void *clib_pmalloc_alloc_aligned_on_numa (clib_pmalloc_main_t * pm,
					  uword size, uword align,
					  u32 numa_node);
void *clib_pmalloc_alloc_aligned (clib_pmalloc_main_t * pm, uword size,
				  uword align);
void clib_pmalloc_free (clib_pmalloc_main_t * pm, void *va);

void *clib_pmalloc_create_shared_arena (clib_pmalloc_main_t * pm, char *name,
					uword size, u32 log2_page_sz,
					u32 numa_node);

void *clib_pmalloc_alloc_from_arena (clib_pmalloc_main_t * pm, void *arena_va,
				     uword size, uword align);

format_function_t format_pmalloc;
format_function_t format_pmalloc_map;

always_inline clib_error_t *
clib_pmalloc_last_error (clib_pmalloc_main_t * pm)
{
  return pm->error;
}

always_inline u32
clib_pmalloc_get_page_index (clib_pmalloc_main_t * pm, void *va)
{
  uword index = (pointer_to_uword (va) - pointer_to_uword (pm->base)) >>
    pm->def_log2_page_sz;

  ASSERT (index < vec_len (pm->pages));

  return index;
}

always_inline clib_pmalloc_arena_t *
clib_pmalloc_get_arena (clib_pmalloc_main_t * pm, void *va)
{
  u32 index = clib_pmalloc_get_page_index (pm, va);
  return pm->arenas + pm->pages[index].arena_index;
}

always_inline uword
clib_pmalloc_get_pa (clib_pmalloc_main_t * pm, void *va)
{
  uword index = (pointer_to_uword (va) - pointer_to_uword (pm->base)) >>
    pm->lookup_log2_page_sz;
  return pointer_to_uword (va) - pm->lookup_table[index];
}


#endif /* included_palloc_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
