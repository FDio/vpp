/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
  clib_mem_page_sz_t def_log2_page_sz;

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
  uword linear_pa_offset;
  u8 linear_pa;

  /* lookup page size - equals to smalles subpage used */
  u32 lookup_log2_page_sz;

  /* last error */
  clib_error_t *error;
} clib_pmalloc_main_t;


int clib_pmalloc_init (clib_pmalloc_main_t * pm, uword base_addr, uword size);
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

always_inline void
clib_pmalloc_convert_to_phys_addrs_with_offset (clib_pmalloc_main_t *pm, uword *a, u32 n_addrs,
						i32 offset)
{
  uword base = pointer_to_uword (pm->base);
  uword *lookup_table = pm->lookup_table;
  u32 shift = pm->lookup_log2_page_sz;

  if (PREDICT_TRUE (pm->linear_pa))
    {
      uword pa_offset = pm->linear_pa_offset;
#if defined(CLIB_HAVE_VEC128) && uword_bits == 64
      u64x2 lookup2 = u64x2_splat (pa_offset);
      u64x2 offset2 = u64x2_splat (offset);
      u64x2u *av = (u64x2u *) a;

      while (n_addrs >= 8)
	{
	  av[0] = av[0] - lookup2 + offset2;
	  av[1] = av[1] - lookup2 + offset2;
	  av[2] = av[2] - lookup2 + offset2;
	  av[3] = av[3] - lookup2 + offset2;
	  av += 4;
	  n_addrs -= 8;
	}

      while (n_addrs >= 2)
	{
	  av[0] = av[0] - lookup2 + offset2;
	  av++;
	  n_addrs -= 2;
	}

      a = (uword *) av;
#else
      while (n_addrs >= 4)
	{
	  a[0] = a[0] - pa_offset + offset;
	  a[1] = a[1] - pa_offset + offset;
	  a[2] = a[2] - pa_offset + offset;
	  a[3] = a[3] - pa_offset + offset;
	  a += 4;
	  n_addrs -= 4;
	}
#endif

      while (n_addrs)
	{
	  a[0] = a[0] - pa_offset + offset;
	  a++;
	  n_addrs--;
	}
      return;
    }

#if defined(CLIB_HAVE_VEC128) && uword_bits == 64
  u64x2 base2 = u64x2_splat (base);
  u64x2 offset2 = u64x2_splat (offset);
  u64x2u *av = (u64x2u *) a;

  while (n_addrs >= 8)
    {
      u64x2 va0 = av[0];
      u64x2 va1 = av[1];
      u64x2 va2 = av[2];
      u64x2 va3 = av[3];
      u64x2 index0 = (va0 - base2) >> shift;
      u64x2 index1 = (va1 - base2) >> shift;
      u64x2 index2 = (va2 - base2) >> shift;
      u64x2 index3 = (va3 - base2) >> shift;

      u64x2 lookup0 = {
	lookup_table[index0[0]],
	lookup_table[index0[1]],
      };
      u64x2 lookup1 = {
	lookup_table[index1[0]],
	lookup_table[index1[1]],
      };
      u64x2 lookup2 = {
	lookup_table[index2[0]],
	lookup_table[index2[1]],
      };
      u64x2 lookup3 = {
	lookup_table[index3[0]],
	lookup_table[index3[1]],
      };

      av[0] = va0 - lookup0 + offset2;
      av[1] = va1 - lookup1 + offset2;
      av[2] = va2 - lookup2 + offset2;
      av[3] = va3 - lookup3 + offset2;
      av += 4;
      n_addrs -= 8;
    }

  while (n_addrs >= 2)
    {
      u64x2 va = av[0];
      u64x2 index = (va - base2) >> shift;
      u64x2 lookup = {
	lookup_table[index[0]],
	lookup_table[index[1]],
      };

      av[0] = va - lookup + offset2;
      av += 1;
      n_addrs -= 2;
    }

  a = (uword *) av;
#else
  while (n_addrs >= 4)
    {
      uword va0 = a[0];
      uword va1 = a[1];
      uword va2 = a[2];
      uword va3 = a[3];

      a[0] = va0 - lookup_table[(va0 - base) >> shift] + offset;
      a[1] = va1 - lookup_table[(va1 - base) >> shift] + offset;
      a[2] = va2 - lookup_table[(va2 - base) >> shift] + offset;
      a[3] = va3 - lookup_table[(va3 - base) >> shift] + offset;
      a += 4;
      n_addrs -= 4;
    }
#endif

  while (n_addrs)
    {
      uword va = a[0];

      a[0] = va - lookup_table[(va - base) >> shift] + offset;
      a++;
      n_addrs--;
    }
}

always_inline void
clib_pmalloc_convert_to_phys_addrs (clib_pmalloc_main_t *pm, uword *a, u32 n_addrs)
{
  clib_pmalloc_convert_to_phys_addrs_with_offset (pm, a, n_addrs, 0);
}

#endif /* included_palloc_h */
