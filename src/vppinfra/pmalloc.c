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

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/mempolicy.h>
#include <linux/memfd.h>

#include <vppinfra/format.h>
#include <vppinfra/linux/syscall.h>
#include <vppinfra/linux/sysfs.h>
#include <vppinfra/mem.h>
#include <vppinfra/hash.h>
#include <vppinfra/pmalloc.h>

#if __SIZEOF_POINTER__ >= 8
#define DEFAULT_RESERVED_MB 16384
#else
#define DEFAULT_RESERVED_MB 256
#endif

static inline clib_pmalloc_chunk_t *
get_chunk (clib_pmalloc_page_t * pp, u32 index)
{
  return pool_elt_at_index (pp->chunks, index);
}

static inline uword
pmalloc_size2pages (uword size, u32 log2_page_sz)
{
  return round_pow2 (size, 1ULL << log2_page_sz) >> log2_page_sz;
}

static inline int
pmalloc_validate_numa_node (u32 * numa_node)
{
  if (*numa_node == CLIB_PMALLOC_NUMA_LOCAL)
    {
      u32 cpu;
      if (getcpu (&cpu, numa_node, 0) != 0)
	return 1;
    }
  return 0;
}

int
clib_pmalloc_init (clib_pmalloc_main_t * pm, uword size)
{
  uword off, pagesize;
  u64 *pt = 0;

  ASSERT (pm->error == 0);

  pagesize = clib_mem_get_default_hugepage_size ();
  pm->def_log2_page_sz = min_log2 (pagesize);
  pm->sys_log2_page_sz = min_log2 (sysconf (_SC_PAGESIZE));
  pm->lookup_log2_page_sz = pm->def_log2_page_sz;

  /* check if pagemap is accessible */
  pt = clib_mem_vm_get_paddr (&pt, pm->sys_log2_page_sz, 1);
  if (pt == 0 || pt[0] == 0)
    pm->flags |= CLIB_PMALLOC_F_NO_PAGEMAP;

  size = size ? size : ((u64) DEFAULT_RESERVED_MB) << 20;
  size = round_pow2 (size, pagesize);

  pm->max_pages = size >> pm->def_log2_page_sz;

  /* reserve VA space for future growth */
  pm->base = mmap (0, size + pagesize, PROT_NONE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (pm->base == MAP_FAILED)
    {
      pm->error = clib_error_return_unix (0, "failed to reserve %u pages");
      return -1;
    }

  off = round_pow2 (pointer_to_uword (pm->base), pagesize) -
    pointer_to_uword (pm->base);

  /* trim start and end of reservation to be page aligned */
  if (off)
    {
      munmap (pm->base, off);
      pm->base += off;
    }

  munmap (pm->base + ((uword) pm->max_pages * pagesize), pagesize - off);
  return 0;
}

static inline void *
alloc_chunk_from_page (clib_pmalloc_main_t * pm, clib_pmalloc_page_t * pp,
		       u32 n_blocks, u32 block_align, u32 numa_node)
{
  clib_pmalloc_chunk_t *c = 0;
  clib_pmalloc_arena_t *a;
  void *va;
  u32 off;
  u32 alloc_chunk_index;

  a = pool_elt_at_index (pm->arenas, pp->arena_index);

  if (pp->chunks == 0)
    {
      u32 i, start = 0, prev = ~0;

      for (i = 0; i < a->subpages_per_page; i++)
	{
	  pool_get (pp->chunks, c);
	  c->start = start;
	  c->prev = prev;
	  c->size = pp->n_free_blocks / a->subpages_per_page;
	  start += c->size;
	  if (prev == ~0)
	    pp->first_chunk_index = c - pp->chunks;
	  else
	    pp->chunks[prev].next = c - pp->chunks;
	  prev = c - pp->chunks;
	}
      c->next = ~0;
      pp->n_free_chunks = a->subpages_per_page;
    }

  alloc_chunk_index = pp->first_chunk_index;

next_chunk:
  c = pool_elt_at_index (pp->chunks, alloc_chunk_index);
  off = (block_align - (c->start & (block_align - 1))) & (block_align - 1);

  if (c->used || n_blocks + off > c->size)
    {
      if (c->next == ~0)
	return 0;
      alloc_chunk_index = c->next;
      goto next_chunk;
    }

  /* if alignment is needed create new empty chunk */
  if (off)
    {
      u32 offset_chunk_index;
      clib_pmalloc_chunk_t *co;
      pool_get (pp->chunks, c);
      pp->n_free_chunks++;
      offset_chunk_index = alloc_chunk_index;
      alloc_chunk_index = c - pp->chunks;

      co = pool_elt_at_index (pp->chunks, offset_chunk_index);
      c->size = co->size - off;
      c->next = co->next;
      c->start = co->start + off;
      c->prev = offset_chunk_index;
      co->size = off;
      co->next = alloc_chunk_index;
    }

  c->used = 1;
  if (c->size > n_blocks)
    {
      u32 tail_chunk_index;
      clib_pmalloc_chunk_t *ct;
      pool_get (pp->chunks, ct);
      pp->n_free_chunks++;
      tail_chunk_index = ct - pp->chunks;
      c = pool_elt_at_index (pp->chunks, alloc_chunk_index);
      ct->size = c->size - n_blocks;
      ct->next = c->next;
      ct->prev = alloc_chunk_index;
      ct->start = c->start + n_blocks;

      c->size = n_blocks;
      c->next = tail_chunk_index;
      if (ct->next != ~0)
	pool_elt_at_index (pp->chunks, ct->next)->prev = tail_chunk_index;
    }
  else if (c->next != ~0)
    pool_elt_at_index (pp->chunks, c->next)->prev = alloc_chunk_index;

  c = get_chunk (pp, alloc_chunk_index);
  va = pm->base + ((pp - pm->pages) << pm->def_log2_page_sz) +
    (c->start << PMALLOC_LOG2_BLOCK_SZ);
  hash_set (pm->chunk_index_by_va, pointer_to_uword (va), alloc_chunk_index);
  pp->n_free_blocks -= n_blocks;
  pp->n_free_chunks--;
  return va;
}

static void
pmalloc_update_lookup_table (clib_pmalloc_main_t * pm, u32 first, u32 count)
{
  uword seek, va, pa, p;
  int fd;
  u32 elts_per_page = 1U << (pm->def_log2_page_sz - pm->lookup_log2_page_sz);

  vec_validate_aligned (pm->lookup_table, vec_len (pm->pages) *
			elts_per_page - 1, CLIB_CACHE_LINE_BYTES);

  p = first * elts_per_page;
  if (pm->flags & CLIB_PMALLOC_F_NO_PAGEMAP)
    {
      while (p < (uword) elts_per_page * count)
	{
	  pm->lookup_table[p] = pointer_to_uword (pm->base) +
	    (p << pm->lookup_log2_page_sz);
	  p++;
	}
      return;
    }

  fd = open ((char *) "/proc/self/pagemap", O_RDONLY);
  while (p < (uword) elts_per_page * count)
    {
      va = pointer_to_uword (pm->base) + (p << pm->lookup_log2_page_sz);
      pa = 0;
      seek = (va >> pm->sys_log2_page_sz) * sizeof (pa);
      if (fd != -1 && lseek (fd, seek, SEEK_SET) == seek &&
	  read (fd, &pa, sizeof (pa)) == (sizeof (pa)) &&
	  pa & (1ULL << 63) /* page present bit */ )
	{
	  pa = (pa & pow2_mask (55)) << pm->sys_log2_page_sz;
	}
      pm->lookup_table[p] = va - pa;
      p++;
    }

  if (fd != -1)
    close (fd);
}

static inline clib_pmalloc_page_t *
pmalloc_map_pages (clib_pmalloc_main_t * pm, clib_pmalloc_arena_t * a,
		   u32 numa_node, u32 n_pages)
{
  clib_pmalloc_page_t *pp = 0;
  int status, rv, i, mmap_flags;
  void *va;
  int old_mpol = -1;
  long unsigned int mask[16] = { 0 };
  long unsigned int old_mask[16] = { 0 };
  uword size = (uword) n_pages << pm->def_log2_page_sz;

  clib_error_free (pm->error);

  if (pm->max_pages <= vec_len (pm->pages))
    {
      pm->error = clib_error_return (0, "maximum number of pages reached");
      return 0;
    }

  if (a->log2_subpage_sz != pm->sys_log2_page_sz)
    {
      pm->error = clib_sysfs_prealloc_hugepages (numa_node,
						 a->log2_subpage_sz, n_pages);

      if (pm->error)
	return 0;
    }

  rv = get_mempolicy (&old_mpol, old_mask, sizeof (old_mask) * 8 + 1, 0, 0);
  /* failure to get mempolicy means we can only proceed with numa 0 maps */
  if (rv == -1 && numa_node != 0)
    {
      pm->error = clib_error_return_unix (0, "failed to get mempolicy");
      return 0;
    }

  mask[0] = 1 << numa_node;
  rv = set_mempolicy (MPOL_BIND, mask, sizeof (mask) * 8 + 1);
  if (rv == -1 && numa_node != 0)
    {
      pm->error = clib_error_return_unix (0, "failed to set mempolicy for "
					  "numa node %u", numa_node);
      return 0;
    }

  mmap_flags = MAP_FIXED | MAP_ANONYMOUS;

  if ((pm->flags & CLIB_PMALLOC_F_NO_PAGEMAP) == 0)
    mmap_flags |= MAP_LOCKED;

  if (a->log2_subpage_sz != pm->sys_log2_page_sz)
    mmap_flags |= MAP_HUGETLB | MAP_LOCKED;

  if (a->flags & CLIB_PMALLOC_ARENA_F_SHARED_MEM)
    {
      mmap_flags |= MAP_SHARED;
      if (mmap_flags & MAP_HUGETLB)
	pm->error = clib_mem_create_hugetlb_fd ((char *) a->name, &a->fd);
      else
	pm->error = clib_mem_create_fd ((char *) a->name, &a->fd);
      if (a->fd == -1)
	goto error;
    }
  else
    {
      mmap_flags |= MAP_PRIVATE;
      a->fd = -1;
    }

  va = pm->base + (((uword) vec_len (pm->pages)) << pm->def_log2_page_sz);
  if (mmap (va, size, PROT_READ | PROT_WRITE, mmap_flags, a->fd, 0) ==
      MAP_FAILED)
    {
      pm->error = clib_error_return_unix (0, "failed to mmap %u pages at %p "
					  "fd %d numa %d flags 0x%x", n_pages,
					  va, a->fd, numa_node, mmap_flags);
      goto error;
    }

  clib_memset (va, 0, size);

  rv = set_mempolicy (old_mpol, old_mask, sizeof (old_mask) * 8 + 1);
  if (rv == -1 && numa_node != 0)
    {
      pm->error = clib_error_return_unix (0, "failed to restore mempolicy");
      goto error;
    }

  /* we tolerate move_pages failure only if request os for numa node 0
     to support non-numa kernels */
  rv = move_pages (0, 1, &va, 0, &status, 0);
  if ((rv == 0 && status != numa_node) || (rv != 0 && numa_node != 0))
    {
      pm->error = rv == -1 ?
	clib_error_return_unix (0, "page allocated on wrong node, numa node "
				"%u status %d", numa_node, status) :
	clib_error_return (0, "page allocated on wrong node, numa node "
			   "%u status %d", numa_node, status);

      /* unmap & reesrve */
      munmap (va, size);
      mmap (va, size, PROT_NONE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
	    -1, 0);
      goto error;
    }

  for (i = 0; i < n_pages; i++)
    {
      vec_add2 (pm->pages, pp, 1);
      pp->n_free_blocks = 1 << (pm->def_log2_page_sz - PMALLOC_LOG2_BLOCK_SZ);
      pp->index = pp - pm->pages;
      pp->arena_index = a->index;
      vec_add1 (a->page_indices, pp->index);
      a->n_pages++;
    }


  /* if new arena is using smaller page size, we need to rebuild whole
     lookup table */
  if (a->log2_subpage_sz < pm->lookup_log2_page_sz)
    {
      pm->lookup_log2_page_sz = a->log2_subpage_sz;
      pmalloc_update_lookup_table (pm, vec_len (pm->pages) - n_pages,
				   n_pages);
    }
  else
    pmalloc_update_lookup_table (pm, 0, vec_len (pm->pages));

  /* return pointer to 1st page */
  return pp - (n_pages - 1);

error:
  if (a->fd != -1)
    close (a->fd);
  return 0;
}

void *
clib_pmalloc_create_shared_arena (clib_pmalloc_main_t * pm, char *name,
				  uword size, u32 log2_page_sz, u32 numa_node)
{
  clib_pmalloc_arena_t *a;
  clib_pmalloc_page_t *pp;
  u32 n_pages;

  clib_error_free (pm->error);

  if (log2_page_sz == 0)
    log2_page_sz = pm->def_log2_page_sz;
  else if (log2_page_sz != pm->def_log2_page_sz &&
	   log2_page_sz != pm->sys_log2_page_sz)
    {
      pm->error = clib_error_create ("unsupported page size (%uKB)",
				     1 << (log2_page_sz - 10));
      return 0;
    }

  n_pages = pmalloc_size2pages (size, pm->def_log2_page_sz);

  if (n_pages + vec_len (pm->pages) > pm->max_pages)
    return 0;

  if (pmalloc_validate_numa_node (&numa_node))
    return 0;

  pool_get (pm->arenas, a);
  a->index = a - pm->arenas;
  a->name = format (0, "%s%c", name, 0);
  a->numa_node = numa_node;
  a->flags = CLIB_PMALLOC_ARENA_F_SHARED_MEM;
  a->log2_subpage_sz = log2_page_sz;
  a->subpages_per_page = 1U << (pm->def_log2_page_sz - log2_page_sz);

  if ((pp = pmalloc_map_pages (pm, a, numa_node, n_pages)) == 0)
    {
      vec_free (a->name);
      memset (a, 0, sizeof (*a));
      pool_put (pm->arenas, a);
      return 0;
    }

  return pm->base + (pp->index << pm->def_log2_page_sz);
}

static inline void *
clib_pmalloc_alloc_inline (clib_pmalloc_main_t * pm, clib_pmalloc_arena_t * a,
			   uword size, uword align, u32 numa_node)
{
  clib_pmalloc_page_t *pp;
  u32 n_blocks, block_align, *page_index;

  ASSERT (is_pow2 (align));

  if (pmalloc_validate_numa_node (&numa_node))
    return 0;

  if (a == 0)
    {
      if (size > 1ULL << pm->def_log2_page_sz)
	return 0;

      vec_validate_init_empty (pm->default_arena_for_numa_node,
			       numa_node, ~0);
      if (pm->default_arena_for_numa_node[numa_node] == ~0)
	{
	  pool_get (pm->arenas, a);
	  pm->default_arena_for_numa_node[numa_node] = a - pm->arenas;
	  a->name = format (0, "default-numa-%u%c", numa_node, 0);
	  a->numa_node = numa_node;
	  a->log2_subpage_sz = pm->def_log2_page_sz;
	  a->subpages_per_page = 1;
	}
      else
	a = pool_elt_at_index (pm->arenas,
			       pm->default_arena_for_numa_node[numa_node]);
    }
  else if (size > 1ULL << a->log2_subpage_sz)
    return 0;

  n_blocks = round_pow2 (size, PMALLOC_BLOCK_SZ) / PMALLOC_BLOCK_SZ;
  block_align = align >> PMALLOC_LOG2_BLOCK_SZ;

  vec_foreach (page_index, a->page_indices)
  {
    pp = vec_elt_at_index (pm->pages, *page_index);
    void *rv = alloc_chunk_from_page (pm, pp, n_blocks, block_align,
				      numa_node);

    if (rv)
      return rv;
  }

  if ((a->flags & CLIB_PMALLOC_ARENA_F_SHARED_MEM) == 0 &&
      (pp = pmalloc_map_pages (pm, a, numa_node, 1)))
    return alloc_chunk_from_page (pm, pp, n_blocks, block_align, numa_node);

  return 0;
}

void *
clib_pmalloc_alloc_aligned_on_numa (clib_pmalloc_main_t * pm, uword size,
				    uword align, u32 numa_node)
{
  return clib_pmalloc_alloc_inline (pm, 0, size, align, numa_node);
}

void *
clib_pmalloc_alloc_aligned (clib_pmalloc_main_t * pm, uword size, uword align)
{
  return clib_pmalloc_alloc_inline (pm, 0, size, align,
				    CLIB_PMALLOC_NUMA_LOCAL);
}

void *
clib_pmalloc_alloc_from_arena (clib_pmalloc_main_t * pm, void *arena_va,
			       uword size, uword align)
{
  clib_pmalloc_arena_t *a = clib_pmalloc_get_arena (pm, arena_va);
  return clib_pmalloc_alloc_inline (pm, a, size, align, 0);
}

static inline int
pmalloc_chunks_mergeable (clib_pmalloc_arena_t * a, clib_pmalloc_page_t * pp,
			  u32 ci1, u32 ci2)
{
  clib_pmalloc_chunk_t *c1, *c2;

  if (ci1 == ~0 || ci2 == ~0)
    return 0;

  c1 = get_chunk (pp, ci1);
  c2 = get_chunk (pp, ci2);

  if (c1->used || c2->used)
    return 0;

  if (c1->start >> (a->log2_subpage_sz - PMALLOC_LOG2_BLOCK_SZ) !=
      c2->start >> (a->log2_subpage_sz - PMALLOC_LOG2_BLOCK_SZ))
    return 0;

  return 1;
}

void
clib_pmalloc_free (clib_pmalloc_main_t * pm, void *va)
{
  clib_pmalloc_page_t *pp;
  clib_pmalloc_chunk_t *c;
  clib_pmalloc_arena_t *a;
  uword *p;
  u32 chunk_index, page_index;

  p = hash_get (pm->chunk_index_by_va, pointer_to_uword (va));

  if (p == 0)
    os_panic ();

  chunk_index = p[0];
  page_index = clib_pmalloc_get_page_index (pm, va);
  hash_unset (pm->chunk_index_by_va, pointer_to_uword (va));

  pp = vec_elt_at_index (pm->pages, page_index);
  c = pool_elt_at_index (pp->chunks, chunk_index);
  a = pool_elt_at_index (pm->arenas, pp->arena_index);
  c->used = 0;
  pp->n_free_blocks += c->size;
  pp->n_free_chunks++;

  /* merge with next if free */
  if (pmalloc_chunks_mergeable (a, pp, chunk_index, c->next))
    {
      clib_pmalloc_chunk_t *next = get_chunk (pp, c->next);
      c->size += next->size;
      c->next = next->next;
      if (next->next != ~0)
	get_chunk (pp, next->next)->prev = chunk_index;
      memset (next, 0, sizeof (*next));
      pool_put (pp->chunks, next);
      pp->n_free_chunks--;
    }

  /* merge with prev if free */
  if (pmalloc_chunks_mergeable (a, pp, c->prev, chunk_index))
    {
      clib_pmalloc_chunk_t *prev = get_chunk (pp, c->prev);
      prev->size += c->size;
      prev->next = c->next;
      if (c->next != ~0)
	get_chunk (pp, c->next)->prev = c->prev;
      memset (c, 0, sizeof (*c));
      pool_put (pp->chunks, c);
      pp->n_free_chunks--;
    }
}

static u8 *
format_log2_page_size (u8 * s, va_list * va)
{
  u32 log2_page_sz = va_arg (*va, u32);

  if (log2_page_sz >= 30)
    return format (s, "%uGB", 1 << (log2_page_sz - 30));

  if (log2_page_sz >= 20)
    return format (s, "%uMB", 1 << (log2_page_sz - 20));

  if (log2_page_sz >= 10)
    return format (s, "%uKB", 1 << (log2_page_sz - 10));

  return format (s, "%uB", 1 << log2_page_sz);
}


static u8 *
format_pmalloc_page (u8 * s, va_list * va)
{
  clib_pmalloc_page_t *pp = va_arg (*va, clib_pmalloc_page_t *);
  int verbose = va_arg (*va, int);
  u32 indent = format_get_indent (s);

  s = format (s, "page %u: phys-addr %p ", pp->index, pp->pa);

  if (pp->chunks == 0)
    return s;

  s = format (s, "free %u chunks %u free-chunks %d ",
	      (pp->n_free_blocks) << PMALLOC_LOG2_BLOCK_SZ,
	      pool_elts (pp->chunks), pp->n_free_chunks);

  if (verbose >= 2)
    {
      clib_pmalloc_chunk_t *c;
      c = pool_elt_at_index (pp->chunks, pp->first_chunk_index);
      s = format (s, "\n%U%12s%12s%8s%8s%8s%8s",
		  format_white_space, indent + 2,
		  "chunk offset", "size", "used", "index", "prev", "next");
      while (1)
	{
	  s = format (s, "\n%U%12u%12u%8s%8d%8d%8d",
		      format_white_space, indent + 2,
		      c->start << PMALLOC_LOG2_BLOCK_SZ,
		      c->size << PMALLOC_LOG2_BLOCK_SZ,
		      c->used ? "yes" : "no",
		      c - pp->chunks, c->prev, c->next);
	  if (c->next == ~0)
	    break;
	  c = pool_elt_at_index (pp->chunks, c->next);
	}
    }
  return s;
}

u8 *
format_pmalloc (u8 * s, va_list * va)
{
  clib_pmalloc_main_t *pm = va_arg (*va, clib_pmalloc_main_t *);
  int verbose = va_arg (*va, int);
  u32 indent = format_get_indent (s);

  clib_pmalloc_page_t *pp;
  clib_pmalloc_arena_t *a;

  s = format (s, "used-pages %u reserved-pages %u default-page-size %U "
	      "lookup-page-size %U%s", vec_len (pm->pages), pm->max_pages,
	      format_log2_page_size, pm->def_log2_page_sz,
	      format_log2_page_size, pm->lookup_log2_page_sz,
	      pm->flags & CLIB_PMALLOC_F_NO_PAGEMAP ? " no-pagemap" : "");


  if (verbose >= 2)
    s = format (s, " va-start %p", pm->base);

  if (pm->error)
    s = format (s, "\n%Ulast-error: %U", format_white_space, indent + 2,
		format_clib_error, pm->error);


  /* *INDENT-OFF* */
  pool_foreach (a, pm->arenas,
    {
      u32 *page_index;
      s = format (s, "\n%Uarena '%s' pages %u subpage-size %U numa-node %u",
		  format_white_space, indent + 2, a->name,
		  vec_len (a->page_indices), format_log2_page_size,
		  a->log2_subpage_sz, a->numa_node);
      if (a->fd != -1)
        s = format (s, " shared fd %d", a->fd);
      if (verbose >= 1)
	vec_foreach (page_index, a->page_indices)
	  {
	    pp = vec_elt_at_index (pm->pages, *page_index);
	    s = format (s, "\n%U%U", format_white_space, indent + 4,
			format_pmalloc_page, pp, verbose);
	  }
    });
  /* *INDENT-ON* */

  if (verbose >= 3)
    {
      u32 index, size = 0, combined = 0;
      s =
	format (s, "\n %16s %13s %8s", "virtual-addr", "physical-addr",
		"size");
      vec_foreach_index (index, pm->lookup_table)
      {
	uword *lookup_val, pa, va;
	lookup_val = vec_elt_at_index (pm->lookup_table, index);
	va = pointer_to_uword (pm->base) + (index << pm->lookup_log2_page_sz);
	pa = va - *lookup_val;
	if (pa != 0)
	  s =
	    format (s, "\n %16p %13p %8U", uword_to_pointer (va, u64),
		    uword_to_pointer (pa, u64), format_log2_page_size,
		    pm->lookup_log2_page_sz);
	else
	  {
	    combined = 1;
	    size += pm->lookup_log2_page_sz;
	  }
      }
      if (combined)
	s =
	  format (s, "\n %16p %13p %8U", pm->base, 0, format_log2_page_size,
		  size);
    }

  return s;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
