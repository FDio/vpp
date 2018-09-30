#include <iacaMarks.h>

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/mempolicy.h>
#include <linux/memfd.h>

#include <vppinfra/format.h>
#include <vppinfra/linux/syscall.h>
#include <vppinfra/mem.h>
#include <vppinfra/pool.h>
#include <vppinfra/hash.h>
#include <vppinfra/pmalloc.h>

#ifndef MFD_HUGETLB
#define MFD_HUGETLB 0x0004U
#endif

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

int
clib_pmalloc_init (clib_pmalloc_main_t * pm, uword max_pages)
{
  struct stat st;
  uword off;
  int fd;

  pm->pagesize = 2 << 20;
  if ((fd = memfd_create ("detect_hugepage_size", MFD_HUGETLB)) != -1)
    {
      if (fstat (fd, &st) == -1)
	pm->pagesize = st.st_blksize;
      close (fd);
    }

  if (max_pages == 0)
    max_pages = (((u64) DEFAULT_RESERVED_MB) << 20) / pm->pagesize;

  pm->max_pages = max_pages;

  /* reserve VA space for future growth */
  pm->start = mmap (0, (max_pages + 1) * pm->pagesize, PROT_NONE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (pm->start == MAP_FAILED)
    return -1;

  off = pm->pagesize - (((off_t) pm->start) & (pm->pagesize - 1));
  off &= pm->pagesize - 1;

  /* trim start and end of reservation to be page aligned */
  if (off)
    {
      munmap (pm->start, off);
      pm->start += off;
    }
  munmap (pm->start + (max_pages * pm->pagesize), pm->pagesize - off);
  return 0;
}

static inline void *
alloc_chunk_from_page (clib_pmalloc_main_t * pm, clib_pmalloc_page_t * pp,
		       u32 n_blocks, u32 block_align, u32 numa_node)
{
  clib_pmalloc_chunk_t *c;
  void *va;
  u32 off;
  u32 alloc_chunk_index;

  if (pp->chunks == 0)
    {
      pool_get (pp->chunks, c);
      pp->n_free_chunks = 1;
      pp->first_chunk_index = c - pp->chunks;
      c->prev = c->next = ~0;
      c->size = pp->n_free_blocks;
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
  va = pm->start + (pm->pagesize * (pp - pm->pages)) +
    (c->start << PMALLOC_LOG2_BLOCK_SZ);
  hash_set (pm->chunk_index_by_va, pointer_to_uword (va), alloc_chunk_index);
  pp->n_free_blocks -= n_blocks;
  pp->n_free_chunks--;
  return va;
}

static inline clib_pmalloc_page_t *
pmalloc_map_pages (clib_pmalloc_main_t * pm, clib_pmalloc_arena_t * a,
		   u32 numa_node, u32 n_pages)
{
  clib_pmalloc_page_t *pp;
  u64 seek, pa, sys_page_size;
  int pagemap_fd, status, rv;
  void *va;
  int old_mpol = -1;
  long unsigned int mask[16] = { 0 };
  long unsigned int old_mask[16] = { 0 };
  int i;

  if (pm->max_pages <= vec_len (pm->pages))
    return 0;

  rv = get_mempolicy (&old_mpol, old_mask, sizeof (old_mask) * 8 + 1, 0, 0);
  /* failure to get mempolicy means we can only proceed with numa 0 maps */
  if (rv == -1 && numa_node != 0)
    return 0;

  mask[0] = 1 << numa_node;
  rv = set_mempolicy (MPOL_BIND, mask, sizeof (mask) * 8 + 1);
  if (rv == -1 && numa_node != 0)
    return 0;

  va = pm->start + vec_len (pm->pages) * pm->pagesize;
  va = mmap (va, pm->pagesize * n_pages, PROT_READ | PROT_WRITE,
	     MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB |
	     MAP_LOCKED, -1, 0);

  if (va == MAP_FAILED)
    return 0;

  rv = set_mempolicy (old_mpol, old_mask, sizeof (old_mask) * 8 + 1);
  if (rv == -1 && numa_node != 0)
    return 0;

  /* we tolerate move_pages failure only if request os for numa node 0
     to support non-numa kernels */
  status = numa_node;
  if (move_pages (0, 1, &va, 0, &status, 0) != 0 || status != numa_node)
    {
      if (numa_node != 0)
	{
	  /* unmap & reesrve */
	  munmap (va, pm->pagesize * n_pages);
	  mmap (va, pm->pagesize * n_pages, PROT_NONE,
		MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	  return 0;
	}
      if (status != numa_node)
	clib_warning ("page %p allocated on the wrong numa node (%d)",
		      va, status);
    }

  memset (va, 0, pm->pagesize * n_pages);
  sys_page_size = sysconf (_SC_PAGESIZE);
  pagemap_fd = open ((char *) "/proc/self/pagemap", O_RDONLY);

  for (i = 0; i < n_pages; i++)
    {
      vec_add2 (pm->pages, pp, 1);
      pp->n_free_blocks = pm->pagesize / PMALLOC_BLOCK_SZ;
      pp->index = pp - pm->pages;

      vec_add1 (a->page_indices, pp->index);

      seek = (pointer_to_uword ((u8 *) va + i * pm->pagesize) /
	      sys_page_size) * sizeof (pa);
      if (pagemap_fd != -1 &&
	  lseek (pagemap_fd, seek, SEEK_SET) == seek &&
	  read (pagemap_fd, &pa, sizeof (pa)) == (sizeof (pa)) &&
	  pa & (1ULL << 63) /* page present bit */ )
	{
	  pp->pa = (pa & pow2_mask (55)) * sys_page_size;
	}
    }

  if (pagemap_fd != -1)
    close (pagemap_fd);

  return pp;
}

clib_pmalloc_arena_t *
clib_pmalloc_create_shared_arena (clib_pmalloc_main_t * pm, char *name,
				  uword size, u32 numa)
{

  return 0;
}

static inline void *
clib_pmalloc_alloc_inline (clib_pmalloc_main_t * pm, uword size,
			   uword align, u32 numa_node)
{
  clib_pmalloc_arena_t *a;
  clib_pmalloc_page_t *pp;
  u32 n_blocks, block_align, *page_index;

  ASSERT (is_pow2 (align));

  if (numa_node == CLIB_PMALLOC_NUMA_LOCAL)
    {
      u32 cpu;
      if (getcpu (&cpu, &numa_node, 0) != 0)
	return 0;
    }

  vec_validate_init_empty (pm->default_arena_for_numa_node, numa_node, ~0);
  if (pm->default_arena_for_numa_node[numa_node] == ~0)
    {
      pool_get (pm->arenas, a);
      pm->default_arena_for_numa_node[numa_node] = a - pm->arenas;
      a->name = format (0, "default-numa-%u", numa_node);
      a->numa_node = numa_node;
    }
  else
    a = pool_elt_at_index (pm->arenas,
			   pm->default_arena_for_numa_node[numa_node]);

  n_blocks = ((size - 1) >> PMALLOC_LOG2_BLOCK_SZ) + 1;
  block_align = align >> PMALLOC_LOG2_BLOCK_SZ;

  vec_foreach (page_index, a->page_indices)
  {
    pp = vec_elt_at_index (pm->pages, *page_index);
    void *rv = alloc_chunk_from_page (pm, pp, n_blocks, block_align,
				      numa_node);

    if (rv)
      return rv;
  }

  if ((pp = pmalloc_map_pages (pm, a, numa_node, 1)))
    return alloc_chunk_from_page (pm, pp, n_blocks, block_align, numa_node);

  return 0;
}

void *
clib_pmalloc_alloc_aligned_on_numa (clib_pmalloc_main_t * pm, uword size,
				    uword align, u32 numa_node)
{
  return clib_pmalloc_alloc_inline (pm, size, align, numa_node);
}

void *
clib_pmalloc_alloc_aligned (clib_pmalloc_main_t * pm, uword size, uword align)
{
  return clib_pmalloc_alloc_inline (pm, size, align, CLIB_PMALLOC_NUMA_LOCAL);
}

void
clib_pmalloc_free (clib_pmalloc_main_t * pm, void *va)
{
  clib_pmalloc_page_t *pp;
  clib_pmalloc_chunk_t *c;
  uword *p;
  u32 chunk_index, page_index;

  p = hash_get (pm->chunk_index_by_va, pointer_to_uword (va));

  if (p == 0)
    os_panic ();

  chunk_index = p[0];
  page_index = ((u8 *) va - pm->start) / pm->pagesize;
  hash_unset (pm->chunk_index_by_va, pointer_to_uword (va));

  pp = vec_elt_at_index (pm->pages, page_index);
  c = pool_elt_at_index (pp->chunks, chunk_index);
  c->used = 0;
  pp->n_free_blocks += c->size;
  pp->n_free_chunks++;

  /* merge with next if free */
  if (c->next != ~0 && get_chunk (pp, c->next)->used == 0)
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
  if (c->prev != ~0 && get_chunk (pp, c->prev)->used == 0)
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

u8 *
format_pmalloc (u8 * s, va_list * va)
{
  clib_pmalloc_main_t *pm = va_arg (*va, clib_pmalloc_main_t *);
  int verbose = va_arg (*va, int);
  u32 indent = format_get_indent (s);

  clib_pmalloc_page_t *pp;
  clib_pmalloc_arena_t *a;

  s = format (s, "num-pages %u", vec_len (pm->pages));

  vec_foreach (a, pm->arenas)
  {
    u32 *page_index;
    s = format (s, "\n%Uarena '%s' pages %u numa-node %u",
		format_white_space, indent + 2,
		a->name, vec_len (a->page_indices), a->numa_node);
    vec_foreach (page_index, a->page_indices)
    {
      pp = vec_elt_at_index (pm->pages, *page_index);
      s = format (s, "\n%Upage %u: pa %p total %u free %u chunks %u "
		  "free-chunks %d ",
		  format_white_space, indent + 4,
		  pp - pm->pages, pp->pa,
		  pm->pagesize >> PMALLOC_LOG2_BLOCK_SZ,
		  (pp->n_free_blocks) * PMALLOC_BLOCK_SZ,
		  pool_elts (pp->chunks), pp->n_free_chunks);
      if (verbose >= 2)
	{
	  clib_pmalloc_chunk_t *c;
	  c = pool_elt_at_index (pp->chunks, pp->first_chunk_index);
	  while (1)
	    {
	      s = format (s, "\n%Ustart %5u blocks %5u%s [%4d,%4d,%4d]",
			  format_white_space, indent + 6,
			  c->start, c->size,
			  c->used ? " used" : "",
			  c->prev, c - pp->chunks, c->next);
	      if (c->next == ~0)
		break;
	      c = pool_elt_at_index (pp->chunks, c->next);
	    }
	}
    }

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
