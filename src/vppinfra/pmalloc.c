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

#define PMALLOC_LOG2_BLOCK_SZ     6
#define PMALLOC_BLOCK_SZ               (1 << 6)

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
  char *name;
  int handle;
  int fd;
  u8 *start;
  uword pagesize;
  u32 max_pages;

  clib_pmalloc_page_t *pages;

  uword *chunk_index_by_va;

} clib_pmalloc_main_t;

static clib_pmalloc_main_t *clib_pmalloc_mains = 0;

static inline clib_pmalloc_chunk_t *
get_chunk (clib_pmalloc_page_t * pp, u32 index)
{
  return pool_elt_at_index (pp->chunks, index);
}

int
clib_pmalloc_init (char *name, uword max_pages)
{
  clib_pmalloc_main_t *pm;
  struct stat st;
  uword off;

  pool_get (clib_pmalloc_mains, pm);
  pm->name = name;
  pm->handle = pm - clib_pmalloc_mains;

  pm->fd = memfd_create (name, MFD_HUGETLB);
  if (pm->fd == -1)
    goto error;

  if (fstat (pm->fd, &st) == -1)
    goto error;
  pm->pagesize = st.st_blksize;
  pm->max_pages = max_pages;

  /* reserve VA space for future growth */
  pm->start = mmap (0, (max_pages + 1) * pm->pagesize, PROT_NONE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  off = pm->pagesize - (((off_t) pm->start) & (pm->pagesize - 1));
  off &= pm->pagesize - 1;

  /* trim start and end of reservation to be page aligned */
  if (off)
    {
      munmap (pm->start, off);
      pm->start += off;
    }
  munmap (pm->start + (max_pages * pm->pagesize), pm->pagesize - off);

  return pm->handle;

error:
  if (pm->fd != -1)
    close (pm->fd);
  memset (pm, 0, sizeof (*pm));
  pool_put (clib_pmalloc_mains, pm);
  return -1;
}

static inline void *
alloc_chunk_from_page (clib_pmalloc_main_t * pm, clib_pmalloc_page_t * pp,
		       u32 n_blocks, u32 block_align, u32 numa_node)
{
  clib_pmalloc_chunk_t *c;
  void *va;
  u32 off;
  u32 alloc_chunk_index = pp->first_chunk_index;

  if (pp->numa_node != numa_node)
    return 0;

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

static clib_pmalloc_page_t *
pmalloc_map_page (clib_pmalloc_main_t * pm, u32 numa_node)
{
  clib_pmalloc_page_t *pp;
  clib_pmalloc_chunk_t *c;
  u64 seek, pa, sys_page_size;
  int fd, status, rv;
  void *va;
  int old_mpol = -1;
  long unsigned int mask[16] = { 0 };
  long unsigned int old_mask[16] = { 0 };

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
  va = mmap (va, pm->pagesize, PROT_READ | PROT_WRITE,
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
	  munmap (va, pm->pagesize);
	  mmap (va, pm->pagesize, PROT_NONE,
		MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	  return 0;
	}
      if (status != numa_node)
	clib_warning ("page %p allocated on the wrong numa node (%d)",
		      va, status);
    }

  memset (va, 0, pm->pagesize);
  vec_add2 (pm->pages, pp, 1);
  pp->n_free_blocks = pm->pagesize / PMALLOC_BLOCK_SZ;
  pp->numa_node = numa_node;

  pool_get (pp->chunks, c);
  pp->n_free_chunks = 1;
  pp->first_chunk_index = c - pp->chunks;
  c->prev = c->next = ~0;
  c->size = pp->n_free_blocks;

  sys_page_size = sysconf (_SC_PAGESIZE);
  seek = (pointer_to_uword (va) / sys_page_size) * sizeof (pa);
  if ((fd = open ((char *) "/proc/self/pagemap", O_RDONLY)) != -1 &&
      lseek (fd, seek, SEEK_SET) == seek &&
      read (fd, &pa, sizeof (pa)) == (sizeof (pa)) &&
      pa & (1ULL << 63) /* page present bit */ )
    {
      pp->pa = (pa & pow2_mask (55)) * sys_page_size;
    }



  return pp;
}

void *
clib_pmalloc_alloc_aligned_on_numa (int handle, uword size, uword align,
				    u32 numa_node)
{
  clib_pmalloc_main_t *pm;
  clib_pmalloc_page_t *pp;

  ASSERT (is_pow2 (align));

  pm = pool_elt_at_index (clib_pmalloc_mains, handle);

  u32 n_blocks = ((size - 1) >> PMALLOC_LOG2_BLOCK_SZ) + 1;
  u32 block_align = align >> PMALLOC_LOG2_BLOCK_SZ;

  vec_foreach (pp, pm->pages)
  {
    void *rv = alloc_chunk_from_page (pm, pp, n_blocks, block_align,
				      numa_node);

    if (rv)
      return rv;
  }

  if (numa_node == CLIB_PMALLOC_NUMA_LOCAL)
    {
      u32 cpu;
      if (getcpu(&cpu, &numa_node, 0) !=0)
	return 0;
    }

  pp = pmalloc_map_page (pm, numa_node);

  if (pp)
    return alloc_chunk_from_page (pm, pp, n_blocks, block_align, numa_node);

  return 0;
}

void
clib_pmalloc_free (int handle, void *va)
{
  clib_pmalloc_main_t *pm;
  clib_pmalloc_page_t *pp;
  clib_pmalloc_chunk_t *c;
  uword *p;
  u32 chunk_index, page_index;

  pm = pool_elt_at_index (clib_pmalloc_mains, handle);
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
  int handle = va_arg (*va, int);
  int verbose = va_arg (*va, int);
  u32 indent = format_get_indent (s);

  clib_pmalloc_main_t *pm;
  clib_pmalloc_page_t *pp;

  pm = pool_elt_at_index (clib_pmalloc_mains, handle);

  s = format (s, "num-pages %u", vec_len (pm->pages));

  vec_foreach (pp, pm->pages)
  {
    s = format (s, "\n%Upage %u: pa %p numa %u total %u free %u chunks %u "
		"free-chunks %d ",
		format_white_space, indent + 2,
		pp - pm->pages, pp->pa, pp->numa_node,
		pm->pagesize >> PMALLOC_LOG2_BLOCK_SZ,
		(pp->n_free_blocks) * PMALLOC_BLOCK_SZ,
		pool_elts (pp->chunks), pp->n_free_chunks);
    if (verbose)
      {
	clib_pmalloc_chunk_t *c;
	c = pool_elt_at_index (pp->chunks, pp->first_chunk_index);
	while (1)
	  {
	    s = format (s, "\n%Ustart %5u blocks %5u%s [%4d,%4d,%4d]",
			format_white_space, indent + 4,
			c->start, c->size,
			c->used ? " used" : "",
			c->prev, c - pp->chunks, c->next);
	    if (c->next == ~0)
	      break;
	    c = pool_elt_at_index (pp->chunks, c->next);
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
