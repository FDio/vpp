#include <iacaMarks.h>

#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/stat.h>
#include <linux/mempolicy.h>
#include <linux/memfd.h>

#include <vppinfra/format.h>
#include <vppinfra/linux/syscall.h>
#include <vppinfra/mem.h>
#include <vppinfra/pool.h>
#include <vppinfra/hash.h>

#define MFD_HUGETLB 0x0004U

#define PMALLOC_LOG2_BLOCK_SZ     6
#define PMALLOC_BLOCK_SZ               (1 << 6)

typedef struct
{
  u32 start, size, prev, next;
  u8 flags;
#define CLIB_PMALLOC_F_USED 1
  u8 numa;
} clib_pmalloc_chunk_t;

STATIC_ASSERT_SIZEOF (clib_pmalloc_chunk_t, 20);

typedef struct
{
  char *name;
  int handle;
  int fd;
  u8 *start;
  uword pagesize;

  clib_pmalloc_chunk_t *chunks;
  u32 first_chunk_index;
  uword *chunk_index_by_va;

  u32 n_blocks;
  u32 n_free_blocks;
  u32 n_free_chunks;
} clib_pmalloc_main_t;

static clib_pmalloc_main_t *clib_pmalloc_mains = 0;

static inline clib_pmalloc_chunk_t *
get_chunk (clib_pmalloc_main_t * pm, u32 index)
{
  return pool_elt_at_index (pm->chunks, index);
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
alloc_chunk (clib_pmalloc_main_t * pm, clib_pmalloc_chunk_t * c, u32 n_blocks,
	     u32 block_align)
{
  void *va = 0;
  u32 off = ((0 - c->start) & (block_align - 1)) & (block_align - 1);
  u32 alloc_chunk_index = c - pm->chunks;

  if (c->flags & CLIB_PMALLOC_F_USED)
    return 0;

  if (n_blocks + off > c->size)
    return 0;

  /* if alignment is needed create new empty chunk */
  if (off)
    {
      u32 offset_chunk_index;
      clib_pmalloc_chunk_t *co;
      pool_get (pm->chunks, c);
      pm->n_free_chunks++;
      offset_chunk_index = alloc_chunk_index;
      alloc_chunk_index = c - pm->chunks;

      co = pool_elt_at_index (pm->chunks, offset_chunk_index);
      c->size = co->size - off;
      c->next = co->next;
      c->start = co->start + off;
      c->prev = offset_chunk_index;
      co->size = off;
      co->next = alloc_chunk_index;
    }

  c->flags |= CLIB_PMALLOC_F_USED;
  if (c->size > n_blocks)
    {
      u32 tail_chunk_index;
      clib_pmalloc_chunk_t *ct;
      pool_get (pm->chunks, ct);
      pm->n_free_chunks++;
      tail_chunk_index = ct - pm->chunks;
      c = pool_elt_at_index (pm->chunks, alloc_chunk_index);
      ct->size = c->size - n_blocks;
      ct->next = c->next;
      ct->prev = alloc_chunk_index;
      ct->start = c->start + n_blocks;

      c->size = n_blocks;
      c->next = tail_chunk_index;
      if (ct->next != ~0)
	pool_elt_at_index (pm->chunks, ct->next)->prev = tail_chunk_index;
    }
  else if (c->next != ~0)
    pool_elt_at_index (pm->chunks, c->next)->prev = alloc_chunk_index;

  c = get_chunk (pm, alloc_chunk_index);
  va = pm->start + (c->start << PMALLOC_LOG2_BLOCK_SZ);
  hash_set (pm->chunk_index_by_va, pointer_to_uword (va), alloc_chunk_index);
  pm->n_free_blocks -= n_blocks;
  pm->n_free_chunks--;

  ASSERT (hash_elts (pm->chunk_index_by_va) ==
	  pool_elts (pm->chunks) - pm->n_free_chunks);
  return va;
}

void *
clib_pmalloc_alloc_aligned (int handle, uword size, uword align)
{
  clib_pmalloc_main_t *pm;
  clib_pmalloc_chunk_t *c;

  pm = pool_elt_at_index (clib_pmalloc_mains, handle);

  /* initial allocation */
  if (pm->n_blocks == 0)
    {
      if (mmap (pm->start, pm->pagesize, PROT_READ | PROT_WRITE,
		MAP_FIXED | MAP_SHARED | MAP_HUGETLB, pm->fd, 0) ==
	  MAP_FAILED)
	return 0;

      pm->n_blocks = pm->pagesize / PMALLOC_BLOCK_SZ;
      pm->n_free_blocks = pm->n_blocks;

      pool_get (pm->chunks, c);
      pm->n_free_chunks = 1;
      pm->first_chunk_index = c - pm->chunks;
      c->prev = c->next = ~0;
      c->size = pm->n_blocks;
    }

  u32 n_blocks = ((size - 1) >> PMALLOC_LOG2_BLOCK_SZ) + 1;
  u32 block_align = align >> PMALLOC_LOG2_BLOCK_SZ;
  c = pool_elt_at_index (pm->chunks, pm->first_chunk_index);

  while (1)
    {
      void *rv = alloc_chunk (pm, c, n_blocks, block_align);

      if (rv)
	return rv;

      if (c->next == ~0)
	return 0;

      c = pool_elt_at_index (pm->chunks, c->next);
    }
  return 0;
}

void
clib_pmalloc_free (int handle, void *va)
{
  clib_pmalloc_main_t *pm;
  clib_pmalloc_chunk_t *c;
  uword *p;
  u32 chunk_index;

  pm = pool_elt_at_index (clib_pmalloc_mains, handle);
  p = hash_get (pm->chunk_index_by_va, pointer_to_uword (va));

  if (p == 0)
    os_panic ();

  chunk_index = p[0];
  hash_unset (pm->chunk_index_by_va, pointer_to_uword (va));

  c = pool_elt_at_index (pm->chunks, chunk_index);
  c->flags &= ~CLIB_PMALLOC_F_USED;
  pm->n_free_blocks += c->size;
  pm->n_free_chunks++;

  /* merge with next if free */
  if (c->next != ~0 &&
      (get_chunk (pm, c->next)->flags & CLIB_PMALLOC_F_USED) == 0 &&
      c->numa == get_chunk (pm, c->next)->numa)
    {
      clib_pmalloc_chunk_t *next = get_chunk (pm, c->next);
      c->size += next->size;
      c->next = next->next;
      if (next->next != ~0)
	get_chunk (pm, next->next)->prev = chunk_index;
      memset (next, 0, sizeof (*next));
      pool_put (pm->chunks, next);
      pm->n_free_chunks--;
    }

  /* merge with prev if free */
  if (c->prev != ~0 &&
      (get_chunk (pm, c->prev)->flags & CLIB_PMALLOC_F_USED) == 0 &&
      c->numa == get_chunk (pm, c->prev)->numa)
    {
      clib_pmalloc_chunk_t *prev = get_chunk (pm, c->prev);
      prev->size += c->size;
      prev->next = c->next;
      if (c->next != ~0)
	get_chunk (pm, c->next)->prev = c->prev;
      memset (c, 0, sizeof (*c));
      pool_put (pm->chunks, c);
      pm->n_free_chunks--;
    }

  ASSERT (hash_elts (pm->chunk_index_by_va) ==
	  pool_elts (pm->chunks) - pm->n_free_chunks);
}

u8 *
format_pmalloc (u8 * s, va_list * va)
{
  int handle = va_arg (*va, int);
  int verbose = va_arg (*va, int);

  clib_pmalloc_main_t *pm;

  pm = pool_elt_at_index (clib_pmalloc_mains, handle);

  s = format (s, "name '%s' total %u used %u chunks %u free-chunks %d",
	      pm->name, pm->n_blocks * PMALLOC_BLOCK_SZ,
	      (pm->n_blocks - pm->n_free_blocks) * PMALLOC_BLOCK_SZ,
	      pool_elts (pm->chunks), pm->n_free_chunks);

  if (pm->n_blocks == 0)
    return s;

  if (verbose)
    {
      clib_pmalloc_chunk_t *c;
      c = pool_elt_at_index (pm->chunks, pm->first_chunk_index);
      while (1)
	{
	  s = format (s, "\n  start %5u blocks %5u%s [%4d,%4d,%4d]",
		      c->start, c->size,
		      c->flags & CLIB_PMALLOC_F_USED ? " used" : "",
		      c->prev, c - pm->chunks, c->next);
	  if (c->next == ~0)
	    break;
	  c = pool_elt_at_index (pm->chunks, c->next);
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
