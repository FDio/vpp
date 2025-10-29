#include <stdio.h>
#include <vppinfra/mem.h>

extern void * __libc_malloc (size_t);
extern void __libc_free (void *);
extern void * __libc_calloc (size_t, size_t);
extern void * __libc_realloc (void *, size_t);
extern void * __libc_valloc (size_t);
extern void * __libc_memalign (size_t, size_t);
extern void * __libc_pvalloc (size_t);

__thread u64 vpp_mem_no_vpp_heap;

static void no_heap (void)
{
  vpp_mem_no_vpp_heap++;

  if (1 == vpp_mem_no_vpp_heap)
    fprintf (stderr, "vpp mem: libc allocation requested but no vpp heap ready, defaulting to libc.\n");
}

static_always_inline int
check_vpp_heap (void)
{
  if (PREDICT_TRUE (clib_mem_get_heap () != 0))
    return 1;

  no_heap ();
  return 0;
}

void *
malloc(size_t size)
{
  if (!check_vpp_heap ())
    return __libc_malloc (size);

  return clib_mem_alloc (size);
}

void
free(void *p)
{
  if (!p)
    return;

  if (!check_vpp_heap ())
    return __libc_free (p);

  clib_mem_free (p);
}

void *
calloc(size_t nmemb, size_t size)
{
  void * p;

  if (!check_vpp_heap ())
    return __libc_calloc (nmemb, size);

  p = clib_mem_alloc (nmemb * size);
  clib_memset (p, 0, nmemb * size);
  return p;
}

void *
realloc(void *p, size_t size)
{
  if (!check_vpp_heap ())
    return __libc_realloc (p, size);

  return clib_mem_realloc (p, size);
}

int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
  if (!check_vpp_heap ())
    *memptr = __libc_memalign (alignment, size);
  else
    *memptr = clib_mem_alloc_aligned (size, alignment);
  return 0;
}

void *
aligned_alloc(size_t alignment, size_t size)
{
  if (!check_vpp_heap ())
    return __libc_memalign (alignment, size);

  return clib_mem_alloc_aligned (size, alignment);
}

void *
valloc(size_t size)
{
  if (!check_vpp_heap ())
    return __libc_valloc (size);

  return clib_mem_alloc_aligned (size, clib_mem_get_page_size ());
}

void *memalign(size_t alignment, size_t size)
{
  if (!check_vpp_heap ())
    return __libc_memalign (alignment, size);

  return clib_mem_alloc_aligned (size, alignment);
}

void *
pvalloc(size_t size)
{
  uword pagesz;

  if (!check_vpp_heap ())
    return __libc_pvalloc (size);

  pagesz = clib_mem_get_page_size ();
  return clib_mem_alloc_aligned (round_pow2 (size, pagesz), pagesz);
}
