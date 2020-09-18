/* replacing libc malloc does not work well with ASAN */
#ifndef CLIB_SANITIZE_ADDR

#include <vppinfra/mem.h>

void *
malloc(size_t size)
{
  return clib_mem_alloc (size);
}

void
free(void *p)
{
  if (p)
    clib_mem_free (p);
}

void *
calloc(size_t nmemb, size_t size)
{
  void * p = clib_mem_alloc (nmemb * size);
  clib_memset (p, 0, nmemb * size);
  return p;
}

void *
realloc(void *p, size_t size)
{
  return clib_mem_realloc (p, size, clib_mem_size (p));
}

int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
  *memptr = clib_mem_alloc_aligned (size, alignment);
  return 0;
}

void *
aligned_alloc(size_t alignment, size_t size)
{
  return clib_mem_alloc_aligned (size, alignment);
}

void *
valloc(size_t size)
{
  return clib_mem_alloc_aligned (size, clib_mem_get_page_size ());
}

void *memalign(size_t alignment, size_t size)
{
  return clib_mem_alloc_aligned (size, alignment);
}

void *
pvalloc(size_t size)
{
  uword pagesz = clib_mem_get_page_size ();
  return clib_mem_alloc_aligned (round_pow2 (size, pagesz), pagesz);
}

#endif  /* CLIB_SANITIZE_ADDR */
