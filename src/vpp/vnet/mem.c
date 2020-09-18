#include <vppinfra/mem.h>

void * clib_mem_libc_mheap;

void *
malloc(size_t size)
{
  return clib_mem_alloc_aligned_at_offset_ex (clib_mem_libc_heap_get(), size, 0, 0, 1);
}

void
free(void *p)
{
  if (p)
    clib_mem_free_ex (clib_mem_libc_heap_get(), p);
}

void *
calloc(size_t nmemb, size_t size)
{
  size *= nmemb;
  void *p = clib_mem_alloc_aligned_at_offset_ex (clib_mem_libc_heap_get(), size, 0, 0, 1);
  clib_memset (p, 0, size);
  return p;
}

void *
realloc(void *p, size_t size)
{
  void *heap = clib_mem_libc_heap_get();
  return clib_mem_realloc_ex (heap, p, size, clib_mem_size_ex (heap, p));
}

int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
  *memptr = clib_mem_alloc_aligned_at_offset_ex (clib_mem_libc_heap_get(), size, alignment, 0, 1);
  return 0;
}

void *
aligned_alloc(size_t alignment, size_t size)
{
  return clib_mem_alloc_aligned_at_offset_ex (clib_mem_libc_heap_get(), size, alignment, 0, 1);
}

void *
valloc(size_t size)
{
  return clib_mem_alloc_aligned_at_offset_ex (clib_mem_libc_heap_get(), size, clib_mem_get_page_size(), 0, 1);
}

void *memalign(size_t alignment, size_t size)
{
  return clib_mem_alloc_aligned_at_offset_ex (clib_mem_libc_heap_get(), size, alignment, 0, 1);
}

void *
pvalloc(size_t size)
{
  uword pagesz = clib_mem_get_page_size();
  size = round_pow2(size, pagesz);
  return clib_mem_alloc_aligned_at_offset_ex (clib_mem_libc_heap_get(), size, pagesz, 0, 1);
}
