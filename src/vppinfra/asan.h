#ifndef _included_clib_asan_h
#define _included_clib_asan_h

#ifdef CLIB_DEBUG_ASAN

#include <sanitizer/asan_interface.h>
#include <vppinfra/clib.h>

#define CLIB_MEM_ATTR_NOASAN    __attribute__((no_sanitize_address))
#define CLIB_MEM_POISON(a, s)   ASAN_POISON_MEMORY_REGION((a), (s))
#define CLIB_MEM_UNPOISON(a, s) ASAN_UNPOISON_MEMORY_REGION((a), (s))

#define CLIB_MEM_OVERFLOW(f, src, n) \
  ({ \
   typeof (f) clib_mem_overflow_ret__; \
   const void *clib_mem_overflow_src__ = (src); \
   size_t clib_mem_overflow_n__ = (n); \
   const void *clib_mem_overflow_start__ = __asan_region_is_poisoned((void *)clib_mem_overflow_src__, clib_mem_overflow_n__); \
   clib_mem_overflow_n__ -= (size_t)(clib_mem_overflow_start__ - clib_mem_overflow_src__); \
   if (clib_mem_overflow_start__) \
     CLIB_MEM_UNPOISON(clib_mem_overflow_start__, clib_mem_overflow_n__); \
   clib_mem_overflow_ret__ = f; \
   if (clib_mem_overflow_start__) \
     CLIB_MEM_POISON(clib_mem_overflow_start__, clib_mem_overflow_n__); \
   clib_mem_overflow_ret__; \
   })

#define clib_memcpy_fast_overflow(dst, src, n) \
  ({ \
      const void *clib_memcpy_fast_overflow_src__ = (src); \
      size_t clib_memcpy_fast_overflow_n__ = (n); \
      CLIB_MEM_OVERFLOW(clib_memcpy_fast((dst), clib_memcpy_fast_overflow_src__, clib_memcpy_fast_overflow_n__), clib_memcpy_fast_overflow_src__, clib_memcpy_fast_overflow_n__); \
   })

#define clib_memcpy_le_overflow(dst, src, n, max) \
  do { \
      void *clib_memcpy_le_overflow_dst__ = (dst); \
      void *clib_memcpy_le_overflow_src__ = (src); \
      size_t clib_memcpy_le_overflow_n__ = (n); \
      size_t clib_memcpy_le_overflow_max__ = (max); \
      CLIB_MEM_OVERFLOW((clib_memcpy_le(clib_memcpy_le_overflow_dst__, clib_memcpy_le_overflow_src__, clib_memcpy_le_overflow_n__, clib_memcpy_le_overflow_max__), 0), clib_max(clib_memcpy_le_overflow_dst__, clib_memcpy_le_overflow_src__), clib_memcpy_le_overflow_max__); \
   } while (0)

#define clib_memcpy_le32_overflow(dst, src, n)  clib_memcpy_le_overflow((dst), (src), (n), 64)
#define clib_memcpy_le64_overflow(dst, src, n)  clib_memcpy_le_overflow((dst), (src), (n), 64)

#define CLIB_MEM_OVERFLOW_LOAD(f, src) \
  ({ \
   typeof(src) clib_mem_overflow_load_src__ = (src); \
   CLIB_MEM_OVERFLOW(f(clib_mem_overflow_load_src__), clib_mem_overflow_load_src__, sizeof(typeof(f(clib_mem_overflow_load_src__)))); \
   })

static_always_inline void
CLIB_MEM_POISON_LEN (void *src, size_t oldlen, size_t newlen)
{
  if (oldlen > newlen)
    CLIB_MEM_POISON (src + newlen, oldlen - newlen);
  else if (newlen > oldlen)
    CLIB_MEM_UNPOISON (src + oldlen, newlen - oldlen);
}

#else /* CLIB_DEBUG_ASAN */

#define CLIB_MEM_ATTR_NOASAN
#define CLIB_MEM_POISON(a, s)                   (void)(a)
#define CLIB_MEM_UNPOISON(a, s)                 (void)(a)
#define CLIB_MEM_OVERFLOW(a, b, c)              a
#define clib_memcpy_fast_overflow(a, b, c)      clib_memcpy_fast((a), (b), (c))
#define clib_memcpy_le64_overflow(a, b, c)      clib_memcpy_le64((a), (b), (c))
#define clib_memcpy_le32_overflow(a, b, c)      clib_memcpy_le32((a), (b), (c))
#define CLIB_MEM_OVERFLOW_LOAD(f, src)          f(src)
#define CLIB_MEM_POISON_LEN(a, b, c)

#endif /* CLIB_DEBUG_ASAN */

#endif /* _included_clib_asan_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
