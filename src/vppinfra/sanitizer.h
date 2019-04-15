#ifndef _included_clib_sanitizer_h
#define _included_clib_sanitizer_h

#ifdef CLIB_SANITIZE_ADDR

#include <sanitizer/asan_interface.h>
#include <vppinfra/clib.h>

#define CLIB_NOSANITIZE_ADDR    __attribute__((no_sanitize_address))
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

#else /* CLIB_SANITIZE_ADDR */

#define CLIB_NOSANITIZE_ADDR
#define CLIB_MEM_POISON(a, s)                   (void)(a)
#define CLIB_MEM_UNPOISON(a, s)                 (void)(a)
#define CLIB_MEM_OVERFLOW(a, b, c)              a
#define CLIB_MEM_OVERFLOW_LOAD(f, src)          f(src)
#define CLIB_MEM_POISON_LEN(a, b, c)

#endif /* CLIB_SANITIZE_ADDR */

#endif /* _included_clib_sanitizer_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
