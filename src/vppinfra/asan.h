#ifndef _included_clib_asan_h
#define _included_clib_asan_h

#include <vppinfra/error_bootstrap.h>

#ifdef __SANITIZE_ADDRESS__

STATIC_ASSERT(__GNUC__ >= 8, "ASAN supported only with GCC 8 or higher");

#include <sanitizer/asan_interface.h>
#define CLIB_MEM_ATTR_NOASAN    __attribute__((no_sanitize_address))

#define CLIB_MEM_POISON(a, s)   ASAN_POISON_MEMORY_REGION((a), (s))
#define CLIB_MEM_UNPOISON(a, s) ASAN_UNPOISON_MEMORY_REGION((a), (s))

#else   /* __SANITIZE_ADDRESS__ */

#define CLIB_MEM_ATTR_NOASAN
#define CLIB_MEM_POISON(a, s)   do { (void)(a); (void)(s); } while (0)
#define CLIB_MEM_UNPOISON(a, s) do { (void)(a); (void)(s); } while (0)

#endif  /* __SANITIZE_ADDRESS__ */

#endif /* _included_clib_asan_h */
