/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco and/or its affiliates.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <vppinfra/mem.h>
#include <vppinfra/string.h>

static_always_inline void
clib_mem_intercept_free_inline (void *p)
{
  extern void __libc_free (void *);
  if (!p)
    return;

  if (clib_mem_main.alloc_free_intercept == 1)
    clib_mem_free (p);
  else
    __libc_free (p);
}

static_always_inline void *
clib_mem_intercept_alloc_inline (void *oldp, size_t size, size_t align,
				 int abort_on_fail, int align_check,
				 int size_check, int *err)
{
  extern void *__libc_malloc (size_t);
  extern void *__libc_realloc (void *, size_t);
  extern void *__libc_memalign (size_t, size_t);
  int rv = ENOMEM;
  void *p;

  if (align_check &&
      ((count_set_bits (align) != 1) || (align < CLIB_MEM_MIN_ALIGN)))
    {
      rv = EINVAL;
      goto error;
    }

  align = clib_max (align, CLIB_MEM_MIN_ALIGN);

  if (size_check && (size % align))
    {
      rv = EINVAL;
      goto error;
    }

  size = clib_max (size, 1);

  if (clib_mem_main.alloc_free_intercept == 0)
    {
      if (oldp)
	p = __libc_realloc (oldp, size);
      else if (align_check || align > CLIB_MEM_MIN_ALIGN)
	p = __libc_memalign (align, size);
      else
	p = __libc_malloc (size);

      if (p)
	return p;

      rv = errno ? errno : ENOMEM;
      goto error;
    }

  if (oldp)
    p = clib_mem_realloc_aligned (oldp, size, align);
  else
    p = clib_mem_alloc_aligned_or_null (size, align);

  if (p)
    return p;

error:
  if (err)
    *err = rv;

  if (abort_on_fail)
    abort ();

  return 0;
}

__clib_export void *
malloc (size_t size)
{
  return clib_mem_intercept_alloc_inline (/* oldp */ 0, size,
					  /* align */ 0,
					  /* abort_on_fail */ 0,
					  /* align_check */ 0,
					  /* size_check */ 0,
					  /* err */ &errno);
}

__clib_export void *
calloc (size_t nmemb, size_t size)
{
  if (__builtin_mul_overflow (nmemb, size, &size))
    {
      errno = ENOMEM;
      return 0;
    }
  void *p = clib_mem_intercept_alloc_inline (/* oldp */ 0, size,
					     /* align */ 0,
					     /* abort_on_fail */ 0,
					     /* align_check */ 0,
					     /* size_check */ 0,
					     /* err */ &errno);
  if (!p)
    return 0;
  clib_memset (p, 0, size);
  return p;
}

__clib_export void
free (void *p)
{
  if (p)
    clib_mem_intercept_free_inline (p);
}

__clib_export void *
realloc (void *p, size_t size)
{
  return clib_mem_intercept_alloc_inline (/* oldp */ p, size,
					  /* align */ 0,
					  /* abort_on_fail */ 0,
					  /* align_check */ 0,
					  /* size_check */ 0,
					  /* err */ &errno);
}

__clib_export void *
reallocarray (void *p, size_t nmemb, size_t size)
{
  if (__builtin_mul_overflow (nmemb, size, &size))
    {
      errno = ENOMEM;
      return 0;
    }
  return clib_mem_intercept_alloc_inline (/* oldp */ p, size,
					  /* align */ 0,
					  /* abort_on_fail */ 0,
					  /* align_check */ 0,
					  /* size_check */ 0,
					  /* err */ &errno);
}

__clib_export int
posix_memalign (void **memptr, size_t align, size_t size)
{
  int alloc_err = 0;
  void *p = clib_mem_intercept_alloc_inline (/* oldp */ 0, size, align,
					     /* abort_on_fail */ 0,
					     /* align_check */ 1,
					     /* size_check */ 0,
					     /* err */ &alloc_err);
  if (!p)
    return alloc_err;
  *memptr = p;
  return 0;
}

__clib_export void *
aligned_alloc (size_t align, size_t size)
{
  return clib_mem_intercept_alloc_inline (/* oldp */ 0, size, align,
					  /* abort_on_fail */ 0,
					  /* align_check */ 1,
					  /* size_check */ 1,
					  /* err */ &errno);
}

__clib_export void *
memalign (size_t align, size_t size)
{
  return clib_mem_intercept_alloc_inline (/* oldp */ 0, size, align,
					  /* abort_on_fail */ 0,
					  /* align_check */ 1,
					  /* size_check */ 0,
					  /* err */ &errno);
}

__clib_export void *
valloc (size_t size)
{
  size_t align = clib_mem_get_page_size ();

  return clib_mem_intercept_alloc_inline (/* oldp */ 0, size, align,
					  /* abort_on_fail */ 0,
					  /* align_check */ 0,
					  /* size_check */ 0,
					  /* err */ &errno);
}

__clib_export void *
pvalloc (size_t size)
{
  size_t align = clib_mem_get_page_size ();
  size = size ? round_pow2 (size, align) : align;

  return clib_mem_intercept_alloc_inline (/* oldp */ 0, size,
					  /* align */ align,
					  /* abort_on_fail */ 0,
					  /* align_check */ 0,
					  /* size_check */ 0,
					  /* err */ &errno);
}

__clib_export size_t
malloc_usable_size (void *p)
{
  if (!p)
    return 0;
  return clib_mem_size (p);
}

/* ------------------------------------------------------------------------ */
/* C++ operator new/delete intercepts (mangled symbols).                   */
/* ------------------------------------------------------------------------ */

struct St9nothrow_t;

/* operator new(unsigned long) */
__clib_export void *
_Znwm (size_t size)
{
  return clib_mem_intercept_alloc_inline (0, size, CLIB_MEM_MIN_ALIGN,
					  /* abort_on_fail */ 1,
					  /* align_check */ 0,
					  /* size_check */ 0,
					  /* err */ &errno);
}

/* operator new[](unsigned long) */
__clib_export void *
_Znam (size_t size)
{
  return clib_mem_intercept_alloc_inline (0, size, CLIB_MEM_MIN_ALIGN,
					  /* abort_on_fail */ 1,
					  /* align_check */ 0,
					  /* size_check */ 0,
					  /* err */ &errno);
}

/* operator new(unsigned long, std::nothrow_t const&) */
__clib_export void *
_ZnwmRKSt9nothrow_t (size_t size,
		     const struct St9nothrow_t *__clib_unused nothrow_arg)
{
  return clib_mem_intercept_alloc_inline (0, size, CLIB_MEM_MIN_ALIGN,
					  /* abort_on_fail */ 0,
					  /* align_check */ 0,
					  /* size_check */ 0,
					  /* err */ &errno);
}

/* operator new[](unsigned long, std::nothrow_t const&) */
__clib_export void *
_ZnamRKSt9nothrow_t (size_t size,
		     const struct St9nothrow_t *__clib_unused nothrow_arg)
{
  return clib_mem_intercept_alloc_inline (0, size, CLIB_MEM_MIN_ALIGN,
					  /* abort_on_fail */ 0,
					  /* align_check */ 0,
					  /* size_check */ 0,
					  /* err */ &errno);
}

/* operator delete(void*) */
__clib_export void
_ZdlPv (void *p)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete[](void*) */
__clib_export void
_ZdaPv (void *p)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete(void*, unsigned long) */
__clib_export void
_ZdlPvm (void *p, size_t __clib_unused size)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete[](void*, unsigned long) */
__clib_export void
_ZdaPvm (void *p, size_t __clib_unused size)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete(void*, std::nothrow_t const&) */
__clib_export void
_ZdlPvRKSt9nothrow_t (void *p,
		      const struct St9nothrow_t *__clib_unused nothrow_arg)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete[](void*, std::nothrow_t const&) */
__clib_export void
_ZdaPvRKSt9nothrow_t (void *p,
		      const struct St9nothrow_t *__clib_unused nothrow_arg)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete(void*, unsigned long, std::nothrow_t const&) */
__clib_export void
_ZdlPvmRKSt9nothrow_t (void *p, size_t __clib_unused size,
		       const struct St9nothrow_t *__clib_unused nothrow_arg)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete[](void*, unsigned long, std::nothrow_t const&) */
__clib_export void
_ZdaPvmRKSt9nothrow_t (void *p, size_t __clib_unused size,
		       const struct St9nothrow_t *__clib_unused nothrow_arg)
{
  clib_mem_intercept_free_inline (p);
}

/* Aligned new/delete */

/* operator new(unsigned long, std::align_val_t) */
__clib_export void *
_ZnwmSt11align_val_t (size_t size, size_t align)
{
  return clib_mem_intercept_alloc_inline (0, size, align,
					  /* abort_on_fail */ 1,
					  /* align_check */ 1,
					  /* size_check */ 0,
					  /* err */ &errno);
}

/* operator new[](unsigned long, std::align_val_t) */
__clib_export void *
_ZnamSt11align_val_t (size_t size, size_t align)
{
  return clib_mem_intercept_alloc_inline (0, size, align,
					  /* abort_on_fail */ 1,
					  /* align_check */ 1,
					  /* size_check */ 0,
					  /* err */ &errno);
}

/* operator new(unsigned long, std::align_val_t, std::nothrow_t const&) */
__clib_export void *
_ZnwmSt11align_val_tRKSt9nothrow_t (size_t size, size_t align,
				    const struct St9nothrow_t *__clib_unused
				      nothrow_arg)
{
  return clib_mem_intercept_alloc_inline (0, size, align,
					  /* abort_on_fail */ 0,
					  /* align_check */ 1,
					  /* size_check */ 0,
					  /* err */ &errno);
}

/* operator new[](unsigned long, std::align_val_t, std::nothrow_t const&) */
__clib_export void *
_ZnamSt11align_val_tRKSt9nothrow_t (size_t size, size_t align,
				    const struct St9nothrow_t *__clib_unused
				      nothrow_arg)
{
  return clib_mem_intercept_alloc_inline (0, size, align,
					  /* abort_on_fail */ 0,
					  /* align_check */ 1,
					  /* size_check */ 0,
					  /* err */ &errno);
}

/* operator delete(void*, std::align_val_t) */
__clib_export void
_ZdlPvSt11align_val_t (void *p, size_t __clib_unused align)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete[](void*, std::align_val_t) */
__clib_export void
_ZdaPvSt11align_val_t (void *p, size_t __clib_unused align)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete(void*, std::align_val_t, std::nothrow_t const&) */
__clib_export void
_ZdlPvSt11align_val_tRKSt9nothrow_t (void *p, size_t __clib_unused align,
				     const struct St9nothrow_t *__clib_unused
				       nothrow_arg)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete[](void*, std::align_val_t, std::nothrow_t const&) */
__clib_export void
_ZdaPvSt11align_val_tRKSt9nothrow_t (void *p, size_t __clib_unused align,
				     const struct St9nothrow_t *__clib_unused
				       nothrow_arg)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete(void*, unsigned long, std::align_val_t) */
__clib_export void
_ZdlPvmSt11align_val_t (void *p, size_t __clib_unused size,
			size_t __clib_unused align)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete[](void*, unsigned long, std::align_val_t) */
__clib_export void
_ZdaPvmSt11align_val_t (void *p, size_t __clib_unused size,
			size_t __clib_unused align)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete(void*, unsigned long, std::align_val_t, std::nothrow_t
 * const&) */
__clib_export void
_ZdlPvmSt11align_val_tRKSt9nothrow_t (
  void *p, size_t __clib_unused size, size_t __clib_unused align,
  const struct St9nothrow_t *__clib_unused nothrow_arg)
{
  clib_mem_intercept_free_inline (p);
}

/* operator delete[](void*, unsigned long, std::align_val_t, std::nothrow_t
 * const&) */
__clib_export void
_ZdaPvmSt11align_val_tRKSt9nothrow_t (
  void *p, size_t __clib_unused size, size_t __clib_unused align,
  const struct St9nothrow_t *__clib_unused nothrow_arg)
{
  clib_mem_intercept_free_inline (p);
}

/* ------------------------------------------------------------------------ */
/* Rust global allocator intercepts                                        */
/* ------------------------------------------------------------------------ */

__clib_export void *
__rust_alloc (size_t size, size_t align)
{
  return clib_mem_intercept_alloc_inline (0, size, align,
					  /* abort_on_fail */ 0,
					  /* align_check */ 1,
					  /* size_check */ 0,
					  /* err */ &errno);
}

__clib_export void *
__rust_alloc_zeroed (size_t size, size_t align)
{
  void *p = __rust_alloc (size, align);
  if (p)
    clib_memset (p, 0, clib_max (size, 1));
  return p;
}

__clib_export void *
__rust_realloc (void *ptr, size_t __clib_unused old_size, size_t size,
		size_t align)
{
  return clib_mem_intercept_alloc_inline (ptr, size, align,
					  /* abort_on_fail */ 0,
					  /* align_check */ 1,
					  /* size_check */ 0,
					  /* err */ &errno);
}

__clib_export void
__rust_dealloc (void *p, size_t __clib_unused size, size_t __clib_unused align)
{
  clib_mem_intercept_free_inline (p);
}

__clib_export void
__rust_alloc_error_handler (size_t __clib_unused size,
			    size_t __clib_unused align)
{
  abort ();
}
