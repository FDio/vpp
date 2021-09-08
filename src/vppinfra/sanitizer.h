#ifndef _included_clib_sanitizer_h
#define _included_clib_sanitizer_h

#ifdef CLIB_SANITIZE_ADDR

#include <sanitizer/asan_interface.h>
#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

typedef struct
{
  size_t shadow_scale;
  size_t shadow_offset;
} clib_sanitizer_main_t;

extern clib_sanitizer_main_t sanitizer_main;

#define CLIB_NOSANITIZE_ADDR    __attribute__((no_sanitize_address))
#define CLIB_MEM_POISON(a, s)   ASAN_POISON_MEMORY_REGION((a), (s))
#define CLIB_MEM_UNPOISON(a, s) ASAN_UNPOISON_MEMORY_REGION((a), (s))

#define CLIB_MEM_OVERFLOW_MAX 64

static_always_inline void
sanitizer_unpoison__ (u64 *restrict *shadow_ptr, size_t *shadow_len,
		      const void *ptr, size_t len)
{
  size_t scale, off;

  if (PREDICT_FALSE (~0 == sanitizer_main.shadow_scale))
    __asan_get_shadow_mapping (&sanitizer_main.shadow_scale,
			       &sanitizer_main.shadow_offset);

  scale = sanitizer_main.shadow_scale;
  off = sanitizer_main.shadow_offset;

  /* compute the shadow address and length */
  *shadow_len = len >> scale;
  ASSERT (*shadow_len <= CLIB_MEM_OVERFLOW_MAX);
  *shadow_ptr = (void *) (((clib_address_t) ptr >> scale) + off);
}

static_always_inline CLIB_NOSANITIZE_ADDR void
sanitizer_unpoison_push__ (u64 *restrict shadow, const void *ptr, size_t len)
{
  u64 *restrict shadow_ptr;
  size_t shadow_len;
  int i;

  sanitizer_unpoison__ (&shadow_ptr, &shadow_len, ptr, len);

  /* save the shadow area */
  for (i = 0; i < shadow_len; i++)
    shadow[i] = shadow_ptr[i];

  /* unpoison */
  for (i = 0; i < shadow_len; i++)
    shadow_ptr[i] = 0;
}

static_always_inline CLIB_NOSANITIZE_ADDR void
sanitizer_unpoison_pop__ (const u64 *restrict shadow, const void *ptr,
			  size_t len)
{
  u64 *restrict shadow_ptr;
  size_t shadow_len;
  int i;

  sanitizer_unpoison__ (&shadow_ptr, &shadow_len, ptr, len);

  /* restore the shadow area */
  for (i = 0; i < shadow_len; i++)
    {
      ASSERT (0 == shadow_ptr[i]);
      shadow_ptr[i] = shadow[i];
    }
}

#define CLIB_MEM_OVERFLOW_PUSH(src, n)                                        \
  do                                                                          \
    {                                                                         \
      const void *clib_mem_overflow_src__ = (src);                            \
      size_t clib_mem_overflow_n__ = (n);                                     \
      u64 clib_mem_overflow_shadow__;                                         \
      sanitizer_unpoison_push__ (&clib_mem_overflow_shadow__,                 \
				 clib_mem_overflow_src__,                     \
				 clib_mem_overflow_n__)

#define CLIB_MEM_OVERFLOW_POP()                                               \
  sanitizer_unpoison_pop__ (&clib_mem_overflow_shadow__,                      \
			    clib_mem_overflow_src__, clib_mem_overflow_n__);  \
  }                                                                           \
  while (0)

#define CLIB_MEM_OVERFLOW_LOAD(src)                                           \
  ({                                                                          \
    typeof (*(src)) *clib_mem_overflow_load_src__ = (src),                    \
		    clib_mem_overflow_load_ret__;                             \
    CLIB_MEM_OVERFLOW_PUSH (clib_mem_overflow_load_src__,                     \
			    sizeof (*clib_mem_overflow_load_src__));          \
    clib_mem_overflow_load_ret__ = *clib_mem_overflow_load_src__;             \
    CLIB_MEM_OVERFLOW_POP ();                                                 \
    clib_mem_overflow_load_ret__;                                             \
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
#define CLIB_MEM_OVERFLOW_PUSH(a, b)		(void) (a)
#define CLIB_MEM_OVERFLOW_POP()
#define CLIB_MEM_OVERFLOW_LOAD(src) (*(src))
#define CLIB_MEM_POISON_LEN(a, b, c)

#endif /* CLIB_SANITIZE_ADDR */

/*
 * clang tends to force alignment of all sections when compiling for address
 * sanitizer. This confuse VPP plugin infra, prevent clang to do that
 * On the contrary, GCC does not support this kind of attribute on sections
 * sigh.
 */
#ifdef __clang__
#define CLIB_NOSANITIZE_PLUGIN_REG_SECTION      CLIB_NOSANITIZE_ADDR
#else
#define CLIB_NOSANITIZE_PLUGIN_REG_SECTION
#endif

#endif /* _included_clib_sanitizer_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
