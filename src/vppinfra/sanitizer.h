#ifndef _included_clib_sanitizer_h
#define _included_clib_sanitizer_h

typedef struct
{
  void *stack;
} clib_sanitizer_stack_context_t;

#ifdef CLIB_SANITIZE_ADDR

#include <sanitizer/asan_interface.h>
#include <vppinfra/clib.h>
#include <vppinfra/error_bootstrap.h>

#define CLIB_NOSANITIZE_ADDR    __attribute__((no_sanitize_address))
#define CLIB_MEM_POISON(a, s)   ASAN_POISON_MEMORY_REGION((a), (s))
#define CLIB_MEM_UNPOISON(a, s) ASAN_UNPOISON_MEMORY_REGION((a), (s))

static_always_inline void
clib_sanitizer_stack_suspend_and_switch (
  clib_sanitizer_stack_context_t *cur_stack, const void *new_stack,
  size_t new_stack_size)
{
  __sanitizer_start_switch_fiber (&cur_stack->stack, new_stack,
				  new_stack_size);
}

static_always_inline void
clib_sanitizer_stack_free_and_switch (const void *new_stack,
				      size_t new_stack_size)
{
  __sanitizer_start_switch_fiber (0, new_stack, new_stack_size);
}

static_always_inline void
clib_sanitizer_stack_restore (clib_sanitizer_stack_context_t stack)
{
  __sanitizer_finish_switch_fiber (stack.stack, 0, 0);
}

static_always_inline void
clib_sanitizer_stack_initialize (const void **prev_stack,
				 size_t *prev_stack_size)
{
  __sanitizer_finish_switch_fiber (0, prev_stack, prev_stack_size);
}

void clib_sanitizer_unpoison_push__ (u64 *shadow, u64 *shadow_mask,
				     u64 **shadow_ptr, const void *ptr,
				     size_t len);
void clib_sanitizer_unpoison_pop__ (u64 shadow, u64 shadow_mask,
				    u64 *shadow_ptr);

#define CLIB_MEM_OVERFLOW_PUSH(src, n)                                        \
  do                                                                          \
    {                                                                         \
      u64 clib_mem_overflow_shadow__;                                         \
      u64 clib_mem_overflow_shadow_mask__;                                    \
      u64 *clib_mem_overflow_shadow_ptr__;                                    \
      clib_sanitizer_unpoison_push__ (                                        \
	&clib_mem_overflow_shadow__, &clib_mem_overflow_shadow_mask__,        \
	&clib_mem_overflow_shadow_ptr__, (src), (n))

#define CLIB_MEM_OVERFLOW_POP()                                               \
  clib_sanitizer_unpoison_pop__ (clib_mem_overflow_shadow__,                  \
				 clib_mem_overflow_shadow_mask__,             \
				 clib_mem_overflow_shadow_ptr__);             \
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
#define clib_sanitizer_stack_suspend_and_switch(a, b, c)                      \
  (void) (a);                                                                 \
  (void) (b);                                                                 \
  (void) (c)
#define clib_sanitizer_stack_free_and_switch(a, b)                            \
  (void) (a);                                                                 \
  (void) (b)
#define clib_sanitizer_stack_restore(a) (void) (a)
#define clib_sanitizer_stack_initialize(a, b)                                 \
  (void) (a);                                                                 \
  (void) (b)
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
