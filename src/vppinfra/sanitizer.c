#ifdef CLIB_SANITIZE_ADDR

#include <vppinfra/sanitizer.h>

__clib_export clib_sanitizer_main_t sanitizer_main = { .shadow_scale = ~0 };

#endif /* CLIB_SANITIZE_ADDR */
