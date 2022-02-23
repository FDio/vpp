#ifdef CLIB_SANITIZE_ADDR

#include <vppinfra/error.h>
#include <vppinfra/sanitizer.h>

#define CLIB_MEM_OVERFLOW_MAX	    64
#define CLIB_SANITIZER_SHADOW_SCALE 3
#define CLIB_SANITIZER_SHADOW_BITS                                            \
  (((u64) 1 << CLIB_SANITIZER_SHADOW_SCALE) - 1)

static struct
{
  uword shadow_offset;
} clib_sanitizer_main = { .shadow_offset = ~0 };

__clib_export CLIB_NOSANITIZE_ADDR void
clib_sanitizer_unpoison_push__ (u64 *shadow, u64 *shadow_mask,
				u64 **shadow_ptr, const void *ptr, size_t len)
{
  /* check aligned length */
  len += (clib_address_t) ptr & CLIB_SANITIZER_SHADOW_BITS;
  ALWAYS_ASSERT (len <= CLIB_MEM_OVERFLOW_MAX);

  /* get shadow pointer */
  if (PREDICT_FALSE (~0 == clib_sanitizer_main.shadow_offset))
    {
      size_t scale, offset;
      __asan_get_shadow_mapping (&scale, &offset);
      ALWAYS_ASSERT (CLIB_SANITIZER_SHADOW_SCALE == scale);
      clib_sanitizer_main.shadow_offset = offset;
    }
  *shadow_ptr =
    (u64 *) (((clib_address_t) ptr >> CLIB_SANITIZER_SHADOW_SCALE) +
	     clib_sanitizer_main.shadow_offset);

  /* save the shadow area */
  *shadow_mask = ~((~(u64) 0) << ((len + CLIB_SANITIZER_SHADOW_BITS) &
				  ~CLIB_SANITIZER_SHADOW_BITS));
  *shadow = **shadow_ptr & *shadow_mask;
  /* unpoison */
  **shadow_ptr &= ~*shadow_mask;
}

__clib_export CLIB_NOSANITIZE_ADDR void
clib_sanitizer_unpoison_pop__ (u64 shadow, u64 shadow_mask, u64 *shadow_ptr)
{
  /* restore the shadow area */
  if (PREDICT_TRUE (0 == (*shadow_ptr & shadow_mask)))
    {
      /* normal case: everything is accessible */
      *shadow_ptr |= shadow;
    }
  else
    {
      /* someone changed the shadow behind our back... */
      clib_warning (
	"unexpected shadow area value, you may experienced false-positives");
      u8 *d = (void *) shadow_ptr;
      const u8 *s = (void *) &shadow;
      d[0] = clib_max (d[0], s[0]);
      d[1] = clib_max (d[1], s[1]);
      d[2] = clib_max (d[2], s[2]);
      d[3] = clib_max (d[3], s[3]);
      d[4] = clib_max (d[4], s[4]);
      d[5] = clib_max (d[5], s[5]);
      d[6] = clib_max (d[6], s[6]);
      d[7] = clib_max (d[7], s[7]);
    }
}

#endif /* CLIB_SANITIZE_ADDR */
