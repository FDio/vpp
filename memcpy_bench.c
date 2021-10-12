#include <vppinfra/clib.h>
#include <vppinfra/vector.h>
#include <vppinfra/string.h>
#include <vppinfra/random.h>
#include <iacaMarks.h>
#include </home/damarion/cisco/vpp-sandbox/include/tscmarks.h>

#if __AVX512BITALG__
#include <vppinfra/memcpy_avx512.h>
#define clib_memcpy_fast_arch(a, b, c) clib_memcpy_fast_avx512 (a, b, c)
#elif __AVX2__
#include <vppinfra/memcpy_avx2.h>
#define clib_memcpy_fast_arch(a, b, c) clib_memcpy_fast_avx2 (a, b, c)
#elif __SSSE3__
#include <vppinfra/memcpy_sse3.h>
#define clib_memcpy_fast_arch(a, b, c) clib_memcpy_fast_sse3 (a, b, c)
#endif /* __AVX512BITALG__ */

#ifdef VER
#define __VER_FN(a, b) a##_##b
#define _VER_FN(a, b)  __VER_FN (a, b)
#define VER_FN(fn)     _VER_FN (fn, VER)
#else
#define VER_FN(fn) fn
#endif

void __clib_noinline __clib_section (".ver1")
VER_FN (ver1) (u8 *dst, const u8 *src, size_t n)
{
  clib_memcpy_fast (dst, src, n);
}

void __clib_noinline __clib_section (".ver2")
VER_FN (ver2) (u8 *dst, const u8 *src, size_t n)
{
  clib_memcpy_fast_arch (dst, src, n);
}

static inline void *
__movsb (void *d, const void *s, size_t n)
{
  asm volatile("rep movsb"
	       : "=D"(d), "=S"(s), "=c"(n)
	       : "0"(d), "1"(s), "2"(n)
	       : "memory");
  return d;
}

void __clib_noinline __clib_section (".ver3")
VER_FN (ver3) (u8 *dst, const u8 *src, size_t n) { __movsb (dst, src, n); }

#ifndef VER

typedef void (test_fn_t) (u8 *dst, const u8 *src, size_t n);

u16 table[4096];

void __clib_noinline __clib_section (".test")
test (test_fn_t *fn, u8 *dst, const u8 *src)
{
  for (int i = 0; i < 100000; i++)
    fn (dst, src, table[i & 0x1ff]);
}

extern test_fn_t ver1_trm;
extern test_fn_t ver2_trm;
extern test_fn_t ver1_hsw;
extern test_fn_t ver2_hsw;
extern test_fn_t ver1_skx;
extern test_fn_t ver2_skx;
extern test_fn_t ver1_icx;
extern test_fn_t ver2_icx;
extern test_fn_t ver3_icx;

int
main ()
{
  u8 _a[8192], *a = _a + 13;
  u8 _b[8192], *b = _b + 13;
  int n_rep, size = 8, inc = 8;

  u32 seed = random_default_seed ();

  for (int i = 0; i < 4096; i++)
    a[i] = i;

next:
  if (size > 4096)
    return 0;
  for (int i = 0; i < 4096; i++)
    table[i] = size + (random_u32 (&seed) & 0xf);

  printf ("\nCopy length: %u\n\n", size);
  n_rep = 2;
  if (size > 128)
    inc = 64;
  if (size > 512)
    inc = 256;

  while (1)
    {
      CLIB_MEMORY_BARRIER ();
      tsc_mark ("new trm");
      test (ver1_trm, b, a);
      tsc_mark ("old trm");
      test (ver2_trm, b, a);

      tsc_mark ("new hsw");
      test (ver1_hsw, b, a);
      tsc_mark ("old hsw");
      test (ver2_hsw, b, a);

      tsc_mark ("new skx");
      test (ver1_skx, b, a);
      tsc_mark ("old skx");
      test (ver2_skx, b, a);

      tsc_mark ("new icx");
      test (ver1_icx, b, a);
      tsc_mark ("old icx");
      test (ver2_icx, b, a);
      tsc_mark ("rep movsb icx");
      test (ver3_icx, b, a);

      tsc_mark (0);
      if (tsc_print (1, 100000))
	{
	  if (--n_rep == 0)
	    {
	      size += inc;
	      goto next;
	    }
	}
    }

  return 0;
}

#endif
