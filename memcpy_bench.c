#include <vppinfra/clib.h>
#include <vppinfra/vector.h>
#include <vppinfra/string.h>
#include <vppinfra/random.h>
//#include <iacaMarks.h>
#include "tscmarks.h"

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

void __clib_noinline __clib_section (".ver4")
VER_FN (ver4) (u8 *dst, const u8 *src, size_t n)
{
  __builtin_memcpy (dst, src, 35);
}

#ifndef VER

typedef void (test_fn_t) (u8 *dst, const u8 *src, size_t n);
typedef void (test_exec_fn_t) (test_fn_t *fn, u8 *dst, const u8 *src);

u16 table[4096];

void __clib_noinline __clib_section (".test")
test (test_fn_t *fn, u8 *dst, const u8 *src)
{
  for (int i = 0; i < 100000; i++)
    fn (dst, src, table[i & 0x1ff]);
}

test_exec_fn_t *test_exec = &test;

extern test_fn_t ver1_trm_gcc;
extern test_fn_t ver2_trm_gcc;
extern test_fn_t ver1_hsw_gcc;
extern test_fn_t ver2_hsw_gcc;
extern test_fn_t ver1_skx_gcc;
extern test_fn_t ver2_skx_gcc;
extern test_fn_t ver1_icx_gcc;
extern test_fn_t ver2_icx_gcc;
extern test_fn_t ver3_icx_gcc;
extern test_fn_t ver1_trm_clang;
extern test_fn_t ver2_trm_clang;
extern test_fn_t ver1_hsw_clang;
extern test_fn_t ver2_hsw_clang;
extern test_fn_t ver1_skx_clang;
extern test_fn_t ver2_skx_clang;
extern test_fn_t ver1_icx_clang;
extern test_fn_t ver2_icx_clang;
extern test_fn_t ver3_icx_clang;

typedef struct
{
  u16 from, to;
} test_range_t;

test_range_t ranges[] = {
  //  { .from = 1, .to = 16 },
  //  { .from = 17, .to = 32 },
  //   { .from = 33, .to = 64 },
  { .from = 232, .to = 255 },
  { .from = 1420, .to = 1460 },
  { .from = 256 * 16, .to = 256 * 16 + 63 },
  {},
};

int
main (int argc, char *argv[])
{
  u8 _a[8192], *a = _a + 64;
  u8 _b[8192], *b = _b + 64;
  int n_rep;
  test_range_t r0[2] = {}, *r = r0;

  for (int i = 0; i < 4096; i++)
    a[i] = i;

  if (argc == 2)
    {
      r0[0].from = r0[0].to = atoi (argv[1]);
    }
  else if (argc == 3)
    {
      r0[0].from = atoi (argv[1]);
      r0[0].to = atoi (argv[2]);
    }
  else
    r = ranges;

next:
  if (r->from == 0)
    return 0;

  for (int i = 0; i < 4096; i++)
    {
      u16 rnd;
      _rdrand16_step (&rnd);
      table[i] = r->from + ((rnd) % (r->to - r->from + 1));
    }

  printf ("\nCopy length range: %u - %d \n\n", r->from, r->to);

  n_rep = 5;
  r++;

  while (1)
    {
#if 1
      tsc_mark ("new trm gcc");
      test_exec (ver1_trm_gcc, b, a);
      tsc_mark ("old trm gcc");
      test_exec (ver2_trm_gcc, b, a);
      tsc_mark ("new trm clang");
      test_exec (ver1_trm_clang, b, a);
      tsc_mark ("old trm clang");
      test_exec (ver2_trm_clang, b, a);
#endif

#if 1
      tsc_mark ("new hsw gcc");
      test_exec (ver1_hsw_gcc, b, a);
      tsc_mark ("old hsw gcc");
      test_exec (ver2_hsw_gcc, b, a);
      tsc_mark ("new hsw clang");
      test_exec (ver1_hsw_clang, b, a);
      tsc_mark ("old hsw clang");
      test_exec (ver2_hsw_clang, b, a);
      tsc_mark ("new skx gcc");
      test_exec (ver1_skx_gcc, b, a);
      tsc_mark ("old skx gcc");
      test_exec (ver2_skx_gcc, b, a);
      tsc_mark ("new skx clang");
      test_exec (ver1_skx_clang, b, a);
      tsc_mark ("old skx clang");
      test_exec (ver2_skx_clang, b, a);
#else
      tsc_mark ("new icx gcc");
      test_exec (ver1_icx_gcc, b, a);
      tsc_mark ("old icx gcc");
      test_exec (ver2_icx_gcc, b, a);
      tsc_mark ("new icx clang");
      test_exec (ver1_icx_clang, b, a);
      tsc_mark ("old icx clang");
      test_exec (ver2_icx_clang, b, a);
      tsc_mark ("new icx gcc");
      test_exec (ver1_icx_gcc, b, a);
      tsc_mark ("old icx gcc");
      test_exec (ver2_icx_gcc, b, a);
      tsc_mark ("new icx clang");
      test_exec (ver1_icx_clang, b, a);
      tsc_mark ("old icx clang");
      test_exec (ver2_icx_clang, b, a);
      tsc_mark ("rep movsb gcc");
      test_exec (ver3_icx_gcc, b, a);
#endif

      tsc_mark (0);
      if (tsc_print (5, 100000))
	if (--n_rep == 0)
	  goto next;
    }

  return 0;
}

#endif
