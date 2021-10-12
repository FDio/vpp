#include <vppinfra/clib.h>
#include <vppinfra/vector.h>
#include <vppinfra/string.h>
#include <vppinfra/random.h>
#include <iacaMarks.h>
#include </home/damarion/cisco/vpp-sandbox/include/tscmarks.h>

void __clib_noinline __clib_section (".ver1")
ver1 (u8 *dst, const u8 *src, size_t n)
{
  if (n < 16)
    {
      u16 mask = pow2_mask (n);
      u8x16_mask_store (u8x16_mask_load_zero ((void *) src, mask), dst, mask);
    }
}

void __clib_noinline __clib_section (".ver2")
ver2 (u8 *dst, const u8 *src, size_t n)
{
  if (n < 16)
    {
      u64 mask = _bextr_u64 (0xFFFF, 0, n);
      u8x16_mask_store (u8x16_mask_load_zero ((void *) src, mask), dst, mask);
    }
}

void __clib_noinline __clib_section (".ver3")
ver3 (u8 *dst, const u8 *src, size_t n)
{
  if (n < 16)
    {
      if (n >= 8)
	{
	  *(u64u *) (dst) = *(u64u *) (src);
	  *(u64u *) (dst + n - 8) = *(u64u *) (src + n - 8);
	  return;
	}

      if (n >= 4)
	{
	  *(u32u *) (dst) = *(u32u *) (src);
	  *(u32u *) (dst + n - 4) = *(u32u *) (src + n - 4);
	  return;
	}

      if (n >= 2)
	{
	  *(u16u *) (dst) = *(u16u *) (src);
	  *(u16u *) (dst + n - 2) = *(u16u *) (src + n - 2);
	  return;
	}

      *(u8 *) (dst) = *(const u8 *) (src);
    }

  return;
}

void __clib_noinline __clib_section (".ver4")
ver4 (u8 *dst, const u8 *src, size_t n)
{
  uword dstu = (uword) dst;
  uword srcu = (uword) src;

  if (n < 16)
    {
      if (n & 0x01)
	{
	  *(u8 *) dstu = *(const u8 *) srcu;
	  srcu = (uword) ((const u8 *) srcu + 1);
	  dstu = (uword) ((u8 *) dstu + 1);
	}
      if (n & 0x02)
	{
	  *(u16u *) dstu = *(const u16u *) srcu;
	  srcu = (uword) ((const u16u *) srcu + 1);
	  dstu = (uword) ((u16u *) dstu + 1);
	}
      if (n & 0x04)
	{
	  *(u32u *) dstu = *(const u32u *) srcu;
	  srcu = (uword) ((const u32u *) srcu + 1);
	  dstu = (uword) ((u32u *) dstu + 1);
	}
      if (n & 0x08)
	*(u64u *) dstu = *(const u64u *) srcu;
    }
}

void __clib_noinline __clib_section (".ver5")
ver5 (u8 *dst, const u8 *src, size_t n)
{
  uword dstu = (uword) dst;
  uword srcu = (uword) src;

  if (n < 16)
    {
      if (n & 0x08)
	{
	  *(u64u *) dstu = *(const u64u *) srcu;
	  srcu = (uword) ((const u64u *) srcu + 1);
	  dstu = (uword) ((u64u *) dstu + 1);
	}
      if (n & 0x04)
	{
	  *(u32u *) dstu = *(const u32u *) srcu;
	  srcu = (uword) ((const u32u *) srcu + 1);
	  dstu = (uword) ((u32u *) dstu + 1);
	}
      if (n & 0x02)
	{
	  *(u16u *) dstu = *(const u16u *) srcu;
	  srcu = (uword) ((const u16u *) srcu + 1);
	  dstu = (uword) ((u16u *) dstu + 1);
	}
      if (n & 0x08)
	*(u8 *) dstu = *(const u8 *) srcu;
    }
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

void __clib_noinline __clib_section (".ver6")
ver6 (u8 *dst, const u8 *src, size_t n)
{
  if (n < 16)
    {
      __movsb (dst, src, n);
    }
}

typedef void (test_fn_t) (u8 *dst, const u8 *src, size_t n);

u8 table[4096];

void __clib_noinline __clib_section (".test")
test (test_fn_t *fn, u8 *dst, const u8 *src)
{
  for (int i = 0; i < 100000; i++)
    fn (dst, src, table[i & 0x1ff]);
}

test_fn_t *v1 = ver1;
test_fn_t *v2 = ver2;
test_fn_t *v3 = ver3;
test_fn_t *v4 = ver4;
test_fn_t *v5 = ver5;
test_fn_t *v6 = ver6;

int
main ()
{
  u8 _a[4096], *a = _a + 13;
  u8 _b[4096], *b = _b + 13;

  u32 seed = random_default_seed ();

  for (int i = 0; i < 4096; i++)
    a[i] = i;

  for (int i = 0; i < 4096; i++)
    table[i] = random_u32 (&seed) & 0xf;

  while (1)
    {
      CLIB_MEMORY_BARRIER ();
      tsc_mark ("v1 mask load/store");
      test (v1, b, a);
      tsc_mark ("v2 mask load/store with bextr");
      test (v2, b, a);
      tsc_mark ("v3");
      test (v3, b, a);
      tsc_mark ("v4 dpdk");
      test (v4, b, a);
      tsc_mark ("v5 dpdk reverse");
      test (v5, b, a);
      tsc_mark ("v6 rep movsb");
      test (v6, b, a);
      tsc_mark (0);
      tsc_print (1, 100000);
    }

  return 0;
}
