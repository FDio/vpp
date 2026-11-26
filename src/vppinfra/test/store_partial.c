/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Pavel Lavrukhin
 */

#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/vector.h>

#include <sys/mman.h>

/* called through a pointer so that the length is not a compile-time constant */
__test_funct_fn void
u8x16_store_partial_wrapper (u8x16 r, u8 *data, uword n)
{
  u8x16_store_partial (r, data, n);
}

static void (*wfn_u8x16) (u8x16, u8 *, uword) = &u8x16_store_partial_wrapper;

/* and once per length with the length known to the compiler, which folds the
 * function differently */
#define foreach_store_partial_len                                                                  \
  _ (0)                                                                                            \
  _ (1)                                                                                            \
  _ (2)                                                                                            \
  _ (3)                                                                                            \
  _ (4)                                                                                            \
  _ (5)                                                                                            \
  _ (6)                                                                                            \
  _ (7)                                                                                            \
  _ (8)                                                                                            \
  _ (9)                                                                                            \
  _ (10)                                                                                           \
  _ (11)                                                                                           \
  _ (12)                                                                                           \
  _ (13)                                                                                           \
  _ (14)                                                                                           \
  _ (15)                                                                                           \
  _ (16)

#define _(n)                                                                                       \
  __test_funct_fn void u8x16_store_partial_##n (u8x16 r, u8 *data)                                 \
  {                                                                                                \
    u8x16_store_partial (r, data, n);                                                              \
  }
foreach_store_partial_len
#undef _

  static void (*lfn_u8x16[]) (u8x16, u8 *) = {
#define _(n) &u8x16_store_partial_##n,
    foreach_store_partial_len
#undef _
  };

#ifdef CLIB_HAVE_VEC256
__test_funct_fn void
u8x32_store_partial_wrapper (u8x32 r, u8 *data, uword n)
{
  u8x32_store_partial (r, data, n);
}

static void (*wfn_u8x32) (u8x32, u8 *, uword) = &u8x32_store_partial_wrapper;
#endif

#define canary	 0x55
#define n_canary 32

/* the n bytes at data must be the first n bytes of r, the bytes before them
 * must not change, and the page after them cannot be written, so a store past
 * n faults */
static clib_error_t *
check_store (clib_error_t *err, char *name, u8 *data, u8 *r, uword n)
{
  for (uword i = 0; i < n; i++)
    if (data[i] != r[i])
      return clib_error_return (err, "%s: n %u byte %u is 0x%02x, expected 0x%02x", name, (u32) n,
				(u32) i, data[i], r[i]);
  for (uword i = 1; i <= n_canary; i++)
    if (data[-(word) i] != canary)
      return clib_error_return (err, "%s: n %u wrote %u bytes before the data", name, (u32) n,
				(u32) i);
  return err;
}

static clib_error_t *
test_clib_store_partial (clib_error_t *err)
{
  u32 ps = clib_mem_get_log2_page_size ();
  void *map;
  u8 *end;
  u8x16 r16;
#ifdef CLIB_HAVE_VEC256
  u8x32 r32;
#endif

  map = clib_mem_vm_map (0, 2ULL << ps, ps, "test");
  if (map == CLIB_MEM_VM_MAP_FAILED)
    return clib_error_return (err, "clib_mem_vm_map failed");

  /* the data ends at a page that cannot be written, so a store past n faults */
  end = (u8 *) map + (1ULL << ps);
  if (mprotect (end, 1ULL << ps, PROT_NONE))
    {
      err = clib_error_return_unix (err, "mprotect");
      goto done;
    }

  for (int i = 0; i < 16; i++)
    r16[i] = 0xa0 + i;

  for (uword n = 0; n <= 16; n++)
    {
      u8 *data = end - n;

      memset (end - n - n_canary, canary, n + n_canary);
      wfn_u8x16 (r16, data, n);
      if ((err = check_store (err, "u8x16_store_partial", data, (u8 *) &r16, n)))
	goto done;

      memset (end - n - n_canary, canary, n + n_canary);
      lfn_u8x16[n](r16, data);
      if ((err = check_store (err, "u8x16_store_partial, constant length", data, (u8 *) &r16, n)))
	goto done;
    }

#ifdef CLIB_HAVE_VEC256
  for (int i = 0; i < 32; i++)
    r32[i] = 0xa0 + i;

  for (uword n = 0; n <= 32; n++)
    {
      u8 *data = end - n;

      memset (end - n - n_canary, canary, n + n_canary);
      wfn_u8x32 (r32, data, n);
      if ((err = check_store (err, "u8x32_store_partial", data, (u8 *) &r32, n)))
	goto done;
    }
#endif

done:
  clib_mem_vm_unmap (map);
  return err;
}

REGISTER_TEST (clib_store_partial) = {
  .name = "clib_store_partial",
  .fn = test_clib_store_partial,
};
