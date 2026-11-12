/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Pavel Lavrukhin
 */

#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/vector.h>

#include <sys/mman.h>

/* called through a pointer so that the length is not a compile-time constant */
__test_funct_fn u8x16
u8x16_load_partial_wrapper (u8 *data, uword n)
{
  return u8x16_load_partial (data, n);
}

static u8x16 (*wfn_u8x16) (u8 *, uword) = &u8x16_load_partial_wrapper;

/* and once per length with the length known to the compiler, which folds the
 * function differently */
#define foreach_load_partial_len                                                                   \
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
  __test_funct_fn u8x16 u8x16_load_partial_##n (u8 *data) { return u8x16_load_partial (data, n); }
foreach_load_partial_len
#undef _

  static u8x16 (*lfn_u8x16[]) (u8 *) = {
#define _(n) &u8x16_load_partial_##n,
    foreach_load_partial_len
#undef _
  };

#ifdef CLIB_HAVE_VEC256
__test_funct_fn u8x32
u8x32_load_partial_wrapper (u8 *data, uword n)
{
  return u8x32_load_partial (data, n);
}

static u8x32 (*wfn_u8x32) (u8 *, uword) = &u8x32_load_partial_wrapper;
#endif

/* r must hold the first n bytes of p followed by zeros */
static clib_error_t *
check_partial (clib_error_t *err, char *name, u8 *r, uword size, u8 *p, uword n)
{
  for (uword i = 0; i < size; i++)
    if (r[i] != (i < n ? p[i] : 0))
      return clib_error_return (err, "%s: n %u byte %u is 0x%02x, expected 0x%02x", name, (u32) n,
				(u32) i, r[i], i < n ? p[i] : 0);
  return err;
}

static clib_error_t *
test_clib_load_partial (clib_error_t *err)
{
  u32 ps = clib_mem_get_log2_page_size ();
  void *map;
  u8 *end;

  map = clib_mem_vm_map (0, 2ULL << ps, ps, "test");
  if (map == CLIB_MEM_VM_MAP_FAILED)
    return clib_error_return (err, "clib_mem_vm_map failed");

  /* the data ends at a page that cannot be read, so a load past n faults */
  end = (u8 *) map + (1ULL << ps);
  if (mprotect (end, 1ULL << ps, PROT_NONE))
    {
      err = clib_error_return_unix (err, "mprotect");
      goto done;
    }

  for (int i = 1; i <= 64; i++)
    end[-i] = 0xa0 + i;

  for (uword n = 0; n <= 16; n++)
    {
      u8x16 r = wfn_u8x16 (end - n, n);
      if ((err = check_partial (err, "u8x16_load_partial", (u8 *) &r, sizeof (r), end - n, n)))
	goto done;

      r = lfn_u8x16[n](end - n);
      if ((err = check_partial (err, "u8x16_load_partial, constant length", (u8 *) &r, sizeof (r),
				end - n, n)))
	goto done;
    }

#ifdef CLIB_HAVE_VEC256
  for (uword n = 0; n <= 32; n++)
    {
      u8x32 r = wfn_u8x32 (end - n, n);
      if ((err = check_partial (err, "u8x32_load_partial", (u8 *) &r, sizeof (r), end - n, n)))
	goto done;
    }
#endif

done:
  clib_mem_vm_unmap (map);
  return err;
}

REGISTER_TEST (clib_load_partial) = {
  .name = "clib_load_partial",
  .fn = test_clib_load_partial,
};
