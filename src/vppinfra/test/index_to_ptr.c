/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/test/test.h>
#include <vppinfra/vector/index_to_ptr.h>

typedef void (wrapper_fn) (u32 *indices, void *base, u8 shift, void **ptrs,
			   u32 n_elts);

__test_funct_fn void
clib_index_to_ptr_u32_wrapper (u32 *indices, void *base, u8 shift, void **ptrs,
			       u32 n_elts)
{
  clib_index_to_ptr_u32 (indices, base, shift, ptrs, n_elts);
}

static wrapper_fn *wfn = &clib_index_to_ptr_u32_wrapper;

static clib_error_t *
test_clib_index_to_ptr_u32 (clib_error_t *err)
{
  void *_ptrs[512 + 128], **ptrs = _ptrs + 64;
  u32 _indices[512 + 128], *indices = _indices + 64;
  u16 lengths[] = { 1,	3,  5,	7,  9,	15, 16, 17,  31, 32,
		    33, 40, 41, 42, 63, 64, 65, 511, 512 };

  for (int i = 0; i < ARRAY_LEN (_indices); i++)
    _indices[i] = i;

  for (int i = 0; i < ARRAY_LEN (lengths); i++)
    {
      u16 len = lengths[i];
      u8 shift = 6;
      void *base = (void *) 0x100000000 + i;

      for (int j = -64; j < len + 64; j++)
	ptrs[j] = (void *) 0xfefefefefefefefe;

      wfn (indices, base, shift, ptrs, len);
      for (int j = 0; j < len; j++)
	{
	  void *expected = base + ((u64) indices[j] << shift);
	  if (ptrs[j] != expected)
	    return clib_error_return (err,
				      "testcase failed for length %u "
				      "(offset %u, expected %p, found %p)",
				      len, j, expected, ptrs[j]);
	}
    }
  return err;
}

REGISTER_TEST (clib_index_to_ptr_u32) = {
  .name = "clib_index_to_ptr_u32",
  .fn = test_clib_index_to_ptr_u32,
};
