/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/vector_funcs.h>
#include <vppinfra/test_vector_funcs.h>

__clib_test_fn void
clib_mask_compare_u16_wrapper (u16 v, u16 *a, u64 *mask, u32 n_elts)
{
  clib_mask_compare_u16 (v, a, mask, n_elts);
}

__clib_test_fn void
clib_mask_compare_u32_wrapper (u32 v, u32 *a, u64 *mask, u32 n_elts)
{
  clib_mask_compare_u32 (v, a, mask, n_elts);
}

static clib_error_t *
test_clib_mask_compare_u16 (clib_error_t *err)
{
  u16 array[513];
  u64 mask[10];
  u32 i, j;

  for (i = 0; i < ARRAY_LEN (array); i++)
    array[i] = i;

  for (i = 0; i < ARRAY_LEN (array); i++)
    {
      for (j = 0; j < ARRAY_LEN (mask); j++)
	mask[j] = 0xa5a5a5a5a5a5a5a5;

      clib_mask_compare_u16_wrapper (i, array, mask, i + 1);

      for (j = 0; j < (i >> 6); j++)
	{
	  if (mask[j])
	    return clib_error_return (err, "mask at position %u not zero", j);
	}
      if (mask[j] != 1ULL << (i & 0x3f))
	return clib_error_return (err,
				  "mask at position %u is %lx, expected %lx",
				  j, mask[j], 1ULL << (i % 64));

      if (mask[j + 1] != 0xa5a5a5a5a5a5a5a5)
	return clib_error_return (err, "mask overrun at position %u", j + 1);
    }
  return err;
}

REGISTER_TEST (clib_mask_compare_u16) = {
  .name = "clib_mask_compare_u16",
  .fn = test_clib_mask_compare_u16,
};

static clib_error_t *
test_clib_mask_compare_u32 (clib_error_t *err)
{
  u32 array[513];
  u64 mask[10];
  u32 i, j;

  for (i = 0; i < ARRAY_LEN (array); i++)
    array[i] = i;

  for (i = 0; i < ARRAY_LEN (array); i++)
    {
      for (j = 0; j < ARRAY_LEN (mask); j++)
	mask[j] = 0xa5a5a5a5a5a5a5a5;

      clib_mask_compare_u32_wrapper (i, array, mask, i + 1);

      for (j = 0; j < (i >> 6); j++)
	{
	  if (mask[j])
	    return clib_error_return (err, "mask at position %u not zero", j);
	}
      if (mask[j] != 1ULL << (i & 0x3f))
	return clib_error_return (err,
				  "mask at position %u is %lx, expected %lx",
				  j, mask[j], 1ULL << (i % 64));

      if (mask[j + 1] != 0xa5a5a5a5a5a5a5a5)
	return clib_error_return (err, "mask overrun at position %u", j + 1);
    }
  return err;
}

REGISTER_TEST (clib_mask_compare_u32) = {
  .name = "clib_mask_compare_u32",
  .fn = test_clib_mask_compare_u32,
};
