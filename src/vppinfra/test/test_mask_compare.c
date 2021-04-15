/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/vector_funcs.h>
#include <vppinfra/test/test.h>

__clib_test_fn void
clib_compare_u16_wrapper (u16 v, u16 *a, u64 *bitmap, u32 n_elts)
{
  clib_compare_u16 (v, a, bitmap, n_elts);
}

__clib_test_fn void
clib_compare_u32_wrapper (u32 v, u32 *a, u64 *bitmap, u32 n_elts)
{
  clib_compare_u32 (v, a, bitmap, n_elts);
}

static clib_error_t *
test_clib_compare_u16 (clib_error_t *err)
{
  u16 array[513];
  u64 bitmap[10];
  u32 i, j;

  for (i = 0; i < ARRAY_LEN (array); i++)
    array[i] = i;

  /* test 1 */
  for (i = 0; i < ARRAY_LEN (array); i++)
    {
      for (j = 0; j < ARRAY_LEN (bitmap); j++)
	bitmap[j] = 0xa5a5a5a5a5a5a5a5;
      clib_compare_u16_wrapper (i, array, bitmap, i + 1);
      for (j = 0; j < i / 64; j++)
	{
	  if (bitmap[j])
	    err = clib_error_return (err, "bitmap at position %u not zero", j);
	}
      if (bitmap[j] != 1ULL << (i % 64))
	err =
	  clib_error_return (err, "bitmap at position %u is %lx, expected %lx",
			     j, bitmap[j], 1ULL << (i % 64));
      if (bitmap[j + 1] != 0xa5a5a5a5a5a5a5a5)
	err = clib_error_return (err, "bitmap overrun at position %u", j + 1);
    }
  return err;
}

REGISTER_TEST (clib_compare_u16) = {
  .name = "clib_compare_u16",
  .fn = test_clib_compare_u16,
};

static clib_error_t *
test_clib_compare_u32 (clib_error_t *err)
{
  u32 array[513];
  u64 bitmap[10];
  u32 i, j;

  for (i = 0; i < ARRAY_LEN (array); i++)
    array[i] = i;

  /* test 1 */
  for (i = 0; i < ARRAY_LEN (array); i++)
    {
      for (j = 0; j < ARRAY_LEN (bitmap); j++)
	bitmap[j] = 0xa5a5a5a5a5a5a5a5;
      clib_compare_u32_wrapper (i, array, bitmap, i + 1);
      for (j = 0; j < i / 64; j++)
	{
	  if (bitmap[j])
	    err = clib_error_return (err, "bitmap at position %u not zero", j);
	}
      if (bitmap[j] != 1ULL << (i % 64))
	err =
	  clib_error_return (err, "bitmap at position %u is %lx, expected %lx",
			     j, bitmap[j], 1ULL << (i % 64));
      if (bitmap[j + 1] != 0xa5a5a5a5a5a5a5a5)
	err = clib_error_return (err, "bitmap overrun at position %u", j + 1);
    }
  return err;
}

REGISTER_TEST (clib_compare_u32) = {
  .name = "clib_compare_u32",
  .fn = test_clib_compare_u32,
};
