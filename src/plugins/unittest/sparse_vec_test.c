/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vppinfra/sparse_vec.h>

static clib_error_t *
test_sparse_vec_lookup (void)
{
  int *spv = 0;
  clib_error_t *error = 0;

  sparse_vec_validate (spv, 42)[0] = 0x4242;

  for (u32 i = 0; i <= 0xffff; i++)
    {
      uword index = sparse_vec_index (spv, i);
      u8 is_member = index != SPARSE_VEC_INVALID_INDEX;

      if (is_member != (i == 42))
	{
	  error = clib_error_return (0, "sparse_vec_index failed for sparse index %u: index %u", i,
				     index);
	  goto done;
	}
    }

  if (vec_elt (spv, sparse_vec_index (spv, 42)) != 0x4242)
    error = clib_error_return (0, "sparse_vec_index failed to preserve value");

done:
  sparse_vec_free (spv);
  return error;
}

static clib_error_t *
test_sparse_vec_insert (void)
{
  const struct
  {
    u16 sparse_index;
    int value;
  } members[] = {
    { 64, 6400 },   { 42, 4200 }, { 0xffff, 0xffff }, { 0, 1000 },
    { 127, 12700 }, { 63, 6300 }, { 128, 12800 },     { 1, 100 },
  };
  int *spv = 0;
  clib_error_t *error = 0;

  for (u32 i = 0; i < ARRAY_LEN (members); i++)
    {
      sparse_vec_validate (spv, members[i].sparse_index)[0] = members[i].value;

      for (u32 j = 0; j <= i; j++)
	{
	  uword index = sparse_vec_index (spv, members[j].sparse_index);

	  if (index == SPARSE_VEC_INVALID_INDEX || vec_elt (spv, index) != members[j].value)
	    {
	      error =
		clib_error_return (0,
				   "sparse_vec_validate failed after inserting %u: key %u has "
				   "index %u and value %d",
				   members[i].sparse_index, members[j].sparse_index, index,
				   index == SPARSE_VEC_INVALID_INDEX ? 0 : vec_elt (spv, index));
	      goto done;
	    }
	}
    }

  {
    uword len = vec_len (spv);
    int *elt = sparse_vec_validate (spv, 64);

    if (vec_len (spv) != len || elt[0] != 6400)
      error = clib_error_return (0, "sparse_vec_validate failed for existing sparse index");
  }

done:
  sparse_vec_free (spv);
  return error;
}

static clib_error_t *
test_sparse_vec_index2_pair (int *spv, u32 si0, u32 si1)
{
  u32 i0, i1;
  uword expected0 = sparse_vec_index (spv, si0);
  uword expected1 = sparse_vec_index (spv, si1);

  sparse_vec_index2 (spv, si0, si1, &i0, &i1);
  if (i0 != expected0 || i1 != expected1)
    return clib_error_return (0,
			      "sparse_vec_index2 failed for sparse indices %u and %u: got %u and "
			      "%u, expected %u and %u",
			      si0, si1, i0, i1, expected0, expected1);

  return 0;
}

static clib_error_t *
test_sparse_vec_index2 (void)
{
  const u16 pairs[][2] = {
    { 63, 127 }, { 63, 128 }, { 128, 127 }, { 128, 192 }, { 63, 63 }, { 127, 127 },
  };
  int *spv = 0;
  clib_error_t *error = 0;

  sparse_vec_validate (spv, 42)[0] = 0x4242;
  for (u32 i = 0; i <= 0xffff; i++)
    {
      error = test_sparse_vec_index2_pair (spv, i, 0xffff ^ i);
      if (error)
	goto done;
    }

  sparse_vec_free (spv);
  sparse_vec_validate (spv, 63)[0] = 6300;
  sparse_vec_validate (spv, 127)[0] = 12700;

  for (u32 i = 0; i < ARRAY_LEN (pairs); i++)
    {
      error = test_sparse_vec_index2_pair (spv, pairs[i][0], pairs[i][1]);
      if (error)
	goto done;
    }

done:
  sparse_vec_free (spv);
  return error;
}

static clib_error_t *
test_sparse_vec_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  clib_error_t *error;

  if ((error = test_sparse_vec_lookup ()))
    return error;
  if ((error = test_sparse_vec_insert ()))
    return error;
  if ((error = test_sparse_vec_index2 ()))
    return error;

  return 0;
}

VLIB_CLI_COMMAND (test_sparse_vec_command, static) = {
  .path = "test sparse_vec",
  .short_help = "test sparse_vec",
  .function = test_sparse_vec_command_fn,
};
