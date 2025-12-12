/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2021 Dave Barach
 */

#include <vlib/vlib.h>

static clib_error_t *
test_pool_command_fn (vlib_main_t *vm, unformat_input_t *input,
		      vlib_cli_command_t *cmd)
{
  static int sizes[] = { 3, 31, 2042, 2048 };

  int i, j;
  u64 *pool;
  uword this_size;

  for (j = 0; j < ARRAY_LEN (sizes); j++)
    {
      this_size = sizes[j];

      pool_init_fixed (pool, this_size);

      i = 0;

      while (pool_free_elts (pool) > 0)
	{
	  u64 *p __attribute__ ((unused));

	  pool_get (pool, p);
	  i++;
	}

      vlib_cli_output (vm, "allocated %d elts\n", i);

      for (--i; i >= 0; i--)
	{
	  pool_put_index (pool, i);
	}

      ALWAYS_ASSERT (pool_free_elts (pool) == this_size);
    }

  vlib_cli_output (vm, "Test succeeded...\n");
  return 0;
}

VLIB_CLI_COMMAND (test_pool_command, static) = {
  .path = "test pool",
  .short_help = "vppinfra pool.h tests",
  .function = test_pool_command_fn,
};
