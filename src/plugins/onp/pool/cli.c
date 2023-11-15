/*
 * Copyright (c) 2021 Marvell.
 * SPDX-License-Identifier: Apache-2.0
 * https://spdx.org/licenses/Apache-2.0.html
 */

/**
 * @file
 * @brief ONP buffer pool CLI implementation.
 */

#include <onp/onp.h>

static clib_error_t *
onp_pool_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  cnxk_pool_info_t pool_info = { 0 };
  u32 pool_index = 0;

  vlib_cli_output (vm, "%=32s%=8s%=8s%=15s%=15s%=15s", "Name", "Index",
		   "BufSz", "Total", "Used", "Available");
  for (pool_index = 0; pool_index < CNXK_POOL_MAX_NUM; pool_index++)
    {
      if (cnxk_drv_pool_info_get (pool_index, &pool_info) < 0)
	continue;

      vlib_cli_output (vm, "%=32s%=8u%=8u%=15u%=15u%=15u\n", pool_info.name,
		       pool_index, pool_info.elem_size, pool_info.elem_limit,
		       pool_info.elem_count, pool_info.elem_available);
    }
  return NULL;
}

/*?
 * This command displays statistics of each OCTEON buffer pool
 *
 * @cliexpar
 * Example of how to display OCTEON buffer pools:
 * @cliexstart{show onp buffers}
 *          Name             Index  BufSz    Total         Used      Available
 *       buffer-pool           0    2432     16384         261           16123
 *
 * @cliexend
?*/

VLIB_CLI_COMMAND (onp_pool_show_command, static) = {
  .path = "show onp buffers",
  .short_help = "show onp buffers",
  .function = onp_pool_show_command_fn,
};

static clib_error_t *
onp_pool_show_info_command_fn (vlib_main_t *vm, unformat_input_t *input,
			       vlib_cli_command_t *cmd)
{
  cnxk_drv_pool_info_dump ();

  return 0;
}

/*?
 * This command displays hardware level pool info
 *
 * @cliexpar
 * Example of how to display hardware level pool info
 * @cliexstart{show onp pool info}
 *
 * @cliexend
?*/
VLIB_CLI_COMMAND (onp_pool_show_info_command, static) = {
  .path = "show onp pool info",
  .short_help = "show onp pool info",
  .function = onp_pool_show_info_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
