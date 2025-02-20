/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <click/click.h>

static clib_error_t *
click_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  clib_error_t *err = 0;
  u8 *name = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &name))
	;
      else
	{
	  err = clib_error_return (0, "unknown input`%U'",
				   format_unformat_error, input);
	  goto done;
	}
    }

done:
  return err;
}

VLIB_CLI_COMMAND (click_create_command, static) = {
  .path = "click create",
  .short_help = "click create",
  .function = click_create_command_fn,
};

