/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include "vppinfra/vec.h"
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <click/click.h>

static clib_error_t *
click_create_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd)
{
  clib_error_t *err = 0;
  click_instance_create_args_t args = {};

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "name %s", &args.name))
	;
      else if (unformat (input, "conf %s", &args.router_file))
	;
      else
	{
	  err = clib_error_return (0, "unknown input`%U'",
				   format_unformat_error, input);
	  goto done;
	}
    }

  if (args.name == 0)
    {
      err = clib_error_return (0, "name required");
      goto done;
    }

  if (args.router_file == 0)
    {
      err = clib_error_return (0, "conf required");
      goto done;
    }

  err = click_instance_create (vm, &args);

done:
  vec_free (args.router_file);
  vec_free (args.name);
  return err;
}

VLIB_CLI_COMMAND (click_create_command, static) = {
  .path = "click create",
  .short_help = "click create name <name> conf <conf>",
  .function = click_create_command_fn,
};
