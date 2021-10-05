/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/format.h>
#include <vlib/process/process.h>

static clib_error_t *
set_process_privilege_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 gid = ~0;
  u32 uid = ~0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "uid %u", &uid))
	;
      else if (unformat (line_input, "gid %u", &gid))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  if (gid == 0)
    {
      error = clib_error_return (0, "Can't set root group id %u", gid);
      goto err;
    }
  else if (uid == 0)
    {
      error = clib_error_return (0, "Can't set root user id %u", uid);
      goto err;
    }

  error = vlib_process_drop_privileges (vm, gid, uid);

err:
  return error;
}

VLIB_CLI_COMMAND (drop_privilege_command, static) = {
  .path = "set process privilege",
  .short_help = "set process privilege gid <n> uid <n>",
  .function = set_process_privilege_fn,
};

static clib_error_t *
show_process_privilege_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  u32 gid, uid;

  vlib_process_get_privileges (vm, &gid, &uid);
  vlib_cli_output (vm, "VPP process group id %u", gid);
  vlib_cli_output (vm, "VPP process user id %u", uid);

  return error;
}

VLIB_CLI_COMMAND (show_privilege_command, static) = {
  .path = "show process privilege",
  .short_help = "show process privilege",
  .function = show_process_privilege_fn,
};

static clib_error_t *
set_process_capabilities_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u64 effective = 0;

  /* Get a line of input. */
  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "caps %U", unformat_vlib_process_capabilities,
		    &effective))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  unformat_free (line_input);

  error = vlib_process_set_capabilities (vm, effective);
  return error;
}

VLIB_CLI_COMMAND (set_capabilities_command, static) = {
  .path = "set process capabilities",
  .short_help = "set process capabilities caps <list>",
  .function = set_process_capabilities_fn,
};

static clib_error_t *
show_process_capabilities_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  cap_user_data_t data;

  error = vlib_process_get_capabilities (vm, &data);
  if (error)
    return error;
  vlib_cli_output (vm, "VPP Process Capabilities");
  vlib_cli_output (vm, "effective:0x%lx \n%U", data.effective,
		   format_vlib_process_effective_capabilities, &data);
  vlib_cli_output (vm, "permitted:0x%lx \n%U", data.permitted,
		   format_vlib_process_permitted_capabilities, &data);
  vlib_cli_output (vm, "inheritable:0x%lx \n%U", data.inheritable,
		   format_vlib_process_inheritable_capabilities, &data);

  return error;
}

VLIB_CLI_COMMAND (show_capabilities_command, static) = {
  .path = "show process capabilities",
  .short_help = "show process capabilities",
  .function = show_process_capabilities_fn,
};

clib_error_t *
vlib_process_cli_init (vlib_main_t *vm)
{
  return 0;
}

VLIB_INIT_FUNCTION (vlib_process_cli_init);
