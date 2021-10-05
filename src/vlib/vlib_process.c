/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vppinfra/format.h>
#include <linux/capability.h>

static clib_error_t *
vlib_drop_process_privilege (vlib_main_t *vm, u32 uid, u32 gid)
{
  clib_error_t *error = 0;

  if (getuid () == 0)
    {
      if (setgid (gid) != 0)
	return clib_error_return_unix (0, "setgid");
      if (setuid (uid) != 0)
	return clib_error_return_unix (0, "setuid");
    }

  if (setuid (0) != -1)
    return clib_error_return (0, "regain root privileges");

  return error;
}

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

  error = vlib_drop_process_privilege (vm, uid, gid);

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

  vlib_cli_output (vm, "VPP process group id %u", getgid ());
  vlib_cli_output (vm, "VPP process user id %u", getuid ());

  return error;
}

VLIB_CLI_COMMAND (show_privilege_command, static) = {
  .path = "show process privilege",
  .short_help = "show process privilege",
  .function = show_process_privilege_fn,
};

static clib_error_t *
show_process_capabilities_fn (vlib_main_t *vm, unformat_input_t *input,
			      vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;
  u64 effective = 0, permitted = 0, inheritable = 0;
  cap_user_header_t hdrp;
  cap_user_data_t datap;
  int ret = -1;

  datap = (cap_user_data_t) clib_mem_alloc (_LINUX_CAPABILITY_U32S_3 *
					    sizeof (cap_user_data_t));
  hdrp = (cap_user_header_t) clib_mem_alloc (sizeof (cap_user_header_t));
  hdrp->version = _LINUX_CAPABILITY_VERSION_3;
  hdrp->pid = getpid ();
  ret = syscall (SYS_capget, hdrp, datap);

  if (ret == -1)
    return clib_error_return_unix (0, "error getting process capabilities");

  effective = (datap[0].effective | (u64) datap[1].effective << 32);
  permitted = (datap[0].permitted | (u64) datap[1].permitted << 32);
  inheritable = (datap[0].inheritable | (u64) datap[1].inheritable << 32);

  vlib_cli_output (vm, "VPP Process Capabilities");
  vlib_cli_output (vm, "effective:0x%lx", effective);
  vlib_cli_output (vm, "permitted:0x%lx", permitted);
  vlib_cli_output (vm, "inheritable:0x%lx", inheritable);

  clib_mem_free (datap);
  clib_mem_free (hdrp);

  return error;
}

VLIB_CLI_COMMAND (show_capabilities_command, static) = {
  .path = "show process capabilities",
  .short_help = "show process capabilities",
  .function = show_process_capabilities_fn,
};
