/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlib/vlib.h>
#include <vlua/vlua.h>
#include <vppinfra/os.h>
#include "lua.h"

static clib_error_t *
lua_cli_exec_command_fn (vlib_main_t *vm __clib_unused,
			 unformat_input_t *input,
			 vlib_cli_command_t *cmd __clib_unused)
{
  vlua_handle_t h = vpp_lua_get_main_handle ();
  clib_error_t *err = 0, *rv = 0;
  u8 *code = 0;
  u8 *path = 0;

  if (!h)
    return clib_error_return (0, "lua process is not running");

  if (unformat (input, "%U", unformat_single_quoted_string, &code))
    {
      vec_add1 (code, 0);
      err = vlua_run_string (h, (const char *) code);
      vec_free (code);
      goto done;
    }

  if (unformat (input, "%s", &path))
    {
      vec_add1 (path, 0);
      err = vlua_run_file (h, "%s", path);
      vec_free (path);
      goto done;
    }

  return clib_error_return (0, "lua exec '<code>' | <file.lua>");

done:
  vpp_lua_process_wakeup (vm);
  if (err)
    {
      rv = clib_error_return (0, "%U", format_clib_error, err);
      clib_error_free (err);
    }

  return rv;
}

VLIB_CLI_COMMAND (lua_exec_cli_command, static) = {
  .path = "lua exec",
  .short_help = "lua exec '<lua code>'",
  .function = lua_cli_exec_command_fn,
};

static clib_error_t *
lua_cli_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd __clib_unused)
{
  vlua_handle_t h = vpp_lua_get_main_handle ();
  u8 *stats;

  if (!h)
    return clib_error_return (0, "lua process is not running");

  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "invalid input");

  stats = format (0, "%U", vlua_format_stats, h);
  if (stats)
    {
      vlib_cli_output (vm, "%v", stats);
      vec_free (stats);
    }
  else
    vlib_cli_output (vm, "no lua statistics available");

  return 0;
}

VLIB_CLI_COMMAND (lua_show_cli_command, static) = {
  .path = "show lua",
  .short_help = "show lua",
  .function = lua_cli_show_command_fn,
};

static clib_error_t *
lua_cli_kill_command_fn (vlib_main_t *vm, unformat_input_t *input,
			 vlib_cli_command_t *cmd __clib_unused)
{
  vlua_handle_t h = vpp_lua_get_main_handle ();
  u32 index;
  clib_error_t *err;

  if (!h)
    return clib_error_return (0, "lua process is not running");

  if (!unformat (input, "%u", &index))
    return clib_error_return (0, "lua kill <task index>");

  err = vlua_scheduler_kill_task (h, index);
  if (err)
    return err;

  vlib_cli_output (vm, "killed lua task %u", index);
  return 0;
}

VLIB_CLI_COMMAND (lua_kill_cli_command, static) = {
  .path = "lua kill",
  .short_help = "lua kill <task index>",
  .function = lua_cli_kill_command_fn,
};

static clib_error_t *
lua_cli_stub_command_fn (vlib_main_t *vm __clib_unused,
			 unformat_input_t *input,
			 vlib_cli_command_t *cmd __clib_unused)
{
  vlua_handle_t h = vpp_lua_get_main_handle ();
  u8 *path = 0;

  if (!h)
    return clib_error_return (0, "lua process is not running");

  if (!unformat (input, "%s", &path))
    return clib_error_return (0, "lua create-stub <path>");

  vlua_stub_dump (h, (const char *) path);
  vec_free (path);
  return 0;
}

VLIB_CLI_COMMAND (lua_stub_cli_command, static) = {
  .path = "lua create-stub",
  .short_help = "lua create-stub <path>",
  .function = lua_cli_stub_command_fn,
};
