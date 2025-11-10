/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include "lua.h"
#include <vlib/vlib.h>
#include <vnet/vnet.h>

VLIB_REGISTER_LOG_CLASS (lua_main_log) = {
  .class_name = "lua",
};

static void
vlua_log_vlib (vlua_handle_t handle, vlua_log_level_t level, const char *fmt,
	       va_list *va)
{
  vlib_log_class_t class = lua_main_log.class;
  vlib_log_level_t vlevel;

  switch (level)
    {
    case VLUA_LOG_LEVEL_DEBUG:
      vlevel = VLIB_LOG_LEVEL_DEBUG;
      break;
    case VLUA_LOG_LEVEL_INFO:
      vlevel = VLIB_LOG_LEVEL_INFO;
      break;
    case VLUA_LOG_LEVEL_WARN:
      vlevel = VLIB_LOG_LEVEL_WARNING;
      break;
    case VLUA_LOG_LEVEL_ERR:
    default:
      vlevel = VLIB_LOG_LEVEL_ERR;
      break;
    }

  vlib_log_va (vlevel, class, (char *) fmt, va);
}

static void
vlua_cli_collect_output (uword arg, u8 *data, uword data_len)
{
  u8 **bufp = (u8 **) arg;
  u8 *buf = *bufp;
  u32 offset = vec_len (buf);

  if (data_len == 0)
    return;

  vec_validate (buf, offset + data_len - 1);
  clib_memcpy_fast (buf + offset, data, data_len);
  *bufp = buf;
}

static clib_error_t *
vlua_cli_run (vlua_method_fn_args_t *ma)
{
  vlib_main_t *vm = vlib_get_main ();
  const vlua_val_t *arg = ma->args;
  unformat_input_t input;
  int rv = 0;
  u8 *s = 0;

  u32 cmd_len = 0;
  const u8 *cmd = vlua_val_get_string (arg, &cmd_len);
  unformat_init_vector (&input, vec_dup ((u8 *) cmd));
  rv = vlib_cli_input (vm, &input, vlua_cli_collect_output, (uword) &s);
  unformat_free (&input);

  if (rv != 0)
    {
      log_err ("CLI command '%v' failed", cmd);
      vec_free (s);
      return clib_error_return (0, "CLI execution failed");
    }

  log_debug ("CLI command '%v' completed", cmd);
  vlua_val_vec_add_string (&ma->returns, "%v", s);
  vec_free (s);
  return 0;
}

static uword
lua_process (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlua_handle_t h = 0;
  vlua_table_handle_t root, cli;
  vlua_method_handle_t mh;

  vlua_create_args_t create_args = {
    .log_cb = vlua_log_vlib,
  };
  h = vlua_create (&create_args);
  root = vlua_table_add (h, "vpp", 0);
  cli = vlua_table_add (h, "cli", root);
  vlua_run_init_functions (h);

  mh = vlua_method_add (h, cli, "run");
  vlua_method_add_call_args (mh, vlua_cli_run, 1, VLUA_T_STRING);

  if (vlua_config_stub_path)
    {
      vlua_metadata_dump (h, (const char *) vlua_config_stub_path);
      vec_free (vlua_config_stub_path);
    }

  if (vlua_config_scripts)
    {
      clib_error_t *err = 0;
      vec_foreach_pointer (s, vlua_config_scripts)
	{
	  if (err == 0)
	    err = vlua_run_file (h, "%s", s);
	  vec_free (s);
	}
      vec_free (vlua_config_scripts);
      if (err)
	{
	  log_err ("%U", format_clib_error, err);
	  clib_error_free (err);
	}
    }

  while (1)
    {
      vlib_process_wait_for_event (vm);
      vlib_process_get_events (vm, 0);
    }

  vlua_destroy (h);
  return 0;
}

VLIB_REGISTER_NODE (lua_process_node) = {
  .function = lua_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "lua",
};
