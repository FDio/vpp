/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlib/vlib.h>
#include <vlua/vlua.h>

static void
cli_collect_output (uword arg, u8 *data, uword data_len)
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
cli_run (vlua_method_fn_args_t *ma)
{
  vlib_main_t *vm = vlib_get_main ();
  const vlua_val_t *arg = ma->args;
  vlua_handle_t h = ma->handle;
  unformat_input_t input;
  int rv = 0;
  u8 *s = 0;

  u32 cmd_len = 0;
  const u8 *cmd = vlua_val_get_string (arg, &cmd_len);
  unformat_init_vector (&input, vec_dup ((u8 *) cmd));
  rv = vlib_cli_input (vm, &input, cli_collect_output, (uword) &s);
  unformat_free (&input);

  if (rv != 0)
    {
      vlua_log_err (h, "CLI command '%v' failed", cmd);
      vec_free (s);
      return clib_error_return (0, "CLI execution failed");
    }

  vlua_log_debug (h, "CLI command '%v' completed", cmd);
  vlua_val_vec_add_string (&ma->returns, "%v", s);
  vec_free (s);
  return 0;
}

static clib_error_t *
cli_init (vlua_handle_t h, vlua_init_fn_args_t *args)
{
  vlua_table_handle_t cli = 0;
  vlua_table_handle_t root = 0;
  vlua_method_handle_t mh;

  if (args && args->table_handles && vec_len (args->table_handles) > 0)
    cli = args->table_handles[0];

  if (!cli)
    {
      root = vlua_table_add (h, "vpp", 0);
      if (!root)
	return clib_error_return (0, "failed to create 'vpp' table");
      cli = vlua_table_add (h, "cli", root);
      if (!cli)
	return clib_error_return (0, "failed to create 'vpp.cli' table");
    }

  mh = vlua_method_add (h, cli, "run");
  if (!mh)
    return clib_error_return (0, "failed to register vpp.cli.run");
  vlua_method_add_call_args (mh, cli_run, 1, VLUA_T_STRING);
  return 0;
}

VLUA_REGISTER_INIT_FN (cli) = {
  .init_fn = cli_init,
  .paths = VLUA_PATHS (".cli"),
};
