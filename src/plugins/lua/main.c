#include "external.h"

#include <string.h>
#include <limits.h>

#include <vppinfra/format.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>

#include <vnet/vnet.h>
#include <vnet/interface_funcs.h>

VLIB_REGISTER_LOG_CLASS (lua_main_log, static) = {
  .class_name = "lua",
  .subclass_name = "init",
};

#define log_debug(fmt, ...)                                                   \
  vlib_log_debug (lua_main_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)
#define log_warn(fmt, ...)                                                    \
  vlib_log_warn (lua_main_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)
#define log_err(fmt, ...)                                                     \
  vlib_log_err (lua_main_log.class, "%s: " fmt, __func__, ##__VA_ARGS__)

static const char *test_strings[] = {
  "do\n"
  "  local version = vpp.get_version()\n"
  "  print('VPP version is :', version)\n"
  "end",
  "do\n"
  "  local output, err = vpp.cli.run('show version')\n"
  "  if err then error('vpp.cli.run failed: ' .. err) end\n"
  "  print('Show version via CLI:')\n"
  "  print(output)\n"
  "end",
  "do\n"
  "  local iface = vpp.interface('local0')\n"
  "  local _, set_err = iface.set_state('up')\n"
  "  if set_err then error('vpp.interface.set_state failed: ' .. set_err) "
  "end\n"
  "  local state, get_err = iface.get_state()\n"
  "  if get_err then error('vpp.interface.get_state failed: ' .. get_err) "
  "end\n"
  "  print('interface local0 state:', state)\n"
  "end"
};

typedef struct
{
  u32 sw_if_index;
} vlua_interface_ns_ctx_t;

static clib_error_t *
resolve_if_ctx (vlua_ns_resolver_fn_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  vlua_interface_ns_ctx_t *ctx = args->context;
  const char *name = 0;
  u32 name_len = 0;
  bool use_index = (vlua_val_vec_type_is_integer (args->args, 0));
  u32 sw_if_index;

  if (use_index)
    {
      sw_if_index = vlua_val_vec_get_integer (args->args, 0);
      if (!vnet_get_sw_interface_or_null (vnm, sw_if_index))
	{
	  log_warn ("interface %u not found", sw_if_index);
	  return clib_error_return (0, "unknown interface");
	}
    }
  else
    {
      name = args->name;
      name_len = args->name_len;
      sw_if_index = vnet_get_sw_if_index_by_name (vnm, "%.*s", name_len, name);
      if (sw_if_index == ~0)
	{
	  log_warn ("interface '%.*s' not found", name_len, name);
	  return clib_error_return (0, "unknown interface");
	}
    }

  *ctx = (vlua_interface_ns_ctx_t){
    .sw_if_index = sw_if_index,
  };

  if (use_index)
    log_debug ("resolved interface index %u", sw_if_index);
  else
    log_debug ("resolved interface '%.*s' to sw_if_index %u", name_len, name,
	       sw_if_index);

  return 0;
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

static clib_error_t *
set_state (vlua_method_fn_args_t *ma)
{
  vnet_main_t *vnm = vnet_get_main ();
  const vlua_interface_ns_ctx_t *ctx = 0;
  vlua_val_t *arg = ma->args;
  u32 sw_if_index = ~0;
  u32 flags = 0;
  clib_error_t *err = 0;

  ASSERT (ma->context && ma->context_size == sizeof (vlua_interface_ns_ctx_t));

  ctx = (const vlua_interface_ns_ctx_t *) ma->context;
  sw_if_index = ctx->sw_if_index;

  if (vlua_val_is_string (arg, "up") ||
      (vlua_val_type_is_integer (arg) && vlua_val_get_integer (arg) == 1))
    flags = VNET_SW_INTERFACE_FLAG_ADMIN_UP;
  else if (vlua_val_is_string (arg, "down") ||
	   (vlua_val_type_is_integer (arg) && vlua_val_get_integer (arg) == 0))
    flags = 0;
  else
    {
      log_err ("set_state called with invalid state '%U'", format_vlua_value,
	       arg);
      return clib_error_return (0, "state must be 'up'/'down' or 1/0");
    }

  err = vnet_sw_interface_set_flags (vnm, sw_if_index, flags);

  if (err)
    {
      log_err ("failed to set interface %u state: %U", sw_if_index,
	       format_clib_error, err);
      return err;
    }

  log_debug ("interface %u admin state set to %s", sw_if_index,
	     flags ? "up" : "down");
  return 0;
}

static clib_error_t *
get_state (vlua_method_fn_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  const vlua_interface_ns_ctx_t *ctx = 0;
  u32 sw_if_index = ~0;
  vnet_sw_interface_t *sw = 0;

  if (args->context == 0 ||
      args->context_size < sizeof (vlua_interface_ns_ctx_t))
    {
      log_err ("get_state called without context");
      return clib_error_return (0, "invalid interface context");
    }

  ctx = (const vlua_interface_ns_ctx_t *) args->context;
  sw_if_index = ctx->sw_if_index;
  sw = vnet_get_sw_interface_or_null (vnm, sw_if_index);

  if (sw == 0)
    {
      log_warn ("interface %u disappeared before get_state", sw_if_index);
      return clib_error_return (0, "unknown interface");
    }

  log_debug ("get_state sw_if_index=%u", sw_if_index);

  vlua_val_vec_add_string (
    &args->returns, "%s",
    (sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? "up" : "down");
  return 0;
}

static clib_error_t *
get_version (vlua_method_fn_args_t *args)
{
  vlua_val_vec_add_string (&args->returns, "%s", VPP_BUILD_VER);
  return 0;
}

static clib_error_t *
vlua_init (vlib_main_t *vm)
{
  vlua_handle_t h = 0;
  vlua_table_handle_t root, cli, iface;
  vlua_ns_handle_t ns;
  vlua_method_handle_t mh;
  clib_error_t *err = 0;

  h = vlua_create ();
  root = vlua_table_add (h, "vpp", 0);
  cli = vlua_table_add (h, "cli", root);
  iface = vlua_table_add (h, "interface", root);

  ns = vlua_ns_create (h, iface, sizeof (vlua_interface_ns_ctx_t));
  vlua_ns_add_call_args (ns, resolve_if_ctx, 1, VLUA_T_STRING);

  mh = vlua_method_add (h, root, "get_version");
  vlua_method_add_call_args (mh, get_version, 0);

  mh = vlua_method_add (h, cli, "run");
  vlua_method_add_call_args (mh, vlua_cli_run, 1, VLUA_T_STRING);

  mh = vlua_method_add (h, iface, "set_state");
  vlua_method_add_call_args (mh, set_state, 1, VLUA_T_STRING);
  vlua_method_add_call_args (mh, set_state, 1, VLUA_T_INTEGER);

  mh = vlua_method_add (h, iface, "get_state");
  vlua_method_add_call_args (mh, get_state, 0);

  FOREACH_ARRAY_ELT (script, test_strings)
    {
      err = vlua_run_string (h, *script);
      if (err)
	goto error;
    }

error:
  if (!mh)
    err = clib_error_return (0, "failed to create method");
  if (err)
    vlua_destroy (h);

  return err;
}

VLIB_INIT_FUNCTION (vlua_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Lua Integration Plugin",
};
