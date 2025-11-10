#include "lua_plugin.h"

#include <string.h>

#include <vppinfra/format.h>
#include <vppinfra/mem.h>
#include <vppinfra/vec.h>

#include <vnet/vnet.h>
#include <vnet/interface_funcs.h>

VLIB_REGISTER_LOG_CLASS (lua_main_log) = {
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
  u8 *buffer;
} vpp_lua_text_buffer_t;

typedef struct
{
  u32 sw_if_index;
} vpp_lua_interface_ns_ctx_t;

static vpp_lua_text_buffer_t vpp_lua_cli_ctx;
static vpp_lua_text_buffer_t vpp_lua_interface_ctx;

static const char *vpp_lua_buffer_literal (vpp_lua_text_buffer_t *ctx,
					   const char *msg);

static bool
vpp_lua_interface_resolve_context (void *ctx, const char *name,
				   size_t name_len, const char **error_message)
{
  vnet_main_t *vnm = vnet_get_main ();
  u32 sw_if_index = vnet_get_sw_if_index_by_name (vnm, "%.*s", name_len, name);

  if (sw_if_index == ~0)
    {
      if (error_message)
	*error_message = "unknown interface";
      log_warn ("interface '%.*s' not found", name_len, name);
      return false;
    }

  ((vpp_lua_interface_ns_ctx_t *) ctx)->sw_if_index = sw_if_index;

  log_debug ("resolved interface '%.*s' to sw_if_index %u", name_len, name,
	     sw_if_index);
  return true;
}

static void
vpp_lua_cli_collect_output (uword arg, u8 *data, uword data_len)
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

static const char *
vpp_lua_cli_run (vpp_lua_string_function_args_t *args)
{
  vpp_lua_text_buffer_t *ctx = args->cookie;
  vlib_main_t *vm = vlib_get_main ();
  const char *command = args->argument;
  size_t command_len = args->argument_length;
  unformat_input_t input;
  int rv = 0;

  if (command == 0 || command_len == 0)
    {
      args->error_message = "empty CLI command";
      log_warn ("CLI run called with empty command");
      return 0;
    }

  vec_reset_length (ctx->buffer);

  unformat_init_string (&input, (char *) command, command_len);
  rv = vlib_cli_input (vm, &input, vpp_lua_cli_collect_output,
		       (uword) &ctx->buffer);
  unformat_free (&input);

  if (rv != 0)
    {
      args->error_message =
	vpp_lua_buffer_literal (ctx, "CLI execution failed");
      log_err ("CLI command \"%.*s\" failed", (int) command_len, command);
      vec_reset_length (ctx->buffer);
      return 0;
    }

  vec_add1 (ctx->buffer, 0);
  log_debug ("CLI command \"%.*s\" completed", (int) command_len, command);
  return (const char *) ctx->buffer;
}

static const char *
vpp_lua_buffer_literal (vpp_lua_text_buffer_t *ctx, const char *msg)
{
  vec_reset_length (ctx->buffer);
  ctx->buffer = format (ctx->buffer, "%s", msg ? msg : "");
  vec_add1 (ctx->buffer, 0);
  return (const char *) ctx->buffer;
}

static const char *
vpp_lua_interface_set_state (vpp_lua_string_function_args_t *args)
{
  vpp_lua_text_buffer_t *ctx_buffer = args->cookie;
  vnet_main_t *vnm = vnet_get_main ();
  const vpp_lua_interface_ns_ctx_t *ctx_mem = 0;
  const char *state = args->argument;
  u32 sw_if_index = ~0;
  u32 flags = 0;
  clib_error_t *err = 0;
  const char *msg = 0;

  if (args->context == 0 ||
      args->context_size < sizeof (vpp_lua_interface_ns_ctx_t))
    {
      args->error_message = "invalid interface context";
      log_err ("set_state called without context");
      return 0;
    }

  if (state == 0 || args->argument_length == 0)
    {
      args->error_message = "state must be 'up' or 'down'";
      log_err ("set_state called without desired state");
      return 0;
    }

  ctx_mem = (const vpp_lua_interface_ns_ctx_t *) args->context;
  log_debug ("set_state ctx=%p ctx_size=%u state='%.*s'", (void *) ctx_mem,
	     (u32) args->context_size, (int) args->argument_length, state);
  sw_if_index = ctx_mem->sw_if_index;

  if (strcmp (state, "up") == 0)
    flags = VNET_SW_INTERFACE_FLAG_ADMIN_UP;
  else if (strcmp (state, "down") == 0)
    flags = 0;
  else
    {
      args->error_message = "state must be 'up' or 'down'";
      log_err ("set_state called with invalid state '%s'", state);
      return 0;
    }

  err = vnet_sw_interface_set_flags (vnm, sw_if_index, flags);

  if (err)
    {
      msg =
	err->what ? (const char *) err->what : "failed to set interface state";
      args->error_message =
	ctx_buffer ? vpp_lua_buffer_literal (ctx_buffer, msg) : msg;
      log_err ("failed to set interface %u state: %s", sw_if_index,
	       args->error_message);
      clib_error_free (err);
      return 0;
    }

  log_debug ("interface %u admin state set to %s", sw_if_index,
	     flags ? "up" : "down");

  return 0;
}

static const char *
vpp_lua_interface_get_state (vpp_lua_string_function_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  const vpp_lua_interface_ns_ctx_t *ctx_mem = 0;
  u32 sw_if_index = ~0;
  vnet_sw_interface_t *sw = 0;

  if (args->context == 0 ||
      args->context_size < sizeof (vpp_lua_interface_ns_ctx_t))
    {
      args->error_message = "invalid interface context";
      log_err ("get_state called without context");
      return 0;
    }

  ctx_mem = (const vpp_lua_interface_ns_ctx_t *) args->context;
  sw_if_index = ctx_mem->sw_if_index;
  sw = vnet_get_sw_interface_or_null (vnm, sw_if_index);

  if (sw == 0)
    {
      args->error_message = "unknown interface";
      log_warn ("interface %u disappeared before get_state", sw_if_index);
      return 0;
    }

  log_debug ("get_state ctx=%p sw_if_index=%u", (void *) ctx_mem, sw_if_index);

  return (sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? "up" : "down";
}

static const char *
get_version (vpp_lua_string_function_args_t *args)
{
  return VPP_BUILD_VER;
}

static clib_error_t *
vpp_lua_init (vlib_main_t *vm)
{
  vpp_lua_handle_t h = 0;
  vpp_lua_table_handle_t root, cli, iface;
  vpp_lua_ns_handle_t iface_ns;
  clib_error_t *err = 0;

  h = vpp_lua_create ();
  root = vpp_lua_table_add (h, "vpp", 0);
  cli = vpp_lua_table_add (h, "cli", root);
  iface = vpp_lua_table_add (h, "interface", root);

  iface_ns = vpp_lua_ns_create (
    h, &(vpp_lua_ns_create_args_t){
	 .table_handle = iface,
	 .context_size = sizeof (vpp_lua_interface_ns_ctx_t),
       });

  vpp_lua_ns_add_call_args (iface_ns, vpp_lua_interface_resolve_context, 1,
			    VPP_LUA_T_STRING);
  vpp_lua_ns_add_call_args (iface_ns, vpp_lua_interface_resolve_context, 2,
			    VPP_LUA_T_STRING, VPP_LUA_T_BOOL);

  err = vpp_lua_register_string_function (h, &(vpp_lua_string_func_desc_t){
					       .table_handle = root,
					       .method = "get_version",
					       .func = get_version,
					     });
  if (err)
    goto error;

  err = vpp_lua_register_string_function (h, &(vpp_lua_string_func_desc_t){
					       .table_handle = cli,
					       .method = "run",
					       .func = vpp_lua_cli_run,
					       .cookie = &vpp_lua_cli_ctx,
					     });
  if (err)
    goto error;

  err =
    vpp_lua_register_string_function (h, &(vpp_lua_string_func_desc_t){
					   .table_handle = iface,
					   .method = "set_state",
					   .func = vpp_lua_interface_set_state,
					   .cookie = &vpp_lua_interface_ctx,
					   .ns_needs_argument = 1,
					 });
  if (err)
    goto error;

  err =
    vpp_lua_register_string_function (h, &(vpp_lua_string_func_desc_t){
					   .table_handle = iface,
					   .method = "get_state",
					   .func = vpp_lua_interface_get_state,
					   .ns_needs_argument = 0,
					 });
  if (err)
    goto error;

  FOREACH_ARRAY_ELT (script, test_strings)
    {
      err = vpp_lua_run_string (h, *script);
      if (err)
	goto error;
    }

error:
  if (err)
    vpp_lua_destroy (h);

  return err;
}

VLIB_INIT_FUNCTION (vpp_lua_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Lua Integration Plugin",
};
