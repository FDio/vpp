/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/vlua.h>
#include <vnet/vnet.h>
#include <vnet/interface_funcs.h>

typedef struct
{
  u32 sw_if_index;
} vlua_interface_ns_ctx_t;

static clib_error_t *
resolve_if_ctx (vlua_ns_resolver_fn_args_t *args)
{
  vlua_handle_t h = args->handle;
  vnet_main_t *vnm = vnet_get_main ();
  vlua_interface_ns_ctx_t *ctx = args->context;
  bool use_index = vlua_val_vec_type_is_integer (args->args, 0);
  u32 sw_if_index;
  const u8 *name;
  u32 name_len;

  if (use_index)
    {
      sw_if_index = vlua_val_vec_get_integer (args->args, 0);
      if (!vnet_get_sw_interface_or_null (vnm, sw_if_index))
	{
	  vlua_log_warn (h, "interface %u not found", sw_if_index);
	  return clib_error_return (0, "unknown interface");
	}
    }
  else
    {
      name = vlua_val_vec_get_string (args->args, 0, &name_len);
      sw_if_index = vnet_get_sw_if_index_by_name (vnm, "%.*s", name_len, name);
      if (sw_if_index == ~0)
	{
	  vlua_log_warn (h, "interface '%.*s' not found", name_len, name);
	  return clib_error_return (0, "unknown interface");
	}
    }

  *ctx = (vlua_interface_ns_ctx_t){
    .sw_if_index = sw_if_index,
  };

  return 0;
}

static clib_error_t *
set_state (vlua_method_fn_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  const vlua_interface_ns_ctx_t *ctx = args->context;
  vlua_val_t *arg = args->args;

  if (vlua_val_is_string (arg, "up") ||
      (vlua_val_type_is_integer (arg) && vlua_val_get_integer (arg) == 1))
    vnet_sw_interface_admin_up (vnm, ctx->sw_if_index);
  else if (vlua_val_is_string (arg, "down") ||
	   (vlua_val_type_is_integer (arg) && vlua_val_get_integer (arg) == 0))
    vnet_sw_interface_admin_down (vnm, ctx->sw_if_index);
  else
    return clib_error_return (0, "state must be 'up'/'down' or 1/0");

  return 0;
}

static clib_error_t *
get_state (vlua_method_fn_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  const vlua_interface_ns_ctx_t *ctx = args->context;
  vnet_sw_interface_t *sw;

  ASSERT (ctx && args->context_size >= sizeof (*ctx));

  sw = vnet_get_sw_interface_or_null (vnm, ctx->sw_if_index);
  if (!sw)
    return clib_error_return (0, "unknown interface");

  vlua_val_vec_add_string (
    &args->returns, "%s",
    (sw->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) ? "up" : "down");
  return 0;
}

static clib_error_t *
vpp_lua_interface_init (vlua_handle_t h, vlua_init_fn_args_t *a)
{
  vlua_table_handle_t iface = a->table_handles[0];
  vlua_ns_handle_t ns;
  vlua_method_handle_t mh;

  ns = vlua_ns_create (h, iface, sizeof (vlua_interface_ns_ctx_t));
  vlua_ns_add_call_args (ns, resolve_if_ctx, 1, VLUA_T_STRING);
  vlua_ns_add_call_args (ns, resolve_if_ctx, 1, VLUA_T_INTEGER);

  mh = vlua_method_add (h, iface, "set_state");
  vlua_method_add_call_args (mh, set_state, 1, VLUA_T_STRING);
  vlua_method_add_call_args (mh, set_state, 1, VLUA_T_INTEGER);

  mh = vlua_method_add (h, iface, "get_state");
  vlua_method_add_call_args (mh, get_state, 0);
  return 0;
}

VLUA_REGISTER_INIT_FN (interface) = {
  .init_fn = vpp_lua_interface_init,
  .paths = VLUA_PATHS (".interface"),
};
