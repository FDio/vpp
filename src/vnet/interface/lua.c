/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/vlua.h>
#include <vnet/vnet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/interface/lua.h>

typedef struct
{
  u32 sw_if_index;
} vlua_interface_ns_ctx_t;

static uword *if_config_handlers;

void
vlua_register_interface_config_handler (char *name, vlua_if_config_fn_t fn)
{
  if (!if_config_handlers)
    if_config_handlers = hash_create_string (0, sizeof (uword));
  hash_set_mem (if_config_handlers, name, (uword) fn);
}

static clib_error_t *
set_config (vlua_method_fn_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  const vlua_interface_ns_ctx_t *ctx = args->context;
  vlua_val_t *config = args->args;
  vlua_table_entry_t *e;
  clib_error_t *err = 0;

  ASSERT (ctx && args->context_size >= sizeof (*ctx));

  if (!vlua_val_type_is_table (config))
    return clib_error_return (0, "config must be a table");

  if (!vnet_get_sw_interface_or_null (vnm, ctx->sw_if_index))
    return clib_error_return (0, "unknown interface");

  vec_foreach (e, config->table_entries)
    {
      uword *p;
      vlua_if_config_fn_t fn;

      if (e->key == 0)
	continue;

      p = hash_get_mem (if_config_handlers, e->key);
      if (!p)
	return clib_error_return (0, "unknown config section '%s'", e->key);

      fn = (vlua_if_config_fn_t) p[0];
      err = fn (vnm, ctx->sw_if_index, &e->value);
      if (err)
	return err;
    }

  return 0;
}

static clib_error_t *
state_config_handler (vnet_main_t *vnm, u32 sw_if_index,
		      const vlua_val_t *config)
{
  u8 state = 0;

  if (vlua_val_type_is_string (config))
    {
      if (vlua_val_is_string (config, "up"))
	state = 1;
      else if (vlua_val_is_string (config, "down"))
	state = 0;
      else
	return clib_error_return (0, "state must be 'up' or 'down'");
    }
  else if (vlua_val_type_is_integer (config))
    state = vlua_val_get_integer (config) != 0;
  else if (vlua_val_type_is_bool (config))
    state = vlua_val_get_bool (config);
  else
    return clib_error_return (
      0, "state must be string ('up'/'down'), integer or bool");

  if (state)
    vnet_sw_interface_admin_up (vnm, sw_if_index);
  else
    vnet_sw_interface_admin_down (vnm, sw_if_index);

  return 0;
}

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
get_mac (vlua_method_fn_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  const vlua_interface_ns_ctx_t *ctx = args->context;
  vnet_sw_interface_t *sw;
  vnet_hw_interface_t *hw;

  ASSERT (ctx && args->context_size >= sizeof (*ctx));

  sw = vnet_get_sw_interface_or_null (vnm, ctx->sw_if_index);
  if (!sw)
    return clib_error_return (0, "unknown interface");

  if (sw->type == VNET_SW_INTERFACE_TYPE_SUB ||
      sw->type == VNET_SW_INTERFACE_TYPE_PIPE ||
      sw->type == VNET_SW_INTERFACE_TYPE_P2P)
    hw = vnet_get_sup_hw_interface (vnm, sw->sw_if_index);
  else
    hw = vnet_get_hw_interface (vnm, sw->hw_if_index);

  vlua_val_vec_add_string (&args->returns, "%U", format_ethernet_address,
			   hw->hw_address);
  return 0;
}

static clib_error_t *
set_mac (vlua_method_fn_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  const vlua_interface_ns_ctx_t *ctx = args->context;
  vnet_sw_interface_t *sw;
  vlua_val_t *arg = args->args;
  u8 *mac_str;
  u8 mac[6];
  clib_error_t *error;

  ASSERT (ctx && args->context_size >= sizeof (*ctx));

  sw = vnet_get_sw_interface_or_null (vnm, ctx->sw_if_index);
  if (!sw)
    return clib_error_return (0, "unknown interface");

  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return clib_error_return (0, "not a hardware interface");

  if (!vlua_val_type_is_string (arg))
    return clib_error_return (0, "mac address must be string");

  mac_str = vec_dup (vlua_val_get_string (arg, 0));
  vec_add1 (mac_str, 0);

  if (unformat (0, "%U", unformat_ethernet_address, mac_str, mac))
    {
      error = vnet_hw_interface_change_mac_address (vnm, sw->hw_if_index, mac);
    }
  else
    error = clib_error_return (0, "invalid mac address '%s'", mac_str);

  vec_free (mac_str);
  return error;
}

static clib_error_t *
set_mtu (vlua_method_fn_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  const vlua_interface_ns_ctx_t *ctx = args->context;
  vlua_val_t *arg = args->args;
  u32 mtu;
  vnet_sw_interface_t *sw;

  ASSERT (ctx && args->context_size >= sizeof (*ctx));

  if (!vlua_val_type_is_number (arg) && !vlua_val_type_is_integer (arg))
    return clib_error_return (0, "mtu must be number");

  if (vlua_val_type_is_integer (arg))
    mtu = (u32) vlua_val_get_integer (arg);
  else
    mtu = (u32) vlua_val_get_number (arg);

  sw = vnet_get_sw_interface_or_null (vnm, ctx->sw_if_index);
  if (!sw)
    return clib_error_return (0, "unknown interface");

  if (sw->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
    return vnet_hw_interface_set_mtu (vnm, sw->hw_if_index, mtu);

  vnet_sw_interface_set_mtu (vnm, ctx->sw_if_index, mtu);
  return 0;
}

static clib_error_t *
get_mtu (vlua_method_fn_args_t *args)
{
  vnet_main_t *vnm = vnet_get_main ();
  const vlua_interface_ns_ctx_t *ctx = args->context;
  vnet_sw_interface_t *sw;
  u32 mtu;

  ASSERT (ctx && args->context_size >= sizeof (*ctx));

  sw = vnet_get_sw_interface_or_null (vnm, ctx->sw_if_index);
  if (!sw)
    return clib_error_return (0, "unknown interface");

  if (sw->type == VNET_SW_INTERFACE_TYPE_HARDWARE)
    mtu = vnet_hw_interface_get_mtu (vnm, sw->hw_if_index);
  else
    mtu = sw->mtu[VNET_MTU_L3];

  vlua_val_vec_add_integer (&args->returns, mtu);
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

  mh = vlua_method_add (h, iface, "set_mac");
  vlua_method_add_call_args (mh, set_mac, 1, VLUA_T_STRING);

  mh = vlua_method_add (h, iface, "get_mac");
  vlua_method_add_call_args (mh, get_mac, 0);

  mh = vlua_method_add (h, iface, "set_mtu");
  vlua_method_add_call_args (mh, set_mtu, 1, VLUA_T_INTEGER);
  vlua_method_add_call_args (mh, set_mtu, 1, VLUA_T_NUMBER);

  mh = vlua_method_add (h, iface, "get_mtu");
  vlua_method_add_call_args (mh, get_mtu, 0);

  mh = vlua_method_add (h, iface, "set_config");
  vlua_method_add_call_args (mh, set_config, 1, VLUA_T_TABLE);

  return 0;
}

static clib_error_t *
vpp_lua_interface_init_handlers (vlib_main_t *vm)
{
  vlua_register_interface_config_handler ("state", state_config_handler);
  return 0;
}

VLIB_INIT_FUNCTION (vpp_lua_interface_init_handlers);

VLUA_REGISTER_INIT_FN (interface) = {
  .init_fn = vpp_lua_interface_init,
  .paths = VLUA_PATHS (".interface"),
};
