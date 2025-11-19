/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlua/vlua.h>
#include <vlib/vlib.h>
#include <vpp/app/version.h>

static clib_error_t *
vpp_get_version (vlua_method_fn_args_t *a)
{
  vlua_val_vec_add_string (&a->returns, "%s", VPP_BUILD_VER);
  return 0;
}

static clib_error_t *
vpp_sleep (vlua_method_fn_args_t *a)
{
  vlua_val_t *arg0 = a->args;
  f64 seconds = 0;

  if (vlua_val_type_is_number (arg0))
    seconds = vlua_val_get_number (arg0);
  else if (vlua_val_type_is_integer (arg0))
    seconds = (f64) vlua_val_get_integer (arg0);
  else
    return clib_error_return (0, "vpp.sleep expects numeric seconds");

  vlua_sleep (a->handle, seconds);

  return 0;
}

static clib_error_t *
vpp_lua_vpp_init (vlua_handle_t h, vlua_init_fn_args_t *a)
{
  vlua_table_handle_t root = 0;
  vlua_method_handle_t mh;

  ASSERT (a && a->table_handles && vec_len (a->table_handles) > 0);
  root = a->table_handles[0];

  mh = vlua_method_add (h, root, "get_version");
  vlua_method_add_call_args (mh, vpp_get_version, 0);

  mh = vlua_method_add (h, root, "sleep");
  vlua_method_add_call_args (mh, vpp_sleep, 0);
  vlua_method_add_call_args (mh, vpp_sleep, 1, VLUA_T_NUMBER);
  vlua_method_add_call_args (mh, vpp_sleep, 1, VLUA_T_INTEGER);

  return 0;
}

VLUA_REGISTER_INIT_FN (vpp_core) = {
  .init_fn = vpp_lua_vpp_init,
  .paths = VLUA_PATHS ("."),
};
