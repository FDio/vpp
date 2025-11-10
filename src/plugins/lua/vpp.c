/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include "lua.h"

static clib_error_t *
vpp_get_version (vlua_method_fn_args_t *a)
{
  vlua_val_vec_add_string (&a->returns, "%s", VPP_BUILD_VER);
  return 0;
}

static void
vpp_lua_vpp_init (vlua_handle_t h, vlua_init_fn_args_t *a)
{
  vlua_table_handle_t root = a->table_handles[0];
  vlua_method_handle_t mh = vlua_method_add (h, root, "get_version");
  vlua_method_add_call_args (mh, vpp_get_version, 0);
}

VLUA_REGISTER_INIT_FN (vpp_core) = {
  .init_fn = vpp_lua_vpp_init,
  .paths = VLUA_PATHS ("vpp"),
};
