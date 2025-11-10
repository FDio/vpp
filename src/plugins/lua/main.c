/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include "lua.h"

#include <vlib/unix/plugin.h>

static clib_error_t *
vlua_init (vlib_main_t *vm)
{
  log_debug ("lua plugin init");

  plugin_main_t *pm = &vlib_plugin_main;
  plugin_info_t *pi;

  vec_foreach (pi, pm->plugin_info)
    {
      log_debug ("trying: %s", pi->name);
    }

  return 0;
}

VLIB_INIT_FUNCTION (vlua_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Lua Integration Plugin",
};
