/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>

static clib_error_t *
vlua_init (vlib_main_t *vm)
{

  return 0;
}

VLIB_INIT_FUNCTION (vlua_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Lua Integration Plugin",
};
