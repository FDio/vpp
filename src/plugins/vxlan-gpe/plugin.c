/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OpenInfra Foundation Europe.
 */

/* plugin.c: vxlan-gpe */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
// register a plugin

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "VxLan GPE Tunnels",
};
