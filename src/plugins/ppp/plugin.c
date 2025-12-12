/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Cisco and/or its affiliates.
 */

/* plugin.c: ppp */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

// register a plugin
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Point-to-Point Protocol (PPP) plugin",
};
