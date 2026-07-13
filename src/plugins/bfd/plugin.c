/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

/* plugin.c: bfd */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

// register a plugin
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Bidirectional Forwarding Detection (BFD) plugin",
};
