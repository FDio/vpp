/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) <current-year> <your-organization>
 */

/* handoffdemo.c - skeleton vpp engine plug-in */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <handoffdemo/handoffdemo.h>

handoffdemo_main_t handoffdemo_main;

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "handoff demo plugin",
};
