/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "TAP/TUN device (virtio backend)",
};
