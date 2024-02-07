/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Tom Jones <thj@freebsd.org>
 *
 * This software was developed by Tom Jones <thj@freebsd.org> under sponsorship
 * from the FreeBSD Foundation.
 *
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "netmap",
};
