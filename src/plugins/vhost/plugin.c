/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 * License: Cisco Proprietary Closed Source License - Cisco Internal.
 * The software, documentation and any fonts accompanying this License whether
 * on disk, in read only memory, on any other media or in any other form (col-
 * lectively the “Software”) are licensed, not sold, to you by Cisco, Inc.
 * (“Cisco”) for use only under the terms of this License, and Cisco reserves
 * all rights not expressly granted to you. The rights granted herein are
 * limited to Cisco’s intel- lectual property rights in the Cisco Software and
 * do not include any other patents or intellectual property rights. You own
 * the media on which the Cisco Software is recorded but Cisco and/or Cisco’s
 * licensor(s) retain ownership of the Software itself.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Vhost-User",
};
