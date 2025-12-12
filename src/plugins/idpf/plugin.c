/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Intel and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description =
    "Intel Infrastructure Data Path Function (IDPF) Device Driver",
  .default_disabled = 1,
};
