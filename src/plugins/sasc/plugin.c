// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2022 Cisco Systems, Inc.

#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

VLIB_PLUGIN_REGISTER() = {
    .version = VPP_BUILD_VER,
    .version_required = VPP_BUILD_VER,
    .description = "Session Aware Service Chaining (sasc)",
};
