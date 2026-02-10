/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015-2026 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <policer/internal.h>

policer_main_t policer_main;

vlib_combined_counter_main_t policer_counters[] = {
  {
    .name = "Policer-Conform",
    .stat_segment_name = "/net/policer/conform",
  },
  {
    .name = "Policer-Exceed",
    .stat_segment_name = "/net/policer/exceed",
  },
  {
    .name = "Policer-Violate",
    .stat_segment_name = "/net/policer/violate",
  },
};

__clib_export policer_main_t *
policer_get_main (void)
{
  return &policer_main;
}

__clib_export vlib_combined_counter_main_t *
policer_get_counters (void)
{
  return policer_counters;
}

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Policer",
};
