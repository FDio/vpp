/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <process/process.h>
#include <vpp/app/version.h>

process_main_t process_main;

static clib_error_t *
process_init (vlib_main_t *vm)
{

  process_main_t *pm = &process_main;

  pm->log_class = vlib_log_register_class ("process_plugin", 0);
  return 0;
}

VLIB_INIT_FUNCTION (process_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Process (privileges and capabilities)",
};
