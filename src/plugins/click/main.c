/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vlib/vlib.h>
#include <vlibapi/api_types.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <click/click.h>

#include <click/vppclick.h>
#include <click/click.h>

click_main_t click_main = {};

VLIB_REGISTER_LOG_CLASS (click_log, static) = {
  .class_name = "click",
};

#define log_debug(fmt, ...) vlib_log_debug (click_log.class, fmt, __VA_ARGS__)
#define log_err(fmt, ...)   vlib_log_err (click_log.class, fmt, __VA_ARGS__)

static void
click_log_fn (int level, const char *str, int str_len)
{
  vlib_log_level_t err_level[] = {
    [0] = VLIB_LOG_LEVEL_EMERG,	  [1] = VLIB_LOG_LEVEL_ALERT,
    [2] = VLIB_LOG_LEVEL_CRIT,	  [3] = VLIB_LOG_LEVEL_ERR,
    [4] = VLIB_LOG_LEVEL_WARNING, [5] = VLIB_LOG_LEVEL_NOTICE,
    [6] = VLIB_LOG_LEVEL_INFO,	  [7] = VLIB_LOG_LEVEL_DEBUG,
  };

  vlib_log(err_level[level], click_log.class, "%.*s", str_len, str);
}

static clib_error_t *
click_init (vlib_main_t *vm)
{
  click_main_t *cm = &click_main;
  click_instance_t *inst;
  vppclick_init (
    &(vppclick_init_args_t) { .n_threads = 1, .log_fn = click_log_fn });

#if 1
  pool_get_zero (cm->instances, inst);
  inst->ctx = vppclick_ctx_create (&(vppclick_ctx_create_args_t) {
    .router_file = "/home/dmarion/src/click/vpp/test1.click",
  });
#endif

#if 1
  pool_get_zero (cm->instances, inst);
  inst->ctx = vppclick_ctx_create (&(vppclick_ctx_create_args_t) {
    .router_file = "/home/dmarion/src/click/vpp/test2.click",
  });
#endif

  vlib_node_set_state (vm, click_input_node.index, VLIB_NODE_STATE_POLLING);

  return 0;
}

VLIB_INIT_FUNCTION (click_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Snort",
};

