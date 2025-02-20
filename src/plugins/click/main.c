/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include "vppinfra/pool.h"
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

  vlib_log (err_level[level], click_log.class, "%.*s", str_len, str);
}


static u32
if_name_to_sw_if_index (const char *if_name)
{
  unformat_input_t in;
  u32 sw_if_index;

  unformat_init_string (&in, if_name, strlen (if_name));

  if (!unformat_user (&in, unformat_vnet_sw_interface, vnet_get_main (),
          &sw_if_index))
      sw_if_index = CLIB_U32_MAX;

  unformat_free (&in);

  return sw_if_index;
}

static vppclick_packet_queue_t *
click_from_q_alloc (const char *if_name)
{
  vppclick_packet_queue_t *q;
  u32 sw_if_index;

  log_debug ("click_from_q_alloc: %s", if_name);

  sw_if_index = if_name_to_sw_if_index (if_name);

  if (sw_if_index == CLIB_U32_MAX)
    {
      log_err ("interface %s not found", if_name);
      return 0;
    }


  q = clib_mem_alloc_aligned (sizeof (*q), CLIB_CACHE_LINE_BYTES);
  return q;
}

static void
click_from_q_free (vppclick_packet_queue_t *q)
{
  log_debug ("click_from_q_free: %p", q);
  clib_mem_free (q);
}

static vppclick_packet_queue_t *
click_to_q_alloc (const char *if_name)
{
  vppclick_packet_queue_t *q;
  u32 sw_if_index;

  log_debug ("click_to_q_alloc: %s", if_name);

  sw_if_index = if_name_to_sw_if_index (if_name);

  if (sw_if_index == CLIB_U32_MAX)
    {
      log_err ("interface %s not found", if_name);
      return 0;
    }

  q = clib_mem_alloc_aligned (sizeof (*q), CLIB_CACHE_LINE_BYTES);
  return q;
}

static void
click_to_q_free (vppclick_packet_queue_t *q)
{
  log_debug ("click_to_q_free: %p", q);
  clib_mem_free (q);
}

clib_error_t *
click_instance_create (vlib_main_t *vm, click_instance_create_args_t *a)
{
  click_main_t *cm = &click_main;
  click_instance_t *inst;

  pool_get_zero (cm->instances, inst);
  inst->ctx = vppclick_ctx_create ( &(vppclick_ctx_create_args_t){
    .router_file = (char *) a->router_file,
    .cb = {
      .log_fn = click_log_fn,
      .from_q_alloc_fn = click_from_q_alloc,
      .from_q_free_fn = click_from_q_free,
      .to_q_alloc_fn = click_to_q_alloc,
      .to_q_free_fn = click_to_q_free,
    },
  });

  if (!inst->ctx)
    {
      pool_put (cm->instances, inst);
      return clib_error_return (0, "failed to create click instance");
    }

  a->index = inst - cm->instances;

  if (pool_elts (cm->instances) == 1)
    vlib_node_set_state (vm, click_input_node.index, VLIB_NODE_STATE_POLLING);

  return 0;
}

static clib_error_t *
click_init (vlib_main_t *vm)
{
  vppclick_init (&(vppclick_init_args_t) { .n_threads = 1 });

  return 0;
}

VLIB_INIT_FUNCTION (click_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Snort",
};

