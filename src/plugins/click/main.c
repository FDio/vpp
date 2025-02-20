/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <click/click.h>

#include <click/vppclick.h>
#include <click/click.h>

click_main_t click_main = {};
vlib_node_registration_t click_node;
vlib_node_registration_t click_input_node;

VLIB_REGISTER_LOG_CLASS (click_log, static) = {
  .class_name = "click",
};

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
if_name_to_hw_if_index (const char *if_name)
{
  unformat_input_t in;
  u32 hw_if_index;

  unformat_init_string (&in, if_name, strlen (if_name));

  if (!unformat_user (&in, unformat_vnet_hw_interface, vnet_get_main (),
		      &hw_if_index))
    hw_if_index = CLIB_U32_MAX;

  unformat_free (&in);

  return hw_if_index;
}

static vppclick_pkt_queue_t *
click_from_q_alloc (const char *if_name)
{
  click_main_t *cm = &click_main;
  vppclick_pkt_queue_t *q;
  click_interface_t *cif;
  u32 hw_if_index;

  log_debug ("click_from_q_alloc: %s", if_name);

  hw_if_index = if_name_to_hw_if_index (if_name);

  if (hw_if_index == CLIB_U32_MAX)
    {
      log_err ("interface %s not found", if_name);
      return 0;
    }

  vec_validate (cm->interfaces, hw_if_index);
  cif = vec_elt_at_index (cm->interfaces, hw_if_index);

  if (cif->from_vpp)
    {
      log_err ("interface %s already in use", if_name);
      return 0;
    }

  q = clib_mem_alloc_aligned (sizeof (*q) +
				CLICK_PKT_Q_SZ * sizeof (vppclick_pkt_t),
			      CLIB_CACHE_LINE_BYTES);
  cif->from_vpp = q;

  *q = (vppclick_pkt_queue_t){
    .interface_index = hw_if_index,
    .queue_size = CLICK_PKT_Q_SZ,
  };

  return q;
}

static void
click_from_q_free (vppclick_pkt_queue_t *q)
{
  click_main_t *cm = &click_main;
  click_interface_t *cif;
  log_debug ("click_from_q_free: %p", q);
  cif = vec_elt_at_index (cm->interfaces, q->interface_index);
  ASSERT (cif->from_vpp == q);
  cif->from_vpp = 0;
  clib_mem_free (q);
}

static vppclick_pkt_queue_t *
click_to_q_alloc (const char *if_name)
{
  click_main_t *cm = &click_main;
  vppclick_pkt_queue_t *q;
  click_interface_t *cif;
  u32 hw_if_index;

  log_debug ("click_to_q_alloc: %s", if_name);

  hw_if_index = if_name_to_hw_if_index (if_name);

  if (hw_if_index == CLIB_U32_MAX)
    {
      log_err ("interface %s not found", if_name);
      return 0;
    }

  vec_validate (cm->interfaces, hw_if_index);
  cif = vec_elt_at_index (cm->interfaces, hw_if_index);

  if (cif->to_vpp)
    {
      log_err ("interface %s already in use", if_name);
      return 0;
    }

  q = clib_mem_alloc_aligned (sizeof (*q) +
				CLICK_PKT_Q_SZ * sizeof (vppclick_pkt_t),
			      CLIB_CACHE_LINE_BYTES);
  cif->to_vpp = q;

  *q = (vppclick_pkt_queue_t){
    .interface_index = hw_if_index,
    .queue_size = CLICK_PKT_Q_SZ,
  };
  return q;
}

static void
click_to_q_free (vppclick_pkt_queue_t *q)
{
  click_main_t *cm = &click_main;
  click_interface_t *cif;
  log_debug ("click_to_q_free: %p", q);
  cif = vec_elt_at_index (cm->interfaces, q->interface_index);
  ASSERT (cif->to_vpp == q);
  cif->to_vpp = 0;
  clib_mem_free (q);
}

clib_error_t *
click_instance_create (vlib_main_t *vm, click_instance_create_args_t *a)
{
  click_main_t *cm = &click_main;
  click_instance_t *inst;
  u32 n_threads = vlib_get_n_threads ();

  if (cm->instances == 0)
    {
      vppclick_init (&(vppclick_init_args_t){
    .n_threads = n_threads,
    .global_cb = {
      .pkt_alloc = click_pkt_alloc,
      .pkt_free = click_pkt_free,
      .register_fd = click_register_fd,
      .get_fd_events = click_get_fd_events,
    },
  });
    }

  pool_get_zero (cm->instances, inst);
  inst->name = a->name;
  a->name = 0;
  vec_validate (inst->threads, n_threads - 1);

  inst->ctx = vppclick_ctx_create ( &(vppclick_ctx_create_args_t){
    .router_file = (char *) a->router_file,
    .instance_index = inst - cm->instances,
    .inst_cb = {
      .log = click_log_fn,
      .from_q_alloc = click_from_q_alloc,
      .from_q_free = click_from_q_free,
      .to_q_alloc = click_to_q_alloc,
      .to_q_free = click_to_q_free,
    },
  });

  if (!inst->ctx)
    {
      pool_put (cm->instances, inst);
      return clib_error_return (0, "failed to create click instance");
    }

  a->index = inst - cm->instances;

  vlib_worker_thread_barrier_sync (vm);

  inst->internal_node_index = vlib_register_node (
    vm,
    &(vlib_node_registration_t){
      .type = VLIB_NODE_TYPE_INTERNAL,
      .node_fn_registrations = click_node.node_fn_registrations,
      .vector_size = sizeof (u32),
    },
    "click-%s", a->name);

  inst->input_node_index = vlib_register_node (
    vm,
    &(vlib_node_registration_t){
      .type = VLIB_NODE_TYPE_SCHED,
      .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
      .node_fn_registrations = click_input_node.node_fn_registrations,
    },
    "click-input-%s", a->name);

  *click_get_node_rt_from_index (vm, inst->input_node_index) =
    (click_node_runtime_t){
      .ctx = inst->ctx,
      .instance_index = inst - cm->instances,
    };

  vec_validate (inst->next_run_time, 0);

  vlib_node_add_named_next_with_slot (vm, inst->input_node_index, "error-drop",
				      0);

  vlib_worker_thread_node_runtime_update ();
  vlib_worker_thread_barrier_release (vm);

  vlib_worker_thread_barrier_sync (vm);
  foreach_vlib_main ()
    vlib_node_set_interrupt_pending (this_vlib_main, inst->input_node_index);
  vlib_worker_thread_barrier_release (vm);

  return 0;
}

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "click",
};
