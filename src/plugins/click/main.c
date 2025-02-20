/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 * Copyright(c) 2024 Arm Limited
 */

#include <vlib/vlib.h>
#include <vlib/file.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <click/click.h>

#include <click/vppclick.h>
#include <click/click.h>

click_main_t click_main = {};
vlib_node_registration_t click_sched_node;

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

static void
click_wake_thread (vppclick_thread_index_t thread_index)
{
  vlib_thread_wakeup (thread_index);
}

static u32
if_name_to_hw_if_index (const char *if_name)
{
  unformat_input_t in;
  u32 hw_if_index;

  unformat_init_string (&in, if_name, (int) strlen (if_name));

  if (!unformat_user (&in, unformat_vnet_hw_interface, vnet_get_main (),
		      &hw_if_index))
    hw_if_index = CLIB_U32_MAX;

  unformat_free (&in);

  return hw_if_index;
}

static vppclick_pkt_queue_t *
click_from_q_alloc (const char *if_name, vppclick_thread_index_t ti,
		    vppclick_elt_t elt)
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

  if (cif->from_vpp == 0)
    {
      vnet_main_t *vnm = vnet_get_main ();
      vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
      vnet_feature_enable_disable ("device-input", "click", hi->sw_if_index, 1,
				   0, 0);
      vnet_feature_enable_disable ("port-rx-eth", "click", hi->sw_if_index, 1,
				   0, 0);
      vec_validate (cif->from_vpp, vlib_get_n_threads () - 1);
    }

  if (cif->from_vpp[ti].queue)
    {
      log_err ("interface %s already in use", if_name);
      return 0;
    }

  q = clib_mem_alloc_aligned (sizeof (*q) +
				CLICK_PKT_Q_SZ * sizeof (vppclick_pkt_t),
			      CLIB_CACHE_LINE_BYTES);

  vec_validate (cif->from_vpp, ti);
  cif->from_vpp[ti] = (click_from_vpp_queue_t){
    .queue = q,
    .elt = elt,
  };

  *q = (vppclick_pkt_queue_t){
    .interface_index = hw_if_index,
    .queue_size = CLICK_PKT_Q_SZ,
  };

  return q;
}

static void
click_from_q_free (vppclick_pkt_queue_t *q, vppclick_thread_index_t ti)
{
  click_main_t *cm = &click_main;
  click_interface_t *cif;
  log_debug ("click_from_q_free: %p", q);
  cif = vec_elt_at_index (cm->interfaces, q->interface_index);
  ASSERT (cif->from_vpp[ti].queue == q);
  cif->from_vpp[ti] = (click_from_vpp_queue_t){};
  clib_mem_free (q);
}

static vppclick_pkt_queue_t *
click_to_q_alloc (const char *if_name, vppclick_thread_index_t ti)
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

  vec_validate (cif->to_vpp, ti);

  if (cif->to_vpp[ti])
    {
      log_err ("interface %s already in use", if_name);
      return 0;
    }

  q = clib_mem_alloc_aligned (sizeof (*q) +
				CLICK_PKT_Q_SZ * sizeof (vppclick_pkt_t),
			      CLIB_CACHE_LINE_BYTES);

  cif->to_vpp[ti] = q;

  *q = (vppclick_pkt_queue_t){
    .interface_index = hw_if_index,
    .queue_size = CLICK_PKT_Q_SZ,
  };
  return q;
}

static void
click_to_q_free (vppclick_pkt_queue_t *q, vppclick_thread_index_t ti)
{
  click_main_t *cm = &click_main;
  click_interface_t *cif;
  log_debug ("click_to_q_free: %p", q);
  cif = vec_elt_at_index (cm->interfaces, q->interface_index);
  ASSERT (cif->to_vpp[ti] == q);
  cif->to_vpp = 0;
  clib_mem_free (q);
}

clib_error_t *
click_instance_create (vlib_main_t *vm, click_instance_create_args_t *a)
{
  click_main_t *cm = &click_main;
  click_instance_t *inst;
  clib_thread_index_t n_threads = vlib_get_n_threads ();

  if (cm->instances == 0)
    {
      vppclick_init (&(vppclick_init_args_t){
        .n_threads = n_threads,
        .global_cb = {
          .log = click_log_fn,
          .wake_thread = click_wake_thread,
          .pkt_alloc = click_pkt_alloc,
          .pkt_free = click_pkt_free,
          .add_select = click_add_select,
          .remove_select = click_remove_select,
          .get_pending_selects = click_get_pending_selects,
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

  inst->sched_node_index = vlib_register_node (
    vm,
    &(vlib_node_registration_t){
      .type = VLIB_NODE_TYPE_SCHED,
      .flags = VLIB_NODE_FLAG_TRACE_SUPPORTED,
      .node_fn_registrations = click_sched_node.node_fn_registrations,
    },
    "click-sched-%s", inst->name);

  *click_get_node_rt_from_index (vm, inst->sched_node_index) =
    (click_node_runtime_t){
      .ctx = inst->ctx,
      .instance_index = inst - cm->instances,
    };

  vec_validate (inst->next_run_time, 0);

  vlib_node_add_named_next_with_slot (vm, inst->sched_node_index, "error-drop",
				      0);

  vlib_worker_thread_node_runtime_update ();
  vlib_worker_thread_barrier_release (vm);

  vlib_worker_thread_barrier_sync (vm);
  foreach_vlib_main ()
    vlib_node_set_interrupt_pending (this_vlib_main, inst->sched_node_index);
  vlib_worker_thread_barrier_release (vm);

  return 0;
}

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "click",
};

static clib_error_t *
click_worker_thread_init (vlib_main_t *vm)
{
  vppclick_register_thread (vm->thread_index);
  return 0;
}

VLIB_WORKER_INIT_FUNCTION (click_worker_thread_init);

VNET_FEATURE_INIT (click_input, static) = {
  .arc_name = "port-rx-eth",
  .node_name = "click",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};

VNET_FEATURE_INIT (click_input2, static) = {
  .arc_name = "device-input",
  .node_name = "click",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};
