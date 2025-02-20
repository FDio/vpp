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

#define CLICK_PKT_Q_SZ		 64
#define CLICK_PKT_ALLOC_BATCH_SZ 64

click_main_t click_main = {};
vlib_node_registration_t click_node;
vlib_node_registration_t click_input_node;

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

  *q = (vppclick_pkt_queue_t) {
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

  *q = (vppclick_pkt_queue_t) {
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

static void
click_pkt_free (u32 buffer_indices[], uint32_t n)
{
  vlib_main_t *vm = vlib_get_main ();

  log_debug ("click_pkt_free: %u", n);

  vlib_buffer_free (vm, buffer_indices, n);
}

vppclick_pkt_t
vlib_buffer_to_vppclick_pkt (vlib_main_t *vm, u32 bi, u32 buffer_size)
{
  vlib_buffer_t *b = vlib_get_buffer (vm, bi);
  u8 *current = vlib_buffer_get_current (b);
  u16 size = b->current_length;
  u16 headroom = current - b->pre_data;

  return (vppclick_pkt_t) {
    .buffer_index = bi,
    .data = current,
    .size = size,
    .headroom = headroom,
    .tailroom = buffer_size + VLIB_BUFFER_PRE_DATA_SIZE - size - headroom,
  };
}

static_always_inline u32
click_pkt_alloc_one (vlib_main_t *vm, vppclick_pkt_t pkts[], u32 data_size,
		     u32 n)
{
  const u32 batch_size = CLICK_PKT_ALLOC_BATCH_SZ;
  u32 buffer_indices[batch_size], rv;

  rv = vlib_buffer_alloc (vm, buffer_indices, batch_size);
  if (rv != batch_size)
    {
      if (rv)
	vlib_buffer_free (vm, buffer_indices, rv);
      return 0;
    }

  for (u32 i = 0; i < n; i++)
    pkts[i] = (vppclick_pkt_t) {
      .buffer_index = buffer_indices[i],
      .data = vlib_get_buffer (vm, buffer_indices[i])->data,
      .headroom = VLIB_BUFFER_PRE_DATA_SIZE,
      .tailroom = data_size,
    };
  return n;
}

static uint32_t
click_pkt_alloc (vppclick_pkt_t pkts[], uint32_t n)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 data_size = vlib_buffer_get_default_data_size (vm);
  const u32 batch_size = CLICK_PKT_ALLOC_BATCH_SZ;
  u32 buffer_indices[batch_size];
  vppclick_pkt_t *p = pkts;

  log_debug ("click_pkt_alloc: %u", n);

  for (; n >= batch_size; n -= batch_size, p += batch_size)
    if (click_pkt_alloc_one (vm, p, data_size, batch_size) == 0)
      goto fail;

  if (click_pkt_alloc_one (vm, p, data_size, n) == 0)
    goto fail;

  return (p - pkts) + n;

fail:
  for (; pkts < p; pkts += batch_size)
    {
      for (u32 i = 0; i < batch_size; i++)
	buffer_indices[i] = pkts[i].buffer_index;
      vlib_buffer_free (vm, buffer_indices, batch_size);
    }
  return 0;
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

  inst->internal_node_index = vlib_register_node (
    vm,
    &(vlib_node_registration_t) {
      .type = VLIB_NODE_TYPE_INTERNAL,
      .node_fn_registrations = click_node.node_fn_registrations,
      .vector_size = sizeof (u32),
    },
    "click-%s", a->name);

  inst->input_node_index = vlib_register_node (
    vm,
    &(vlib_node_registration_t){
      .type = VLIB_NODE_TYPE_INPUT,
      .state = VLIB_NODE_STATE_INTERRUPT,
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

  if (pool_elts (cm->instances) == 1)
    vlib_process_signal_event (vm, click_process_node.index,
			       CLICK_PROCESS_EVENT_START, 0);

  return 0;
}

static clib_error_t *
click_init (vlib_main_t *vm)
{
  vppclick_init (&(vppclick_init_args_t){
    .n_threads = 1,
    .pkt_alloc_fn = click_pkt_alloc,
    .pkt_free_fn = click_pkt_free,
  });

  return 0;
}

VLIB_INIT_FUNCTION (click_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "click",
};
