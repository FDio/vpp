/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/error.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "process",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U: " f,                    \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_warn(dev, f, ...)                                                 \
  vlib_log (VLIB_LOG_LEVEL_WARNING, dev_log.class, "%U: " f,                  \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)
#define log_err(dev, f, ...)                                                  \
  vlib_log (VLIB_LOG_LEVEL_ERR, dev_log.class, "%U: " f,                      \
	    format_vnet_dev_addr, dev, ##__VA_ARGS__)

typedef enum
{
  VNET_DEV_EVENT_PERIODIC_STOP,
  VNET_DEV_EVENT_PERIODIC_START,
  VNET_DEV_EVENT_PORT_CONFIG_CHANGE,
  VNET_DEV_EVENT_PROCESS_QUIT,
  VNET_DEV_EVENT_CLOCK = ~0
} vnet_dev_event_t;

typedef struct
{
  vnet_dev_event_t event;
  u32 calling_process_index;
  struct
  {
    vnet_dev_port_t *port;
    vnet_dev_port_config_changes_t changes;
  } port_config_change;
} vnet_dev_event_data_t;

static uword
vnet_dev_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  int periodic = 0, quit = 0;
  vnet_dev_periodic_op_t *pop, *pops = 0;
  f64 next = CLIB_F64_MAX;
  vnet_dev_event_data_t *event_data = 0, *new_event_data, *ed;

  vnet_dev_t *dev =
    *((vnet_dev_t **) vlib_node_get_runtime_data (vm, rt->node_index));

  log_debug (dev, "process '%U' started", format_vlib_node_name, vm,
	     rt->node_index);

  while (quit == 0)
    {
      uword event_type;
      f64 now = vlib_time_now (vm);

      if (periodic)
	vlib_process_wait_for_event_or_clock (vm, next > now ? next - now : 0);
      else
	vlib_process_wait_for_event (vm);

      new_event_data = vlib_process_get_event_data (vm, &event_type);

      if (new_event_data)
	{
	  vec_append (event_data, new_event_data);
	  vlib_process_put_event_data (vm, new_event_data);

	  ASSERT (event_type == 0);

	  vec_foreach (ed, event_data)
	    {
	      vnet_dev_port_t *p;
	      vnet_dev_rv_t rv = VNET_DEV_OK;
	      switch (ed->event)
		{
		case VNET_DEV_EVENT_CLOCK:
		  break;
		case VNET_DEV_EVENT_PROCESS_QUIT:
		  log_debug (dev, "quit requested");
		  quit = 1;
		  vlib_process_signal_event (vm, ed->calling_process_index,
					     VNET_DEV_EVENT_PROCESS_QUIT, rv);
		  break;
		case VNET_DEV_EVENT_PERIODIC_START:
		  log_debug (dev, "periodic start");
		  periodic = 1;
		  break;
		case VNET_DEV_EVENT_PERIODIC_STOP:
		  log_debug (dev, "periodic stop");
		  periodic = 0;
		  break;
		case VNET_DEV_EVENT_PORT_CONFIG_CHANGE:
		  p = ed->port_config_change.port;
		  rv = vnet_dev_port_config_change (
		    vm, p, ed->port_config_change.changes);
		  vlib_process_signal_event (vm, ed->calling_process_index,
					     VNET_DEV_EVENT_PROCESS_QUIT, rv);
		  break;
		default:
		  ASSERT (0);
		};
	    }
	  vec_reset_length (event_data);
	}

      next = CLIB_F64_MAX;
      pool_foreach (pop, dev->periodic_ops)
	{
	  if (pop->last_run + pop->interval < now)
	    {
	      vec_add1 (pops, *pop);
	      pop->last_run = now;
	    }
	  if (pop->last_run + pop->interval < next)
	    next = pop->last_run + pop->interval;
	}

      vec_foreach (pop, pops)
	{
	  switch (pop->type)
	    {
	    case VNET_DEV_PERIODIC_OP_TYPE_DEV:
	      pop->dev_op (vm, pop->dev);
	      break;
	    case VNET_DEV_PERIODIC_OP_TYPE_PORT:
	      pop->port_op (vm, pop->port);
	      break;
	    default:
	      ASSERT (0);
	    }
	}
      vec_reset_length (pops);
    }

  log_debug (dev, "process '%U' quit", format_vlib_node_name, vm,
	     rt->node_index);
  vlib_node_set_state (vm, rt->node_index, VLIB_NODE_STATE_DISABLED);
  vlib_node_rename (vm, rt->node_index, "deleted-%u", rt->node_index);

  /* add node index to the freelist */
  vec_add1 (dm->free_process_node_indices, rt->node_index);
  vec_free (pops);
  vec_free (event_data);
  return 0;
}

vnet_dev_rv_t
vnet_dev_process_create (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vlib_node_t *n;
  uword l;

  l = vec_len (dm->free_process_node_indices);
  if (l > 0)
    {
      n = vlib_get_node (vm, dm->free_process_node_indices[l - 1]);
      vlib_node_rename (vm, n->index, "%s-process", dev->device_id);
      vlib_node_set_state (vm, n->index, VLIB_NODE_STATE_POLLING);
      vec_set_len (dm->free_process_node_indices, l - 1);
    }
  else
    {
      vlib_node_registration_t r = {
	.function = vnet_dev_process,
	.type = VLIB_NODE_TYPE_PROCESS,
	.process_log2_n_stack_bytes = 16,
	.runtime_data_bytes = sizeof (void *),
      };

      vlib_register_node (vm, &r, "%s-process", dev->device_id);

      n = vlib_get_node (vm, r.index);
    }

  dev->process_node_index = n->index;
  *(vnet_dev_t **) vlib_node_get_runtime_data (vm, n->index) = dev;
  vlib_start_process (vm, n->runtime_index);

  return VNET_DEV_OK;
}

static void
vnet_dev_process_event_send (vlib_main_t *vm, vnet_dev_t *dev,
			     vnet_dev_event_data_t ed)
{
  vnet_dev_event_data_t *edp = vlib_process_signal_event_data (
    vm, dev->process_node_index, 0, 1, sizeof (ed));
  *edp = ed;
}

static vnet_dev_rv_t
vnet_dev_process_event_send_and_wait (vlib_main_t *vm, vnet_dev_t *dev,
				      vnet_dev_event_data_t ed)
{
  uword event, *event_data = 0;
  vnet_dev_rv_t rv;

  ed.calling_process_index = vlib_get_current_process_node_index (vm);
  vnet_dev_process_event_send (vm, dev, ed);
  vlib_process_wait_for_event_or_clock (vm, 5.0);
  event = vlib_process_get_events (vm, &event_data);
  if (event != VNET_DEV_EVENT_PROCESS_QUIT)
    {
      log_err (dev, "%s",
	       event == VNET_DEV_EVENT_CLOCK ?
		       "timeout waiting for process node to respond" :
		       "unexpected event received");
      rv = VNET_DEV_ERR_PROCESS_REPLY;
    }
  else
    rv = event_data[0];
  vec_free (event_data);
  return rv;
}

void
vnet_dev_process_quit (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_event_data_t ed = { .event = VNET_DEV_EVENT_PROCESS_QUIT };
  vnet_dev_process_event_send_and_wait (vm, dev, ed);
}

static int
_vnet_dev_poll_add (vlib_main_t *vm, vnet_dev_t *dev,
		    vnet_dev_periodic_op_t pop)
{
  const vnet_dev_event_data_t ed = { .event = VNET_DEV_EVENT_PERIODIC_START };
  vnet_dev_periodic_op_t *p;

  pool_foreach (p, dev->periodic_ops)
    if (p->op == pop.op && p->arg == pop.arg)
      return 0;

  pool_get_zero (dev->periodic_ops, p);
  *p = pop;
  if (pool_elts (dev->periodic_ops) == 1)
    vnet_dev_process_event_send (vm, dev, ed);
  return 1;
}

static int
_vnet_dev_poll_remove (vlib_main_t *vm, vnet_dev_t *dev, void *op, void *arg)
{
  const vnet_dev_event_data_t ed = { .event = VNET_DEV_EVENT_PERIODIC_STOP };
  vnet_dev_periodic_op_t *pop;

  pool_foreach (pop, dev->periodic_ops)
    if (pop->op == op && pop->arg == arg)
      {
	pool_put (dev->periodic_ops, pop);
	if (pool_elts (dev->periodic_ops) == 0)
	  vnet_dev_process_event_send (vm, dev, ed);
	return 1;
      }
  return 0;
}

void
vnet_dev_poll_dev_add (vlib_main_t *vm, vnet_dev_t *dev, f64 interval,
		       vnet_dev_op_t *dev_op)
{
  vnet_dev_periodic_op_t pop = {
    .interval = interval,
    .type = VNET_DEV_PERIODIC_OP_TYPE_DEV,
    .dev_op = dev_op,
    .dev = dev,
  };

  if (_vnet_dev_poll_add (vm, dev, pop) == 0)
    log_warn (dev, "poll_dev_add: op already exists, not added");
}

void
vnet_dev_poll_dev_remove (vlib_main_t *vm, vnet_dev_t *dev,
			  vnet_dev_op_t *dev_op)
{
  if (_vnet_dev_poll_remove (vm, dev, (void *) dev_op, (void *) dev) == 0)
    log_warn (dev, "poll_dev_remove: op not found, not removed");
}

void
vnet_dev_poll_port_add (vlib_main_t *vm, vnet_dev_port_t *port, f64 interval,
			vnet_dev_port_op_t *port_op)
{
  vnet_dev_t *dev = port->dev;
  vnet_dev_periodic_op_t pop = {
    .interval = interval,
    .type = VNET_DEV_PERIODIC_OP_TYPE_PORT,
    .port_op = port_op,
    .port = port,
  };

  if (_vnet_dev_poll_add (vm, dev, pop) == 0)
    log_warn (dev, "poll_port_add: op already exists, not added");
}

void
vnet_dev_poll_port_remove (vlib_main_t *vm, vnet_dev_port_t *port,
			   vnet_dev_port_op_t *port_op)
{
  vnet_dev_t *dev = port->dev;
  if (_vnet_dev_poll_remove (vm, dev, (void *) port_op, (void *) port) == 0)
    log_warn (dev, "poll_port_remove: op not found, not removed");
}

clib_error_t *
vnet_dev_admin_up_down_fn (vnet_main_t *vnm, u32 hw_if_index, u32 flags)
{
  vnet_hw_interface_t *hi = vnet_get_hw_interface (vnm, hw_if_index);
  vlib_main_t *vm = vlib_get_main ();
  vnet_dev_port_t *p = vnet_dev_get_port_from_dev_instance (hi->dev_instance);
  vnet_dev_rv_t rv;
  u32 is_up = (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP) != 0;

  const vnet_dev_event_data_t ed = {
    .event = VNET_DEV_EVENT_PORT_CONFIG_CHANGE,
    .port_config_change = {
      .port = p,
      .changes = {
        .change.admin_state = 1,
        .admin_state = is_up,
      },
    },
  };

  rv = vnet_dev_process_event_send_and_wait (vm, p->dev, ed);

  if (rv != VNET_DEV_OK)
    return clib_error_return (0, "failed to chagne port admin state: %U",
			      format_vnet_dev_rv, rv);

  return 0;
}
