/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/error.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/log.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "process",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

typedef enum
{
  VNET_DEV_EVENT_PERIODIC_STOP,
  VNET_DEV_EVENT_PERIODIC_START,
  VNET_DEV_EVENT_PORT_CONFIG_CHANGE_REQ,
  VNET_DEV_EVENT_PROCESS_QUIT,
  VNET_DEV_EVENT_CALL_OP,
  VNET_DEV_EVENT_CALL_OP_NO_RV,
  VNET_DEV_EVENT_CALL_OP_NO_WAIT,
  VNET_DEV_EVENT_CALL_PORT_OP,
  VNET_DEV_EVENT_CALL_PORT_OP_NO_RV,
  VNET_DEV_EVENT_CALL_PORT_OP_NO_WAIT,
  VNET_DEV_EVENT_CLOCK = ~0
} __clib_packed vnet_dev_event_t;

typedef struct
{
  vnet_dev_event_t event;
  vnet_dev_rv_t rv;
  u32 calling_process_index;
  union
  {
    struct
    {
      vnet_dev_port_t *port;
      vnet_dev_port_cfg_change_req_t *change_req;
    } port_cfg_change;
    struct
    {
      vnet_dev_op_t *op;
    } call_op;
    struct
    {
      vnet_dev_op_no_rv_t *op;
    } call_op_no_rv;
    struct
    {
      vnet_dev_op_no_rv_t *op;
    } call_op_no_wait;
    struct
    {
      vnet_dev_port_op_t *op;
      vnet_dev_port_t *port;
    } call_port_op;
    struct
    {
      vnet_dev_port_op_no_rv_t *op;
      vnet_dev_port_t *port;
    } call_port_op_no_rv;
    struct
    {
      vnet_dev_port_op_no_rv_t *op;
      vnet_dev_port_t *port;
    } call_port_op_no_wait;
  };
} vnet_dev_event_data_t;

static vnet_dev_rv_t
vnet_dev_process_one_event (vlib_main_t *vm, vnet_dev_t *dev,
			    vnet_dev_event_data_t *edp)
{
  vnet_dev_port_t *p;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u8 dealloc = 0;

  log_debug (dev, "process one event: starting");
  switch (edp->event)
    {
    case VNET_DEV_EVENT_CLOCK:
      dealloc = 1;
      break;
    case VNET_DEV_EVENT_PROCESS_QUIT:
      log_debug (dev, "quit requested");
      dev->process_node_quit = 1;
      dealloc = 1;
      break;
    case VNET_DEV_EVENT_PERIODIC_START:
      log_debug (dev, "periodic start");
      dev->process_node_periodic = 1;
      dealloc = 1;
      break;
    case VNET_DEV_EVENT_PERIODIC_STOP:
      log_debug (dev, "periodic stop");
      dev->process_node_periodic = 0;
      dealloc = 1;
      break;
    case VNET_DEV_EVENT_PORT_CONFIG_CHANGE_REQ:
      log_debug (dev, "port config change");
      p = edp->port_cfg_change.port;
      rv = vnet_dev_port_cfg_change (vm, p, edp->port_cfg_change.change_req);
      break;
    case VNET_DEV_EVENT_CALL_OP:
      log_debug (dev, "call op");
      rv = edp->call_op.op (vm, dev);
      break;
    case VNET_DEV_EVENT_CALL_OP_NO_RV:
      log_debug (dev, "call op no rv");
      edp->call_op_no_rv.op (vm, dev);
      dealloc = 1;
      break;
    case VNET_DEV_EVENT_CALL_OP_NO_WAIT:
      log_debug (dev, "call op no wait");
      edp->call_op_no_wait.op (vm, dev);
      dealloc = 1;
      break;
    case VNET_DEV_EVENT_CALL_PORT_OP:
      log_debug (dev, "call port op");
      rv = edp->call_port_op.op (vm, edp->call_port_op.port);
      break;
    case VNET_DEV_EVENT_CALL_PORT_OP_NO_RV:
      log_debug (dev, "call port op no rv");
      edp->call_port_op_no_rv.op (vm, edp->call_port_op_no_rv.port);
      dealloc = 1;
      break;
    case VNET_DEV_EVENT_CALL_PORT_OP_NO_WAIT:
      log_debug (dev, "call port op no wait");
      edp->call_port_op_no_wait.op (vm, edp->call_port_op_no_wait.port);
      dealloc = 1;
      break;
    default:
      ASSERT (0);
    }

  if (dealloc)
    {
      vec_free (edp);
      log_debug (dev, "returning after discard");
    }
  else
    {
      edp->rv = rv;
      log_debug (dev, "returning with rv");
    }
  return rv;
}

static uword
vnet_dev_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_periodic_op_t *pop, *pops = 0;
  f64 next = CLIB_F64_MAX;
  vnet_dev_event_data_t **event_pdata = 0, **new_event_pdata, **edpp;

  vnet_dev_t *dev =
    *((vnet_dev_t **) vlib_node_get_runtime_data (vm, rt->node_index));

  log_debug (dev, "process '%U' started", format_vlib_node_name, vm,
	     rt->node_index);

  while (dev->process_node_quit == 0)
    {
      uword event_type;
      f64 now = vlib_time_now (vm);

      if (dev->process_node_periodic)
	vlib_process_wait_for_event_or_clock (vm, next > now ? next - now : 0);
      else
	vlib_process_wait_for_event (vm);

      new_event_pdata = vlib_process_get_event_data (vm, &event_type);

      if (new_event_pdata)
	{
	  vec_append (event_pdata, new_event_pdata);
	  vlib_process_put_event_data (vm, new_event_pdata);

	  ASSERT (event_type == 0);

	  vec_foreach (edpp, event_pdata)
	    {
	      log_debug (dev, "event from signal received");
	      vnet_dev_process_one_event (vm, dev, *edpp);
	    }
	  vec_reset_length (event_pdata);
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
  vec_free (event_pdata);
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
      if (n->function != vnet_dev_process)
	{
	  vlib_node_runtime_t *rt = vlib_node_get_runtime (vm, n->index);
	  n->function = vnet_dev_process;
	  rt->function = vnet_dev_process;
	}
      vlib_node_rename (vm, n->index, "%s-process", dev->device_id);
      vlib_node_set_state (vm, n->index, VLIB_NODE_STATE_POLLING);
      vec_set_len (dm->free_process_node_indices, l - 1);
      log_debug (dev, "process node '%U' (%u) reused", format_vlib_node_name,
		 vm, n->index, n->index);
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
      log_debug (dev, "process node '%U' (%u) created", format_vlib_node_name,
		 vm, r.index, r.index);
    }

  dev->process_node_index = n->index;
  *(vnet_dev_t **) vlib_node_get_runtime_data (vm, n->index) = dev;
  vlib_start_process (vm, n->runtime_index);

  return VNET_DEV_OK;
}

static void
vnet_dev_process_event_send (vlib_main_t *vm, vnet_dev_t *dev,
			     vnet_dev_event_data_t *edp, u8 copy)
{
  vnet_dev_event_data_t *edp2;

  if (copy)
    {
      edp2 = vec_new (vnet_dev_event_data_t, 1);
     *edp2 = *edp;
      log_debug (dev, "created a copy");
    }
  else
    {
      edp2 = edp;
      log_debug (dev, "not creating a copy");
    }
  edp2->rv = VNET_DEV_PENDING;
  vnet_dev_event_data_t **edp_copy_p = vlib_process_signal_event_data (
    vm, dev->process_node_index, 0, 1, sizeof (edp2));
  *edp_copy_p = edp2;
  log_debug (dev, "event sent");
}

static vnet_dev_rv_t
vnet_dev_process_event_send_and_wait (vlib_main_t *vm, vnet_dev_t *dev,
				      vnet_dev_event_data_t *edp)
{
  f64 t0, interval = 3e-5;

  log_debug (dev, "vdpesaw starts");
  edp->calling_process_index = vlib_get_current_process_node_index (vm);

  if (edp->calling_process_index == dev->process_node_index)
    {
      log_debug (dev, "same process, calling directly");
      return vnet_dev_process_one_event (vm, dev, edp);
    }

  log_debug (dev, "not same process, calling indirectly");
  vnet_dev_process_event_send (vm, dev, edp);

  t0 = vlib_time_now (vm);

  do
    {
      log_debug (dev, "suspending");
      vlib_process_suspend (vm, interval);
      if (edp->rv != VNET_DEV_PENDING)
	{
	  log_debug (dev, "rv no longer pending");
	  return edp->rv;
	}
      interval *= 2;
    }
  while (vlib_time_now (vm) - t0 < 0.5);
  log_warn (dev, "event timed out");

  return VNET_DEV_ERR_PROCESS_REPLY;
}

void
vnet_dev_process_quit (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_event_data_t ed = { .event = VNET_DEV_EVENT_PROCESS_QUIT };
  vnet_dev_process_event_send_and_wait (vm, dev, &ed);
}

static int
_vnet_dev_poll_add (vlib_main_t *vm, vnet_dev_t *dev,
		    vnet_dev_periodic_op_t pop)
{
  vnet_dev_event_data_t ed = { .event = VNET_DEV_EVENT_PERIODIC_START };
  vnet_dev_periodic_op_t *p;

  pool_foreach (p, dev->periodic_ops)
    if (p->op == pop.op && p->arg == pop.arg)
      return 0;

  pool_get_zero (dev->periodic_ops, p);
  *p = pop;
  if (pool_elts (dev->periodic_ops) == 1)
    {
      log_debug (dev, "periodic op on add, going to send");
      vnet_dev_process_event_send (vm, dev, &ed);
      log_debug (dev, "periodic op on add, sending done");
    }
  return 1;
}

static int
_vnet_dev_poll_remove (vlib_main_t *vm, vnet_dev_t *dev, void *op, void *arg)
{
  vnet_dev_event_data_t ed = { .event = VNET_DEV_EVENT_PERIODIC_STOP };
  vnet_dev_periodic_op_t *pop;

  pool_foreach (pop, dev->periodic_ops)
    if (pop->op == op && pop->arg == arg)
      {
	pool_put (dev->periodic_ops, pop);
	if (pool_elts (dev->periodic_ops) == 0)
	  {
	    log_debug (dev, "periodic op on remove, going to send");
	    vnet_dev_process_event_send (vm, dev, &ed);
	    log_debug (dev, "periodic op on remove, sending done");
	  }
	return 1;
      }
  return 0;
}

void
vnet_dev_poll_dev_add (vlib_main_t *vm, vnet_dev_t *dev, f64 interval,
		       vnet_dev_op_no_rv_t *dev_op)
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
			  vnet_dev_op_no_rv_t *dev_op)
{
  if (_vnet_dev_poll_remove (vm, dev, (void *) dev_op, (void *) dev) == 0)
    log_warn (dev, "poll_dev_remove: op not found, not removed");
}

void
vnet_dev_poll_port_add (vlib_main_t *vm, vnet_dev_port_t *port, f64 interval,
			vnet_dev_port_op_no_rv_t *port_op)
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
			   vnet_dev_port_op_no_rv_t *port_op)
{
  vnet_dev_t *dev = port->dev;
  if (_vnet_dev_poll_remove (vm, dev, (void *) port_op, (void *) port) == 0)
    log_warn (dev, "poll_port_remove: op not found, not removed");
}

vnet_dev_rv_t
vnet_dev_process_port_cfg_change_req (vlib_main_t *vm, vnet_dev_port_t *port,
				      vnet_dev_port_cfg_change_req_t *pccr)
{
  vnet_dev_event_data_t ed = {
      .event = VNET_DEV_EVENT_PORT_CONFIG_CHANGE_REQ,
      .port_cfg_change = {
        .port = port,
      .change_req = pccr,
      },
    };

  return vnet_dev_process_event_send_and_wait (vm, port->dev, &ed);
}

vnet_dev_rv_t
vnet_dev_process_call_op (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_op_t *op)
{
  vnet_dev_event_data_t ed = {
    .event = VNET_DEV_EVENT_CALL_OP,
    .call_op.op = op,
  };

  return vnet_dev_process_event_send_and_wait (vm, dev, &ed);
}

vnet_dev_rv_t
vnet_dev_process_call_op_no_rv (vlib_main_t *vm, vnet_dev_t *dev,
				vnet_dev_op_no_rv_t *op)
{
  vnet_dev_event_data_t ed = {
    .event = VNET_DEV_EVENT_CALL_OP_NO_RV,
    .call_op_no_rv.op = op,
  };

  return vnet_dev_process_event_send_and_wait (vm, dev, &ed);
}

void
vnet_dev_process_call_op_no_wait (vlib_main_t *vm, vnet_dev_t *dev,
				  vnet_dev_op_no_rv_t *op)
{
  vnet_dev_event_data_t ed = {
    .event = VNET_DEV_EVENT_CALL_OP_NO_WAIT,
    .call_op_no_rv.op = op,
  };

  log_debug (dev, "vdpconw");
  vnet_dev_process_event_send (vm, dev, &ed);
}

vnet_dev_rv_t
vnet_dev_process_call_port_op (vlib_main_t *vm, vnet_dev_port_t *port,
			       vnet_dev_port_op_t *op)
{
  vnet_dev_event_data_t ed = {
    .event = VNET_DEV_EVENT_CALL_PORT_OP,
    .call_port_op = { .op = op, .port = port },
  };

  return vnet_dev_process_event_send_and_wait (vm, port->dev, &ed);
}

vnet_dev_rv_t
vnet_dev_process_call_port_op_no_rv (vlib_main_t *vm, vnet_dev_port_t *port,
				     vnet_dev_port_op_no_rv_t *op)
{
  vnet_dev_event_data_t ed = {
    .event = VNET_DEV_EVENT_CALL_PORT_OP_NO_RV,
    .call_port_op_no_rv = { .op = op, .port = port },
  };

  return vnet_dev_process_event_send_and_wait (vm, port->dev, &ed);
}

void
vnet_dev_process_call_port_op_no_wait (vlib_main_t *vm, vnet_dev_port_t *port,
				       vnet_dev_port_op_no_rv_t *op)
{
  vnet_dev_event_data_t ed = {
    .event = VNET_DEV_EVENT_CALL_PORT_OP_NO_WAIT,
    .call_port_op_no_wait = { .op = op, .port = port },
  };

  log_debug (port->dev, "vdpcponw");
  vnet_dev_process_event_send (vm, port->dev, &ed);
}
