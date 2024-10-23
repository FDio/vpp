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
};

typedef enum
{
  VNET_DEV_EVENT_PERIODIC_STOP,
  VNET_DEV_EVENT_PERIODIC_START,
  VNET_DEV_EVENT_PORT_CONFIG_CHANGE_REQ,
  VNET_DEV_EVENT_PROCESS_QUIT,
  VNET_DEV_EVENT_CALL_OP,
  VNET_DEV_EVENT_CALL_OP_NO_RV,
  VNET_DEV_EVENT_CALL_OP_WITH_PTR,
  VNET_DEV_EVENT_CALL_OP_NO_WAIT,
  VNET_DEV_EVENT_CALL_PORT_OP,
  VNET_DEV_EVENT_CALL_PORT_OP_NO_RV,
  VNET_DEV_EVENT_CALL_PORT_OP_WITH_PTR,
  VNET_DEV_EVENT_CALL_PORT_OP_NO_WAIT,
  VNET_DEV_EVENT_CLOCK = ~0
} __clib_packed vnet_dev_event_t;

typedef struct
{
  vnet_dev_event_t event;
  u8 reply_needed : 1;
  u8 completed : 1;
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
      vnet_dev_op_with_ptr_t *op;
      void *ptr;
    } call_op_with_ptr;
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
      vnet_dev_port_op_with_ptr_t *op;
      vnet_dev_port_t *port;
      void *ptr;
    } call_port_op_with_ptr;
    struct
    {
      vnet_dev_port_op_no_rv_t *op;
      vnet_dev_port_t *port;
    } call_port_op_no_wait;
  };
} vnet_dev_event_data_t;

vnet_dev_event_data_t *
vnet_dev_event_data_alloc (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_event_data_t *ed = clib_mem_alloc (sizeof (vnet_dev_event_data_t));
  *ed = (vnet_dev_event_data_t){};

  return ed;
}

void
vnet_dev_event_data_free (vlib_main_t *vm, vnet_dev_t *dev,
			  vnet_dev_event_data_t *ed)
{
  clib_mem_free (ed);
}

static void
ev_log_debug (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_event_data_t *ed,
	      char *str)
{
  log_debug (dev, "%s requested received from process node %U (%u)", str,
	     format_vlib_node_name, vm, ed->calling_process_index,
	     ed->calling_process_index);
}

static void
vnet_dev_process_one_event (vlib_main_t *vm, vnet_dev_t *dev,
			    vnet_dev_event_data_t *ed)
{
  vnet_dev_port_t *p;
  vnet_dev_rv_t rv = VNET_DEV_OK;

  switch (ed->event)
    {
    case VNET_DEV_EVENT_CLOCK:
      break;
    case VNET_DEV_EVENT_PROCESS_QUIT:
      ev_log_debug (vm, dev, ed, "quit");
      dev->process_node_quit = 1;
      break;
    case VNET_DEV_EVENT_PERIODIC_START:
      ev_log_debug (vm, dev, ed, "periodic start");
      dev->process_node_periodic = 1;
      break;
    case VNET_DEV_EVENT_PERIODIC_STOP:
      ev_log_debug (vm, dev, ed, "periodic stop");
      dev->process_node_periodic = 0;
      break;
    case VNET_DEV_EVENT_PORT_CONFIG_CHANGE_REQ:
      ev_log_debug (vm, dev, ed, "port config change");
      p = ed->port_cfg_change.port;
      rv = vnet_dev_port_cfg_change (vm, p, ed->port_cfg_change.change_req);
      break;
    case VNET_DEV_EVENT_CALL_OP:
      ev_log_debug (vm, dev, ed, "call op");
      rv = ed->call_op.op (vm, dev);
      break;
    case VNET_DEV_EVENT_CALL_OP_NO_RV:
      ev_log_debug (vm, dev, ed, "call op no rv");
      ed->call_op_no_rv.op (vm, dev);
      break;
    case VNET_DEV_EVENT_CALL_OP_WITH_PTR:
      ev_log_debug (vm, dev, ed, "call op woth ptr");
      rv = ed->call_op_with_ptr.op (vm, dev, ed->call_op_with_ptr.ptr);
      break;
    case VNET_DEV_EVENT_CALL_OP_NO_WAIT:
      ev_log_debug (vm, dev, ed, "call op no wait");
      ed->call_op_no_wait.op (vm, dev);
      break;
    case VNET_DEV_EVENT_CALL_PORT_OP:
      ev_log_debug (vm, dev, ed, "call port op");
      rv = ed->call_port_op.op (vm, ed->call_port_op.port);
      break;
    case VNET_DEV_EVENT_CALL_PORT_OP_NO_RV:
      ev_log_debug (vm, dev, ed, "call port op no rv");
      ed->call_port_op_no_rv.op (vm, ed->call_port_op_no_rv.port);
      break;
    case VNET_DEV_EVENT_CALL_PORT_OP_WITH_PTR:
      ev_log_debug (vm, dev, ed, "call port op woth ptr");
      rv = ed->call_port_op_with_ptr.op (vm, ed->call_port_op_with_ptr.port,
					 ed->call_port_op_with_ptr.ptr);
      break;
    case VNET_DEV_EVENT_CALL_PORT_OP_NO_WAIT:
      ev_log_debug (vm, dev, ed, "call port op no wait");
      ed->call_port_op_no_wait.op (vm, ed->call_port_op_no_wait.port);
      break;
    default:
      ASSERT (0);
    }
  if (ed->reply_needed)
    {
      ed->rv = rv;
      ed->completed = 1;
    }
  else
    vnet_dev_event_data_free (vm, dev, ed);
}

static uword
vnet_dev_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  vnet_dev_main_t *dm = &vnet_dev_main;
  vnet_dev_periodic_op_t *pop, *pops = 0;
  f64 next = CLIB_F64_MAX;
  vnet_dev_event_data_t **event_data = 0, **new_event_data, **edp;

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

      new_event_data = vlib_process_get_event_data (vm, &event_type);

      if (new_event_data)
	{
	  vec_append (event_data, new_event_data);
	  vlib_process_put_event_data (vm, new_event_data);

	  ASSERT (event_type == 0);

	  vec_foreach (edp, event_data)
	    vnet_dev_process_one_event (vm, dev, *edp);
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
			     vnet_dev_event_data_t *ed)
{
  void *p = vlib_process_signal_event_data (vm, dev->process_node_index, 0, 1,
					    sizeof (void *));
  *(vnet_dev_event_data_t **) p = ed;
}

static vnet_dev_rv_t
vnet_dev_process_event_send_and_wait (vlib_main_t *vm, vnet_dev_t *dev,
				      vnet_dev_event_data_t *ed)
{
  ed->calling_process_index = vlib_get_current_process_node_index (vm);
  vnet_dev_rv_t rv = VNET_DEV_ERR_PROCESS_REPLY;

  ed->reply_needed = 1;

  if (ed->calling_process_index == dev->process_node_index)
    {
      vnet_dev_process_one_event (vm, dev, ed);
      rv = ed->rv;
      goto done;
    }

  vnet_dev_process_event_send (vm, dev, ed);
  vlib_process_yield (vm);

  if (!ed->completed)
    {
      f64 t0, interval = 25e-6, max_interval = 50e-3;
      t0 = vlib_time_now (vm);

      do
	{
	  vlib_process_suspend (vm, interval);
	  if (ed->completed)
	    {
	      rv = ed->rv;
	      goto done;
	    }
	  if (interval < max_interval)
	    {
	      interval *= 2;
	      if (interval > max_interval)
		interval = max_interval;
	    }
	}
      while (vlib_time_now (vm) - t0 < 5.0);
    }
  else
    rv = ed->rv;

done:
  vnet_dev_event_data_free (vm, dev, ed);
  return rv;
}

void
vnet_dev_process_quit (vlib_main_t *vm, vnet_dev_t *dev)
{
  vnet_dev_event_data_t *ed = vnet_dev_event_data_alloc (vm, dev);
  *ed = (vnet_dev_event_data_t){ .event = VNET_DEV_EVENT_PROCESS_QUIT };
  vnet_dev_process_event_send_and_wait (vm, dev, ed);
}

static int
_vnet_dev_poll_add (vlib_main_t *vm, vnet_dev_t *dev,
		    vnet_dev_periodic_op_t pop)
{
  vnet_dev_event_data_t *ed = vnet_dev_event_data_alloc (vm, dev);
  *ed = (vnet_dev_event_data_t){ .event = VNET_DEV_EVENT_PERIODIC_START };
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
  vnet_dev_event_data_t *ed = vnet_dev_event_data_alloc (vm, dev);
  *ed = (vnet_dev_event_data_t){ .event = VNET_DEV_EVENT_PERIODIC_STOP };
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
  vnet_dev_event_data_t *ed = vnet_dev_event_data_alloc (vm, port->dev);
  *ed = (vnet_dev_event_data_t) {
      .event = VNET_DEV_EVENT_PORT_CONFIG_CHANGE_REQ,
      .port_cfg_change = {
        .port = port,
      .change_req = pccr,
      },
    };

  return vnet_dev_process_event_send_and_wait (vm, port->dev, ed);
}

vnet_dev_rv_t
vnet_dev_process_call_op (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_op_t *op)
{
  vnet_dev_event_data_t *ed = vnet_dev_event_data_alloc (vm, dev);
  *ed = (vnet_dev_event_data_t){
    .event = VNET_DEV_EVENT_CALL_OP,
    .call_op.op = op,
  };

  return vnet_dev_process_event_send_and_wait (vm, dev, ed);
}

vnet_dev_rv_t
vnet_dev_process_call_op_no_rv (vlib_main_t *vm, vnet_dev_t *dev,
				vnet_dev_op_no_rv_t *op)
{
  vnet_dev_event_data_t *ed = vnet_dev_event_data_alloc (vm, dev);
  *ed = (vnet_dev_event_data_t){
    .event = VNET_DEV_EVENT_CALL_OP_NO_RV,
    .call_op_no_rv.op = op,
  };

  return vnet_dev_process_event_send_and_wait (vm, dev, ed);
}

vnet_dev_rv_t
vnet_dev_process_call_op_with_ptr (vlib_main_t *vm, vnet_dev_t *dev,
				   vnet_dev_op_with_ptr_t *op, void *p)
{
  vnet_dev_event_data_t *ed = vnet_dev_event_data_alloc (vm, dev);
  *ed = (vnet_dev_event_data_t){
    .event = VNET_DEV_EVENT_CALL_OP_WITH_PTR,
    .call_op_with_ptr = { .op = op, .ptr = p },
  };

  return vnet_dev_process_event_send_and_wait (vm, dev, ed);
}

void
vnet_dev_process_call_op_no_wait (vlib_main_t *vm, vnet_dev_t *dev,
				  vnet_dev_op_no_rv_t *op)
{
  vnet_dev_event_data_t *ed = vnet_dev_event_data_alloc (vm, dev);
  *ed = (vnet_dev_event_data_t){
    .event = VNET_DEV_EVENT_CALL_OP_NO_WAIT,
    .call_op_no_rv.op = op,
  };

  vnet_dev_process_event_send (vm, dev, ed);
}

vnet_dev_rv_t
vnet_dev_process_call_port_op (vlib_main_t *vm, vnet_dev_port_t *port,
			       vnet_dev_port_op_t *op)
{
  vnet_dev_event_data_t *ed = vnet_dev_event_data_alloc (vm, port->dev);
  *ed = (vnet_dev_event_data_t){
    .event = VNET_DEV_EVENT_CALL_PORT_OP,
    .call_port_op = { .op = op, .port = port },
  };

  return vnet_dev_process_event_send_and_wait (vm, port->dev, ed);
}

vnet_dev_rv_t
vnet_dev_process_call_port_op_no_rv (vlib_main_t *vm, vnet_dev_port_t *port,
				     vnet_dev_port_op_no_rv_t *op)
{
  vnet_dev_event_data_t *ed = vnet_dev_event_data_alloc (vm, port->dev);
  *ed = (vnet_dev_event_data_t){
    .event = VNET_DEV_EVENT_CALL_PORT_OP_NO_RV,
    .call_port_op_no_rv = { .op = op, .port = port },
  };

  return vnet_dev_process_event_send_and_wait (vm, port->dev, ed);
}

vnet_dev_rv_t
vnet_dev_process_call_port_op_with_ptr (vlib_main_t *vm, vnet_dev_port_t *port,
					vnet_dev_port_op_with_ptr_t *op,
					void *p)
{
  vnet_dev_event_data_t *ed = vnet_dev_event_data_alloc (vm, port->dev);
  *ed = (vnet_dev_event_data_t){
    .event = VNET_DEV_EVENT_CALL_PORT_OP_WITH_PTR,
    .call_port_op_with_ptr = { .op = op, .port = port, .ptr = p },
  };

  return vnet_dev_process_event_send_and_wait (vm, port->dev, ed);
}

void
vnet_dev_process_call_port_op_no_wait (vlib_main_t *vm, vnet_dev_port_t *port,
				       vnet_dev_port_op_no_rv_t *op)
{
  vnet_dev_event_data_t *ed = vnet_dev_event_data_alloc (vm, port->dev);
  *ed = (vnet_dev_event_data_t){
    .event = VNET_DEV_EVENT_CALL_PORT_OP_NO_WAIT,
    .call_port_op_no_wait = { .op = op, .port = port },
  };

  vnet_dev_process_event_send (vm, port->dev, ed);
}
