
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/bitmap.h"
#include "vppinfra/lock.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/log.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "runtime",
};

static vnet_dev_rt_op_t *rt_ops;

static void
_vnet_dev_rt_exec_op (vlib_main_t *vm, vnet_dev_rt_op_t *op)
{
  vnet_dev_port_t *port = op->port;
  vnet_dev_rx_queue_t *previous = 0, *first = 0;
  vnet_dev_rx_node_runtime_t *rtd;
  vlib_node_state_t state = VLIB_NODE_STATE_DISABLED;
  u32 node_index = vnet_dev_get_port_rx_node_index (port);

  rtd = vlib_node_get_runtime_data (vm, node_index);

  foreach_vnet_dev_port_rx_queue (q, port)
    {
      if (q->rx_thread_index != vm->thread_index)
	continue;

      if (q->interrupt_mode == 0)
	state = VLIB_NODE_STATE_POLLING;
      else if (state != VLIB_NODE_STATE_POLLING)
	state = VLIB_NODE_STATE_INTERRUPT;

      q->next_on_thread = 0;
      if (previous == 0)
	first = q;
      else
	previous->next_on_thread = q;

      previous = q;
    }

  rtd->first_rx_queue = first;
  vlib_node_set_state (vm, node_index, state);
  __atomic_store_n (&op->completed, 1, __ATOMIC_RELEASE);
}

static uword
vnet_dev_rt_mgmt_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame)
{
  clib_thread_index_t thread_index = vm->thread_index;
  vnet_dev_rt_op_t *op, *ops = __atomic_load_n (&rt_ops, __ATOMIC_ACQUIRE);
  u32 n_pending = 0;
  uword rv = 0;

  vec_foreach (op, ops)
    {
      if (!op->completed && op->thread_index == thread_index)
	{
	  if (op->in_order == 1 && n_pending)
	    {
	      vlib_node_set_interrupt_pending (vm, node->node_index);
	      return rv;
	    }
	  _vnet_dev_rt_exec_op (vm, op);
	  rv++;
	}

      if (op->completed == 0)
	n_pending++;
    }

  return rv;
}

VLIB_REGISTER_NODE (vnet_dev_rt_mgmt_node, static) = {
  .function = vnet_dev_rt_mgmt_node_fn,
  .name = "dev-rt-mgmt",
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

vnet_dev_rv_t
vnet_dev_rt_exec_ops (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_rt_op_t *ops,
		      u32 n_ops)
{
  vnet_dev_rt_op_t *op = ops;
  vnet_dev_rt_op_t *remote_ops = 0;
  clib_bitmap_t *remote_bmp = 0;
  u32 i;

  ASSERT (rt_ops == 0);

  if (vlib_worker_thread_barrier_held ())
    {
      for (op = ops; op < (ops + n_ops); op++)
	{
	  vlib_main_t *tvm = vlib_get_main_by_index (op->thread_index);
	  _vnet_dev_rt_exec_op (tvm, op);
	  log_debug (
	    dev,
	    "port %u rx node runtime update on thread %u executed locally",
	    op->port->port_id, op->thread_index);
	}
      return VNET_DEV_OK;
    }

  while (n_ops)
    {
      if (op->thread_index != vm->thread_index)
	break;

      _vnet_dev_rt_exec_op (vm, op);
      log_debug (
	dev, "port %u rx node runtime update on thread %u executed locally",
	op->port->port_id, op->thread_index);
      op++;
      n_ops--;
    }

  if (n_ops == 0)
    return VNET_DEV_OK;

  for (op = ops; op < (ops + n_ops); op++)
    {
      if (op->thread_index == vm->thread_index &&
	  (op->in_order == 0 || vec_len (remote_ops) == 0))
	{
	  _vnet_dev_rt_exec_op (vm, op);
	  log_debug (dev,
		     "port %u rx node runtime update on thread "
		     "%u executed locally",
		     op->port->port_id, op->thread_index);
	}
      else
	{
	  vec_add1 (remote_ops, *op);
	  log_debug (dev,
		     "port %u rx node runtime update on thread %u "
		     "enqueued for remote execution",
		     op->port->port_id, op->thread_index);
	  remote_bmp = clib_bitmap_set (remote_bmp, op->thread_index, 1);
	}
    }

  if (remote_ops == 0)
    return VNET_DEV_OK;

  __atomic_store_n (&rt_ops, remote_ops, __ATOMIC_RELEASE);

  clib_bitmap_foreach (i, remote_bmp)
    {
      vlib_node_set_interrupt_pending (vlib_get_main_by_index (i),
				       vnet_dev_rt_mgmt_node.index);
      log_debug (dev, "interrupt sent to %s node on thread %u",
		 vnet_dev_rt_mgmt_node.name, i);
    }

  vec_foreach (op, remote_ops)
    {
      while (op->completed == 0)
	vlib_process_suspend (vm, 5e-5);

      log_debug (
	dev, "port %u rx node runtime update on thread %u executed locally",
	op->port->port_id, op->thread_index);
    }

  __atomic_store_n (&rt_ops, 0, __ATOMIC_RELAXED);
  vec_free (remote_ops);
  clib_bitmap_free (remote_bmp);
  return VNET_DEV_OK;
}
