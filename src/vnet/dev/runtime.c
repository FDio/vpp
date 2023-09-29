
/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco Systems, Inc.
 */

#include "vppinfra/bitmap.h"
#include "vppinfra/lock.h"
#include <vnet/vnet.h>
#include <vnet/dev/dev.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "runtime",
};

#define log_debug(dev, f, ...)                                                \
  vlib_log (VLIB_LOG_LEVEL_DEBUG, dev_log.class, "%U%s" f,                    \
	    format_vnet_dev_addr, dev, dev ? ": " : "", ##__VA_ARGS__)

static vnet_dev_rt_op_t *rt_ops;

static void
_vnet_dev_rt_exec_op (vlib_main_t *vm, vnet_dev_rt_op_t *op)
{
  if (op->type == VNET_DEV_RT_OP_TYPE_RX_QUEUE)
    {
      vnet_dev_rx_node_runtime_t *rtd;
      vnet_dev_rx_queue_t *rxq = op->rx_queue;
      u32 i, node_index = rxq->port->intf.rx_node_index;

      rtd = vlib_node_get_runtime_data (vm, node_index);

      if (op->action == VNET_DEV_RT_OP_ACTION_START)
	{
	  for (i = 0; i < rtd->n_rx_queues; i++)
	    ASSERT (rtd->rx_queues[i] != op->rx_queue);
	  rtd->rx_queues[rtd->n_rx_queues++] = op->rx_queue;
	}

      else if (op->action == VNET_DEV_RT_OP_ACTION_STOP)
	{
	  for (i = 0; i < rtd->n_rx_queues; i++)
	    if (rtd->rx_queues[i] == op->rx_queue)
	      break;
	  ASSERT (i < rtd->n_rx_queues);
	  rtd->n_rx_queues--;
	  for (; i < rtd->n_rx_queues; i++)
	    rtd->rx_queues[i] = rtd->rx_queues[i + 1];
	}

      if (rtd->n_rx_queues == 1)
	vlib_node_set_state (vm, node_index, VLIB_NODE_STATE_POLLING);
      else if (rtd->n_rx_queues == 0)
	vlib_node_set_state (vm, node_index, VLIB_NODE_STATE_DISABLED);

      __atomic_store_n (&op->completed, 1, __ATOMIC_RELEASE);
    }
}

static int
_vnet_dev_rt_op_not_occured_before (vnet_dev_rt_op_t *first,
				    vnet_dev_rt_op_t *current)
{
  for (vnet_dev_rt_op_t *op = first; op < current; op++)
    if (op->rx_queue == current->rx_queue && op->completed == 0)
      return 0;
  return 1;
}

static uword
vnet_dev_rt_mgmt_node_fn (vlib_main_t *vm, vlib_node_runtime_t *node,
			  vlib_frame_t *frame)
{
  u16 thread_index = vm->thread_index;
  vnet_dev_rt_op_t *ops = __atomic_load_n (&rt_ops, __ATOMIC_ACQUIRE);
  vnet_dev_rt_op_t *op;
  int come_back = 0;
  uword rv = 0;

  vec_foreach (op, ops)
    if (op->thread_index == thread_index)
      {
	if (_vnet_dev_rt_op_not_occured_before (ops, op))
	  {
	    _vnet_dev_rt_exec_op (vm, op);
	    rv++;
	  }
	else
	  come_back = 1;
      }

  if (come_back)
    vlib_node_set_interrupt_pending (vm, node->node_index);

  return rv;
}

VLIB_REGISTER_NODE (vnet_dev_rt_mgmt_node, static) = {
  .function = vnet_dev_rt_mgmt_node_fn,
  .name = "dev-rt-mgmt",
  .type = VLIB_NODE_TYPE_PRE_INPUT,
  .state = VLIB_NODE_STATE_INTERRUPT,
};

u8 *
format_vnet_dev_mgmt_op (u8 *s, va_list *args)
{
  vnet_dev_rt_op_t *op = va_arg (*args, vnet_dev_rt_op_t *);

  char *types[] = {
    [VNET_DEV_RT_OP_TYPE_RX_QUEUE] = "rx queue",
  };
  char *actions[] = {
    [VNET_DEV_RT_OP_ACTION_START] = "start",
    [VNET_DEV_RT_OP_ACTION_STOP] = "stop",
  };

  return format (s, "port %u %s %u %s on thread %u",
		 op->rx_queue->port->port_id, types[op->type],
		 op->rx_queue->queue_id, actions[op->action],
		 op->thread_index);
}

vnet_dev_rv_t
vnet_dev_rt_exec_ops (vlib_main_t *vm, vnet_dev_t *dev, vnet_dev_rt_op_t *ops,
		      u32 n_ops)
{
  vnet_dev_rt_op_t *op = ops;
  vnet_dev_rt_op_t *remote_ops = 0;
  clib_bitmap_t *remote_bmp = 0;
  u32 i;

  ASSERT (rt_ops == 0);

  for (op = ops; op < (ops + n_ops); op++)
    {
      vlib_main_t *tvm = vlib_get_main_by_index (op->thread_index);

      if ((tvm->parked_at_barrier) ||
	  (op->thread_index == vm->thread_index &&
	   _vnet_dev_rt_op_not_occured_before (ops, op)))
	{
	  _vnet_dev_rt_exec_op (tvm, op);
	  log_debug (dev, "%U executed locally", format_vnet_dev_mgmt_op, op);
	  continue;
	}

      vec_add1 (remote_ops, *op);
      log_debug (dev, "%U enqueued for remote execution",
		 format_vnet_dev_mgmt_op, op);
      remote_bmp = clib_bitmap_set (remote_bmp, op->thread_index, 1);
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
	CLIB_PAUSE ();
    }

  __atomic_store_n (&rt_ops, 0, __ATOMIC_RELAXED);
  vec_free (remote_ops);
  clib_bitmap_free (remote_bmp);
  return VNET_DEV_OK;
}
